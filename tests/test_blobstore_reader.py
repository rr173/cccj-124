"""读取生命周期：固定闭包、名称变更隔离、闭包外拒绝、保护期间回收。"""

import os
import unittest

from blobstore_fixtures import BlobStoreFixture
from oci_catalog.blobstore import (
    GC_DELETED,
    READER_ACTIVE,
    READER_CLOSED,
    BlobStore,
    ClosedReaderError,
    StoreError,
)
from oci_catalog.blobstore.sample_data import AMD64_L2, ARM64_L2, BASE_LAYER


class TestReaderLifecycle(BlobStoreFixture):

    def test_reader_pins_root_at_open(self):
        self.import_root("A", "delivery-a")
        self.import_root("B", "delivery-b")
        reader = self.store.open_reader("delivery-a")
        try:
            self.assertEqual(reader.root.digest, self.layout.roots["A"])
            self.store.set_ref("delivery-a", self.layout.roots["B"])
            self.assertEqual(reader.root.digest, self.layout.roots["A"])
            self.assertEqual(self.store.resolve_name("delivery-a"),
                             self.layout.roots["B"])
            self.assertEqual(reader.read_all(self.layout.names["amd64-l2"]),
                             AMD64_L2)
        finally:
            reader.close()

    def test_reader_survives_name_deletion(self):
        self.import_root("A", "delivery-a")
        reader = self.store.open_reader("delivery-a")
        try:
            self.store.delete_ref("delivery-a")
            self.assertEqual(reader.read_all(self.layout.names["base"]),
                             BASE_LAYER)
        finally:
            reader.close()

    def test_reader_cannot_open_unrelated_name(self):
        self.import_root("A", "delivery-a")
        self.import_root("B", "delivery-b")
        with self.store.open_reader("delivery-a") as reader:
            with self.assertRaises(StoreError):
                reader.read_all(self.layout.names["repack-l2"])

    def test_reader_rejects_closed_context(self):
        self.import_root("A", "delivery-a")
        reader = self.store.open_reader("delivery-a")
        reader.close()
        with self.assertRaises(ClosedReaderError):
            reader.read_all(self.layout.names["base"])

    def test_reader_objects_cover_whole_closure(self):
        self.import_root("A", "delivery-a")
        with self.store.open_reader("delivery-a") as reader:
            digests = set(reader.object_digests())
            roles = reader.roles()
            self.assertEqual(len(digests), 10)
            self.assertEqual(roles[self.layout.roots["A"]], "root")
            self.assertEqual(roles[self.layout.names["base"]], "layer")
            # 手写期待：10 个对象、唯一字节总数 3120（见 sample_data）
            self.assertEqual(
                sum(desc.size for desc in reader.objects()), 3120)
            self.assertEqual(
                sorted(roles.values()),
                ["config", "config", "layer", "layer", "layer", "layer",
                 "manifest", "manifest", "manifest", "root"])

    def test_close_releases_protection_immediately(self):
        self.import_root("A", "delivery-a")
        self.import_root("C")
        reader = self.store.open_reader("delivery-a")
        self.store.set_ref("delivery-a", self.layout.roots["C"])
        reader.close()
        row = self.store.conn.execute(
            "SELECT status FROM readers ORDER BY opened_at DESC"
        ).fetchone()
        self.assertEqual(row["status"], READER_CLOSED)
        plan = self.store.plan_gc()
        run = self.store.apply_gc(plan.plan_id)
        self.assertGreater(
            sum(1 for item in run.items if item["outcome"] == GC_DELETED), 0)

    def test_unclosed_reader_blocks_only_its_closure(self):
        self.import_root("A", "delivery-a")
        self.import_root("B", "delivery-b")
        self.import_root("C")
        reader = self.store.open_reader("delivery-a")
        self.store.delete_ref("delivery-a")
        plan = self.store.plan_gc()
        candidates = {c["digest"] for c in plan.candidates}
        # C 闭包（未命名、无读者）应作为候选；A 的独有层与共享层不应
        self.assertIn(self.layout.roots["C"], candidates)
        self.assertNotIn(self.layout.roots["A"], candidates)
        self.assertNotIn(self.layout.names["base"], candidates)
        self.assertNotIn(self.layout.names["amd64-l2"], candidates)
        # B 仍被引用，也不在候选里
        self.assertNotIn(self.layout.roots["B"], candidates)
        reader.close()

    def test_reader_open_unknown_name_raises(self):
        with self.assertRaises(KeyError):
            self.store.open_reader("nope")

    def test_partial_read_paused_then_full_read(self):
        self.import_root("A", "delivery-a")
        reader = self.store.open_reader("delivery-a")
        layer = self.layout.names["amd64-l2"]
        chunks = reader.read_chunks(layer, 16)
        first = next(chunks)
        self.assertEqual(first, AMD64_L2[:16])
        # 暂停期间名称被删除，剩余层仍可继续取
        self.store.delete_ref("delivery-a")
        rest = b"".join(chunks)
        self.assertEqual(first + rest, AMD64_L2)
        reader.close()


class TestDeadReaderDetection(BlobStoreFixture):

    def _spawn_reader(self, name: str, script_extra: str = "") -> object:
        import subprocess
        import sys
        code = (
            "import sys, time\n"
            "sys.path.insert(0, %r)\n"
            "from oci_catalog.blobstore import BlobStore\n"
            "s=BlobStore(%r)\n"
            "r=s.open_reader(%r)\n"
            "print(r.reader_id, flush=True)\n"
            "time.sleep(60)\n"
        ) % (os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
             self.store_path, name)
        return subprocess.Popen([sys.executable, "-I", "-c", code],
                                stdout=subprocess.PIPE)

    def test_killed_reader_is_released_on_next_gc(self):
        self.import_root("A", "delivery-a")
        self.import_root("C")
        proc = self._spawn_reader("delivery-a")
        reader_id = proc.stdout.readline().decode().strip()
        proc.stdout.close()
        self.assertTrue(reader_id)
        self.store.delete_ref("delivery-a")
        proc.kill()
        proc.wait()
        # 进程已死，但 reader 行仍是 active；下一次回收必须辨认并释放
        row = self.store.conn.execute(
            "SELECT status FROM readers WHERE reader_id = ?",
            (reader_id,)).fetchone()
        self.assertEqual(row["status"], READER_ACTIVE)
        plan = self.store.plan_gc()
        run = self.store.apply_gc(plan.plan_id)
        row = self.store.conn.execute(
            "SELECT status FROM readers WHERE reader_id = ?",
            (reader_id,)).fetchone()
        self.assertEqual(row["status"], "exited")
        deleted = {item["digest"] for item in run.items
                   if item["outcome"] == GC_DELETED}
        self.assertIn(self.layout.roots["A"], deleted)
        self.assertIn(self.layout.roots["C"], deleted)
        self.assertFalse(self.blob_exists(self.layout.names["amd64-l2"]))

    def test_live_reader_is_not_expired_by_time(self):
        """活着的慢读者即使等待很久也不能被当成失效。"""
        import time
        self.import_root("A", "delivery-a")
        self.import_root("C")
        reader = self.store.open_reader("delivery-a")
        self.store.delete_ref("delivery-a")
        time.sleep(0.05)  # 与时间无关：没有任何固定秒数阈值
        plan = self.store.plan_gc()
        candidates = {c["digest"] for c in plan.candidates}
        self.assertNotIn(self.layout.names["amd64-l2"], candidates)
        run = self.store.apply_gc(plan.plan_id)
        self.assertTrue(all(item["digest"] != self.layout.names["amd64-l2"]
                            for item in run.items))
        self.assertEqual(reader.read_all(self.layout.names["amd64-l2"]),
                         AMD64_L2)
        reader.close()

    def test_two_readers_one_root_all_protected(self):
        self.import_root("A", "delivery-a")
        r1 = self.store.open_reader("delivery-a")
        r2 = self.store.open_reader("delivery-a")
        self.store.delete_ref("delivery-a")
        r1.close()
        plan = self.store.plan_gc()
        candidates = {c["digest"] for c in plan.candidates}
        self.assertNotIn(self.layout.roots["A"], candidates)
        self.assertEqual(r2.read_all(self.layout.names["arm64-l2"]),
                         ARM64_L2)
        r2.close()
        plan = self.store.plan_gc()
        self.assertIn(self.layout.roots["A"],
                      {c["digest"] for c in plan.candidates})


if __name__ == "__main__":
    unittest.main()
