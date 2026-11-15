"""两阶段回收：计划候选、计划后新保护、计划后新对象、并发回收、状态异常。"""

import os
import threading
import unittest

from blobstore_fixtures import BlobStoreFixture
from oci_catalog.blobstore import (
    GC_ALREADY_DELETED,
    GC_DELETED,
    GC_SKIPPED,
    StoreError,
)
from oci_catalog.blobstore.sample_data import BASE_LAYER


class TestGcPlan(BlobStoreFixture):

    def test_plan_lists_unreachable_objects_and_unique_bytes(self):
        self.import_root("A", "delivery-a")
        self.import_root("B", "delivery-b")
        self.import_root("C")
        plan = self.store.plan_gc()
        # 手写期待：C 闭包 = manifest(399) + config(98) + layer(50)
        self.assertEqual(plan.unique_bytes, 399 + 98 + 50)
        self.assertEqual({c["digest"] for c in plan.candidates},
                         {self.layout.roots["C"],
                          self.layout.names["config-garbage"],
                          self.layout.names["garbage-l2"]})
        # 共享 base 被 A/B 引用，绝不在候选内
        self.assertNotIn(self.layout.names["base"],
                         {c["digest"] for c in plan.candidates})

    def test_plan_does_not_delete(self):
        self.import_root("C")
        plan = self.store.plan_gc()
        for candidate in plan.candidates:
            self.assertTrue(self.blob_exists(candidate["digest"]))
        self.assertEqual(self.object_count(), 3)

    def test_apply_deletes_only_planned_objects(self):
        self.import_root("A", "delivery-a")
        self.import_root("C")
        plan = self.store.plan_gc()
        run = self.store.apply_gc(plan.plan_id)
        self.assertEqual(run.freed_bytes, 547)
        self.assertEqual({item["outcome"] for item in run.items},
                         {GC_DELETED})
        self.assertFalse(self.blob_exists(self.layout.names["garbage-l2"]))
        self.assertTrue(self.blob_exists(self.layout.names["base"]))
        self.assertEqual(self.object_count(), 10)

    def test_plan_then_new_ref_skips_protected_but_deletes_rest(self):
        self.import_root("A", "delivery-a")
        self.import_root("C")
        self.import_root("D")
        plan = self.store.plan_gc()
        # 计划生成后给 C 新建保留引用
        self.store.set_ref("keep-c", self.layout.roots["C"])
        run = self.store.apply_gc(plan.plan_id)
        outcomes = {item["digest"]: item for item in run.items}
        # C 的整条闭包被跳过
        for digest in (self.layout.roots["C"],
                       self.layout.names["config-garbage"],
                       self.layout.names["garbage-l2"]):
            self.assertEqual(outcomes[digest]["outcome"], GC_SKIPPED)
            self.assertIn("可达", outcomes[digest]["reason"])
        # D 的整条闭包仍被删除
        for digest in (self.layout.roots["D"],
                       self.layout.names["config-garbage2"],
                       self.layout.names["garbage2-l2"]):
            self.assertEqual(outcomes[digest]["outcome"], GC_DELETED)
        self.assertFalse(self.blob_exists(self.layout.roots["D"]))
        self.assertTrue(self.blob_exists(self.layout.roots["C"]))

    def test_objects_appearing_after_plan_are_not_deleted(self):
        self.import_root("A", "delivery-a")
        self.import_root("C")
        plan = self.store.plan_gc()
        # 计划生成后导入一个全新的根 E（复用 layout 的 D）
        result = self.import_root("D", "delivery-e")
        self.assertEqual(result.status, "imported")
        run = self.store.apply_gc(plan.plan_id)
        planned = {c["digest"] for c in plan.candidates}
        self.assertEqual({item["digest"] for item in run.items}, planned)
        # D/E 的独有对象不在旧计划中，必须保留
        self.assertTrue(self.blob_exists(self.layout.names["garbage2-l2"]))
        self.assertTrue(self.blob_exists(self.layout.roots["D"]))

    def test_reapply_same_plan_reports_already_deleted(self):
        self.import_root("C")
        plan = self.store.plan_gc()
        first = self.store.apply_gc(plan.plan_id)
        self.assertEqual({item["outcome"] for item in first.items},
                         {GC_DELETED})
        second = self.store.apply_gc(plan.plan_id)
        self.assertEqual({item["outcome"] for item in second.items},
                         {GC_ALREADY_DELETED})
        self.assertEqual(second.freed_bytes, 0)
        # 两次运行都保留记录，不宣称第一次从未发生
        runs = self.store.list_gc_runs()
        self.assertEqual(len(runs), 2)

    def test_partial_application_distinguishes_three_outcomes(self):
        self.import_root("A", "delivery-a")
        self.import_root("C")
        self.import_root("D")
        plan = self.store.plan_gc()
        # 先只应用前两个候选（模拟中途退出）
        from oci_catalog.blobstore.store import _utcnow
        run_id = "partial-run"
        with self.store._transaction() as tx:
            tx.execute("INSERT INTO gc_runs (run_id, plan_id, applied_at) "
                       "VALUES (?, ?, ?)",
                       (run_id, plan.plan_id, _utcnow()))
        # 先只处理 C 的一个 layer，模拟应用过程在第一项之后退出
        cursor = self.store.conn.execute(
            "SELECT p.digest, p.size FROM gc_plan_objects p "
            "JOIN closure_objects co ON co.digest = p.digest "
            "JOIN closures c ON c.closure_id = co.closure_id "
            "WHERE p.plan_id = ? AND c.root_digest = ? AND co.role = 'layer'",
            (plan.plan_id, self.layout.roots["C"])).fetchone()
        self.store._apply_one_candidate(
            run_id, plan.plan_id, cursor["digest"], cursor["size"], None,
            None,
            self.store._reachable_objects(self.store._referenced_roots()))
        # 再给 D 建引用，然后重新应用整份计划
        self.store.set_ref("keep-d", self.layout.roots["D"])
        run = self.store.apply_gc(plan.plan_id)
        outcomes = {item["digest"]: item for item in run.items}
        self.assertIn(GC_SKIPPED, {i["outcome"] for i in run.items})
        self.assertIn(GC_DELETED, {i["outcome"] for i in run.items})
        self.assertIn(GC_ALREADY_DELETED,
                      {i["outcome"] for i in run.items})
        self.assertEqual(outcomes[cursor["digest"]]["outcome"],
                         GC_ALREADY_DELETED)

    def test_unknown_plan_raises(self):
        with self.assertRaises(KeyError):
            self.store.apply_gc("nope")

    def test_delete_ref_does_not_unlink(self):
        self.import_root("A", "delivery-a")
        self.store.delete_ref("delivery-a")
        for digest in self.store.conn.execute(
                "SELECT digest FROM objects").fetchall():
            self.assertTrue(self.blob_exists(digest["digest"]))


class TestGcIntegrity(BlobStoreFixture):

    def test_corrupt_referenced_closure_blocks_plan(self):
        self.import_root("A", "delivery-a")
        layer = self.layout.names["amd64-l3"]
        os.unlink(self.store.blob_path(layer))
        with self.assertRaises(StoreError) as ctx:
            self.store.plan_gc()
        self.assertIn("仓库状态异常", str(ctx.exception))
        # 其它对象不得被顺带清理：计划未生成，所有元数据仍在
        self.assertEqual(self.object_count(), 10)

    def test_corrupt_reader_closure_blocks_plan(self):
        self.import_root("A", "delivery-a")
        self.import_root("C")
        reader = self.store.open_reader("delivery-a")
        self.store.delete_ref("delivery-a")
        os.unlink(self.store.blob_path(self.layout.names["base"]))
        with self.assertRaises(StoreError):
            self.store.plan_gc()
        self.assertTrue(self.blob_exists(self.layout.names["garbage-l2"]))
        reader.close()

    def test_health_reports_corruption(self):
        self.import_root("A", "delivery-a")
        self.assertEqual(self.store.check_health()["status"], "ok")
        os.unlink(self.store.blob_path(self.layout.names["base"]))
        health = self.store.check_health()
        self.assertEqual(health["status"], "corrupt")
        self.assertTrue(any("base" in p or "长度" in p or "缺失" in p
                            for p in health["problems"]))

    def test_missing_manifest_in_closure_blocks_plan(self):
        self.import_root("A", "delivery-a")
        os.unlink(self.store.blob_path(self.layout.roots["inner"]))
        with self.assertRaises(StoreError):
            self.store.plan_gc()


class TestConcurrentGc(BlobStoreFixture):

    def test_two_concurrent_gc_runs_on_overlapping_plan(self):
        from oci_catalog.blobstore import BlobStore
        self.import_root("A", "delivery-a")
        self.import_root("C")
        self.import_root("D")
        plan = self.store.plan_gc()
        results = []
        errors = []

        def worker():
            try:
                store = BlobStore(self.store_path)
                try:
                    results.append(store.apply_gc(plan.plan_id).to_dict())
                finally:
                    store.close()
            except BaseException as exc:  # pragma: no cover - 失败时报告
                errors.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(errors, [])
        self.assertEqual(len(results), 2)
        deleted = [sum(1 for item in r["items"]
                       if item["outcome"] == GC_DELETED) for r in results]
        already = [sum(1 for item in r["items"]
                       if item["outcome"] == GC_ALREADY_DELETED)
                   for r in results]
        # 每个候选恰好删除一次；另一个回收者如实报告已删除
        self.assertEqual(sorted(deleted), [0, 6])
        self.assertEqual(sorted(already), [0, 6])
        self.assertEqual(self.object_count(), 10)

    def test_gc_while_unrelated_publish_and_plan(self):
        """长读期间其他进程仍可发布无关引用与规划空间。"""
        import threading
        import time
        from oci_catalog.blobstore import BlobStore
        self.import_root("A", "delivery-a")
        self.import_root("C")
        reader = self.store.open_reader("delivery-a")
        self.store.delete_ref("delivery-a")
        errors = []

        def publisher():
            try:
                store = BlobStore(self.store_path)
                try:
                    time.sleep(0.05)
                    store.import_layout(self.layout.layout_dir,
                                        self.layout.roots["B"], "new-b")
                    store.plan_gc()
                finally:
                    store.close()
            except BaseException as exc:  # pragma: no cover
                errors.append(exc)

        thread = threading.Thread(target=publisher)
        thread.start()
        # 读者读取期间不持有发布锁
        self.assertEqual(reader.read_all(self.layout.names["amd64-l2"]),
                         b"AMD64-UNIQUE-L2\n" + bytes(range(256)))
        thread.join()
        self.assertEqual(errors, [])
        self.assertEqual(self.store.resolve_name("new-b"),
                         self.layout.roots["B"])
        reader.close()


if __name__ == "__main__":
    unittest.main()


class TestStagingLifecycle(BlobStoreFixture):

    def test_in_progress_import_staging_not_collected(self):
        from oci_catalog.blobstore.locking import FileLock
        self.import_root("A", "delivery-a")
        # 模拟一次进行中的导入：暂存目录 + 持有中的暂存锁
        entry = "live-import"
        staging = os.path.join(self.store.staging_dir, entry)
        os.makedirs(os.path.join(staging, "sha256", "cc"))
        with open(os.path.join(staging, "sha256", "cc", "cc" * 32),
                  "wb") as fh:
            fh.write(b"PARTIAL")
        lock = FileLock(os.path.join(self.store.staging_dir,
                                     entry + ".lock"))
        lock.acquire()
        try:
            plan = self.store.plan_gc()
            self.assertFalse(any(c.get("staged_relpath")
                                 for c in plan.candidates))
            self.store.apply_gc(plan.plan_id)
            self.assertTrue(os.path.isdir(staging))
        finally:
            lock.release()
        # 锁释放后，未发布字节进入候选并可回收
        plan = self.store.plan_gc()
        self.assertTrue(any(c.get("staged_relpath")
                            for c in plan.candidates))
        self.store.apply_gc(plan.plan_id)
        self.assertFalse(os.path.isdir(staging))

    def test_redundant_staging_copy_removed_after_gc(self):
        self.import_root("A", "delivery-a")
        base = self.layout.names["base"]
        entry = "crashed-before-publish"
        staging = os.path.join(self.store.staging_dir, entry)
        os.makedirs(os.path.join(staging, "sha256",
                                 base.split(":", 1)[1][:2]))
        with open(os.path.join(staging, "sha256",
                               base.split(":", 1)[1][:2],
                               base.split(":", 1)[1]), "wb") as fh:
            fh.write(BASE_LAYER)
        plan = self.store.plan_gc()
        # 该副本与仓内对象同摘要同长度：不是可释放的新字节
        self.assertFalse(any(c.get("staged_relpath") ==
                             os.path.join("staging", entry, "sha256",
                                          base.split(":", 1)[1][:2],
                                          base.split(":", 1)[1])
                             for c in plan.candidates))
        self.store.apply_gc(plan.plan_id)
        self.assertFalse(os.path.isdir(staging))
        self.assertTrue(self.blob_exists(base))
