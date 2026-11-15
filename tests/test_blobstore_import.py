"""导入接收边界：嵌套索引闭包、共享对象去重、真实字节核验与失败原子性。"""

import hashlib
import json
import os
import unittest

from blobstore_fixtures import BlobStoreFixture
from oci_catalog.blobstore import (
    IMPORTED,
    NAME_REPLACED,
    BlobStore,
    StoreError,
)
from oci_catalog.blobstore.sample_data import (
    AMD64_L2,
    BASE_LAYER,
    OCI_IMAGE_INDEX,
    OCI_IMAGE_MANIFEST,
)


class TestImportClosure(BlobStoreFixture):

    def test_nested_index_imports_full_closure(self):
        result = self.import_root("A", "delivery-a")
        self.assertEqual(result.status, IMPORTED)
        self.assertEqual(result.objects_added, 10)
        self.assertEqual(result.objects_existing, 0)
        self.assertEqual(result.name_status, "set")
        # 根/子 index/两个 image manifest/两个 config/四条 layer
        closure = self.store.conn.execute(
            "SELECT digest FROM closure_objects ORDER BY digest").fetchall()
        self.assertEqual(len(closure), 10)
        roles = {row["role"] for row in self.store.conn.execute(
            "SELECT role FROM closure_objects").fetchall()}
        self.assertIn("root", roles)
        self.assertIn("manifest", roles)
        self.assertIn("config", roles)
        self.assertIn("layer", roles)

    def test_shared_objects_counted_once_by_length(self):
        self.import_root("A", "delivery-a")
        self.import_root("B", "delivery-b")
        stats = self.store.stats()
        # A 的 10 个对象 + B 独有 config/manifest/layer = 13，共享 base 只算一次
        self.assertEqual(stats["object_count"], 13)
        base = self.layout.names["base"]
        expected = sum(len(info[1]) for info in [])
        sizes = {row["digest"]: row["size"] for row in self.store.conn.execute(
            "SELECT digest, size FROM objects").fetchall()}
        self.assertEqual(sizes[base], len(BASE_LAYER))
        self.assertEqual(stats["unique_bytes"], sum(sizes.values()))

    def test_manifest_bytes_kept_verbatim(self):
        self.import_root("A")
        root = self.layout.roots["A"]
        with open(self.store.blob_path(root), "rb") as fh:
            stored = fh.read()
        self.assertEqual(hashlib.sha256(stored).hexdigest(),
                         root.split(":", 1)[1])
        # 与输入 layout 的原始字节完全一致
        with open(self.layout.blob_path(root), "rb") as fh:
            self.assertEqual(stored, fh.read())

    def test_non_utf8_layer_bytes_preserved(self):
        self.import_root("A", "delivery-a")
        with self.store.open_reader("delivery-a") as reader:
            digest = self.layout.names["amd64-l2"]
            self.assertEqual(reader.read_all(digest), AMD64_L2)
            self.assertIn(b"\xff", reader.read_all(digest))

    def test_same_name_same_root_is_idempotent(self):
        first = self.import_root("A", "delivery-a")
        second = self.import_root("A", "delivery-a")
        self.assertEqual(second.name_status, "set")
        self.assertEqual(second.objects_added, 0)
        self.assertEqual(second.objects_existing, 10)

    def test_name_replacement_is_explicit(self):
        self.import_root("A", "delivery-a")
        self.import_root("B", "delivery-b")
        status = self.store.set_ref("delivery-a", self.layout.roots["B"])
        self.assertEqual(status, NAME_REPLACED)
        self.assertEqual(self.store.resolve_name("delivery-a"),
                         self.layout.roots["B"])
        # 原根闭包仍完整（替换名称不删对象）
        self.assertTrue(self.blob_exists(self.layout.roots["A"]))

    def test_import_does_not_modify_source_layout(self):
        before = {}
        for dirpath, _dirnames, filenames in os.walk(self.layout.layout_dir):
            for filename in filenames:
                full = os.path.join(dirpath, filename)
                with open(full, "rb") as fh:
                    before[full] = hashlib.sha256(fh.read()).hexdigest()
        self.import_root("A")
        after = {}
        for dirpath, _dirnames, filenames in os.walk(self.layout.layout_dir):
            for filename in filenames:
                full = os.path.join(dirpath, filename)
                with open(full, "rb") as fh:
                    after[full] = hashlib.sha256(fh.read()).hexdigest()
        self.assertEqual(before, after)


class TestImportRejections(BlobStoreFixture):

    def assert_failed(self, result, code):
        self.assertEqual(result.status, "failed")
        self.assertIn(code, [d.code for d in result.diagnostics])

    def test_missing_object_rejected(self):
        bad = self.copy_layout("missing")
        # 第二层 manifest 的子对象里删掉一个 layer
        self.remove_blob(bad, self.layout.names["arm64-l2"])
        result = self.store.import_layout(bad, self.layout.roots["A"], "new")
        self.assert_failed(result, "missing_object")
        self.assertEqual(self.store.list_refs(), [])

    def test_wrong_length_rejected(self):
        bad = self.copy_layout("badlen")
        self.rewrite_blob(bad, self.layout.names["base"], b"short")
        result = self.store.import_layout(bad, self.layout.roots["A"])
        self.assert_failed(result, "size_mismatch")

    def test_wrong_digest_rejected(self):
        bad = self.copy_layout("baddigest")
        # 保持长度不变但替换 bytes -> 摘要不符
        original = BASE_LAYER
        mutated = bytes([original[0] ^ 0xFF]) + original[1:]
        self.rewrite_blob(bad, self.layout.names["base"], mutated)
        result = self.store.import_layout(bad, self.layout.roots["A"])
        self.assert_failed(result, "digest_mismatch")

    def test_unsupported_manifest_type_rejected(self):
        layout_dir = self.copy_layout("docker")
        raw = json.dumps({
            "schemaVersion": 2,
            "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
            "config": {"mediaType": "application/vnd.docker.container.image.v1+json",
                       "digest": self.layout.names["base"],
                       "size": len(BASE_LAYER)},
            "layers": [],
        }, sort_keys=True, separators=(",", ":")).encode()
        digest = self.add_layout_manifest(
            layout_dir, raw,
            "application/vnd.docker.distribution.manifest.v2+json")
        result = self.store.import_layout(layout_dir, digest)
        self.assert_failed(result, "unsupported_manifest_type")

    def test_duplicate_json_keys_rejected(self):
        layout_dir = self.copy_layout("dup")
        raw = (b'{"schemaVersion":2,'
               b'"mediaType":"application/vnd.oci.image.index.v1+json",'
               b'"manifests":[],"manifests":[]}')
        digest = self.add_layout_manifest(layout_dir, raw, OCI_IMAGE_INDEX)
        result = self.store.import_layout(layout_dir, digest)
        self.assert_failed(result, "duplicate_json_key")

    def test_conflicting_descriptor_rejected(self):
        layout_dir = self.copy_layout("conflict")
        base = self.layout.names["base"]
        raw = json.dumps({
            "schemaVersion": 2,
            "mediaType": OCI_IMAGE_INDEX,
            "manifests": [
                {"mediaType": OCI_IMAGE_MANIFEST, "digest": base,
                 "size": len(BASE_LAYER)},
                {"mediaType": OCI_IMAGE_MANIFEST, "digest": base,
                 "size": len(BASE_LAYER) + 1},
            ],
        }, sort_keys=True, separators=(",", ":")).encode()
        digest = self.add_layout_manifest(layout_dir, raw, OCI_IMAGE_INDEX)
        result = self.store.import_layout(layout_dir, digest)
        self.assert_failed(result, "conflicting_descriptor")

    def test_invalid_digest_rejected(self):
        result = self.store.import_layout(self.layout.layout_dir,
                                          "sha256:not-hex")
        self.assert_failed(result, "invalid_digest")
        self.assertEqual(self.store.list_refs(), [])

    def test_negative_size_rejected(self):
        layout_dir = self.copy_layout("negsize")
        raw = json.dumps({
            "schemaVersion": 2, "mediaType": OCI_IMAGE_INDEX,
            "manifests": [{"mediaType": OCI_IMAGE_MANIFEST,
                           "digest": self.layout.names["base"],
                           "size": -1}],
        }, sort_keys=True, separators=(",", ":")).encode()
        digest = self.add_layout_manifest(layout_dir, raw, OCI_IMAGE_INDEX)
        result = self.store.import_layout(layout_dir, digest)
        self.assert_failed(result, "invalid_size")

    def test_root_must_exist_in_index_json(self):
        result = self.store.import_layout(
            self.layout.layout_dir, "sha256:" + "ab" * 32)
        self.assert_failed(result, "invalid_layout")

    def test_failed_import_keeps_existing_name_usable(self):
        self.import_root("A", "delivery-a")
        before = self.store.resolve_name("delivery-a")
        bad = self.copy_layout("missing2")
        self.remove_blob(bad, self.layout.names["amd64-l2"])
        result = self.store.import_layout(bad, self.layout.roots["A"],
                                          "delivery-a")
        self.assertEqual(result.status, "failed")
        self.assertEqual(self.store.resolve_name("delivery-a"), before)
        with self.store.open_reader("delivery-a") as reader:
            self.assertEqual(
                reader.read_all(self.layout.names["amd64-l2"]), AMD64_L2)

    def test_failure_recorded_without_visible_objects(self):
        bad = self.copy_layout("missing3")
        self.remove_blob(bad, self.layout.names["base"])
        self.store.import_layout(bad, self.layout.roots["A"])
        self.assertEqual(self.object_count(), 0)
        failures = self.store.conn.execute(
            "SELECT COUNT(*) AS c FROM import_failures").fetchone()["c"]
        self.assertEqual(failures, 1)

    def test_unreadable_layout_dir(self):
        result = self.store.import_layout(
            os.path.join(self.tmpdir, "nope"), self.layout.roots["A"])
        self.assert_failed(result, "invalid_layout")


if __name__ == "__main__":
    unittest.main()


class TestCopySemantics(BlobStoreFixture):

    def test_source_mutation_after_import_does_not_change_store(self):
        self.import_root("A", "delivery-a")
        layer = self.layout.names["amd64-l2"]
        # 导入后改写输入 layout 的同一路径字节
        self.rewrite_blob(self.layout.layout_dir, layer, b"REPLACED" * 50)
        with self.store.open_reader("delivery-a") as reader:
            self.assertEqual(reader.read_all(layer), AMD64_L2)
        # 仓内文件字节也未改变
        with open(self.store.blob_path(layer), "rb") as fh:
            self.assertEqual(fh.read(), AMD64_L2)

    def test_copy_is_chunked(self):
        """小 chunk 的导入必须与默认结果一致（逐块复制/核验路径）。"""
        import shutil
        path = os.path.join(self.tmpdir, "small-chunk-store")
        self.store.close()
        self.store = BlobStore(path, chunk_size=7)
        result = self.import_root("A", "delivery-a")
        self.assertEqual(result.status, IMPORTED)
        with self.store.open_reader("delivery-a") as reader:
            self.assertEqual(reader.read_all(self.layout.names["amd64-l2"]),
                             AMD64_L2)
        self.store.close()
        self.store = BlobStore(self.store_path)  # tearDown 使用默认仓

    def test_source_change_during_copy_rejected(self):
        """复制期间源字节被改动：摘要不符必须整体拒绝。"""
        import oci_catalog.blobstore.store as store_module
        original = store_module._copy_verified
        layer = self.layout.names["base"]
        state = {"mutated": False}

        def mutate_then_copy(src, dst, digest, size, chunk_size):
            if not state["mutated"]:
                state["mutated"] = True
                with open(src, "r+b") as fh:
                    fh.seek(0)
                    fh.write(b"X")
            return original(src, dst, digest, size, chunk_size)

        store_module._copy_verified = mutate_then_copy
        try:
            result = self.import_root("A", "delivery-a")
        finally:
            store_module._copy_verified = original
        self.assertEqual(result.status, "failed")
        self.assertIn("digest_mismatch", [d.code for d in result.diagnostics])
        self.assertEqual(self.store.list_refs(), [])
        self.assertEqual(self.object_count(), 0)
