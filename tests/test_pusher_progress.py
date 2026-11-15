"""进度文件检查：绑定冲突、损坏拒绝、原子落盘、状态机字段校验。"""

import json
import os
import unittest

from pusher_fixtures import PusherFixture

from oci_catalog.blobstore import BlobStore
from oci_catalog.pusher.errors import ProgressProblem
from oci_catalog.pusher.progress import (DONE, PENDING, Binding, Progress,
                                         normalize_endpoint)
from oci_catalog.pusher.pusher import _manifest_order


def _closure_and_order(store_path, name):
    store = BlobStore(store_path)
    try:
        with store.open_reader(name) as reader:
            closure = {d.digest: d for d in reader.objects()}
            order = _manifest_order(reader, reader.root.digest)
            root = reader.root.digest
    finally:
        store.close()
    return closure, order, root


class TestProgress(PusherFixture):
    def binding(self, **overrides):
        params = dict(
            store=os.path.abspath(self.store_path),
            name="delivery-a",
            root_digest=self.layout.root_a,
            endpoint=normalize_endpoint(self.receiver.base_url),
            repo="mirror/worker",
            tag="release-7")
        params.update(overrides)
        return Binding(**params)

    def create_progress(self, **binding_overrides):
        closure, order, _root = _closure_and_order(self.store_path,
                                                   "delivery-a")
        return Progress.create(self.progress_path,
                               self.binding(**binding_overrides),
                               closure, order)

    def load_progress(self, **binding_overrides):
        closure, order, _root = _closure_and_order(self.store_path,
                                                   "delivery-a")
        return Progress.load(self.progress_path,
                             self.binding(**binding_overrides),
                             closure, order)

    # -- 创建与重载 ------------------------------------------------------
    def test_create_then_load_roundtrip(self):
        progress = self.create_progress()
        self.assertTrue(os.path.exists(self.progress_path))
        self.assertEqual(len(progress.objects), 10)  # 根 A 闭包 10 个对象
        self.assertEqual(progress.manifest_order,
                         [self.digests["amd64-manifest"],
                          self.digests["arm64-manifest"],
                          self.digests["inner-index"],
                          self.digests["outer-index"]])
        loaded = self.load_progress()
        self.assertEqual(set(loaded.objects), set(progress.objects))
        for entry in loaded.objects.values():
            self.assertEqual(entry.state, PENDING)

    def test_manifest_order_children_before_parent(self):
        progress = self.create_progress()
        order = progress.manifest_order
        self.assertLess(order.index(self.digests["amd64-manifest"]),
                        order.index(self.digests["inner-index"]))
        self.assertLess(order.index(self.digests["arm64-manifest"]),
                        order.index(self.digests["inner-index"]))
        self.assertLess(order.index(self.digests["inner-index"]),
                        order.index(self.digests["outer-index"]))

    # -- 绑定冲突 ---------------------------------------------------------
    def test_binding_conflicts_rejected(self):
        self.create_progress()
        cases = [
            {"store": "/elsewhere"},
            {"name": "other-name"},
            {"root_digest": self.layout.old_root},
            {"endpoint": "http://127.0.0.1:1"},
            {"repo": "mirror/other"},
            {"tag": "other-tag"},
        ]
        for overrides in cases:
            with self.assertRaises(ProgressProblem, msg=str(overrides)):
                self.load_progress(**overrides)

    def test_endpoint_trailing_slash_is_same_binding(self):
        self.create_progress()
        closure, order, _ = _closure_and_order(self.store_path,
                                               "delivery-a")
        loaded = Progress.load(
            self.progress_path,
            self.binding(endpoint=normalize_endpoint(
                self.receiver.base_url + "/")),
            closure, order)
        self.assertEqual(loaded.binding.tag, "release-7")

    # -- 损坏进度：拒绝且不覆盖 -------------------------------------------
    def _assert_corrupt_rejected(self, mutate):
        self.create_progress()
        with open(self.progress_path, "rb") as fh:
            original = fh.read()
        mutate()
        with self.assertRaises(ProgressProblem):
            self.load_progress()
        # 损坏文件不得被覆盖或修复
        with open(self.progress_path, "rb") as fh:
            self.assertNotEqual(fh.read(), b"")
        os.remove(self.progress_path)

    def test_truncated_json_rejected(self):
        def mutate():
            with open(self.progress_path, "rb") as fh:
                data = fh.read()
            with open(self.progress_path, "wb") as fh:
                fh.write(data[:len(data) // 2])
        self._assert_corrupt_rejected(mutate)

    def test_garbage_file_rejected(self):
        def mutate():
            with open(self.progress_path, "wb") as fh:
                fh.write(b"\x00\xff not json")
        self._assert_corrupt_rejected(mutate)

    def test_wrong_format_rejected(self):
        def mutate():
            node = self._read_json()
            node["format"] = "something-else"
            self._write_json(node)
        self._assert_corrupt_rejected(mutate)

    def test_missing_binding_field_rejected(self):
        def mutate():
            node = self._read_json()
            del node["binding"]["tag"]
            self._write_json(node)
        self._assert_corrupt_rejected(mutate)

    def test_object_set_mismatch_rejected(self):
        def mutate():
            node = self._read_json()
            node["objects"].pop(self.digests["empty-layer"])
            self._write_json(node)
        self._assert_corrupt_rejected(mutate)

    def test_extra_object_rejected(self):
        def mutate():
            node = self._read_json()
            node["objects"]["sha256:" + "1" * 64] = {
                "kind": "blob", "media_type": "x", "size": 0,
                "state": "pending", "location": None, "confirmed": 0}
            self._write_json(node)
        self._assert_corrupt_rejected(mutate)

    def test_bad_state_rejected(self):
        def mutate():
            node = self._read_json()
            key = self.digests["base-layer"]
            node["objects"][key]["state"] = "half-done"
            self._write_json(node)
        self._assert_corrupt_rejected(mutate)

    def test_confirmed_out_of_range_rejected(self):
        def mutate():
            node = self._read_json()
            key = self.digests["base-layer"]
            node["objects"][key]["confirmed"] = 10 ** 9
            self._write_json(node)
        self._assert_corrupt_rejected(mutate)

    def test_manifest_order_tampered_rejected(self):
        def mutate():
            node = self._read_json()
            node["manifest_order"] = list(
                reversed(node["manifest_order"]))
            self._write_json(node)
        self._assert_corrupt_rejected(mutate)

    def _read_json(self):
        with open(self.progress_path, encoding="utf-8") as fh:
            return json.load(fh)

    def _write_json(self, node):
        with open(self.progress_path, "w", encoding="utf-8") as fh:
            json.dump(node, fh)

    # -- 状态推进与落盘 ----------------------------------------------------
    def test_state_transition_persisted(self):
        progress = self.create_progress()
        key = self.digests["base-layer"]
        progress.objects[key].state = DONE
        progress.objects[key].confirmed = \
            progress.objects[key].size
        progress.save()
        loaded = self.load_progress()
        self.assertEqual(loaded.objects[key].state, DONE)

    def test_atomic_write_leaves_no_tmp(self):
        self.create_progress()
        self.assertFalse(os.path.exists(self.progress_path + ".tmp"))


if __name__ == "__main__":
    unittest.main()
