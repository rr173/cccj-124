"""端到端推送：嵌套索引闭包、共享对象去重、零字节对象、远端复用、
旧交付标签保留到最后、清单依赖序、逐字节一致、单平台根、鉴权。"""

import json
import os
import unittest

from pusher_fixtures import PusherFixture

from oci_catalog.blobstore import BlobStore
from oci_catalog.pusher.errors import AuthProblem, ProtocolProblem
from oci_catalog.pusher.pusher import push


class TestPushEndToEnd(PusherFixture):
    def test_full_closure_delivered_byte_exact(self):
        result = push(self.make_config())
        self.assertEqual(result.status, "completed")
        self.verify_remote_closure()
        # 交付标签指向嵌套索引根
        self.assertEqual(self.remote_tags()["release-7"],
                         self.digests["outer-index"])
        # 远端清单可经 GET 读回原字节（客户端已核对，这里直接查文件）
        self.assertEqual(
            self.remote_manifest(self.digests["outer-index"]),
            self.bytes_table["outer-index"][0])

    def test_shared_objects_sent_once(self):
        """base 层被两个平台引用，只向同一目标仓库交付一次。"""
        push(self.make_config())
        base = self.digests["base-layer"]
        posts = [r for r in self.read_requests() if r["method"] == "POST"]
        # 每个不存在的 blob 恰好一个上传会话：5 个 blob（base/amd64/arm64/
        # empty/两个 config）——base 只算一次
        self.assertEqual(len(posts), 6)
        # 远端只有一份 base 字节
        self.assertEqual(self.remote_blob(base),
                         self.bytes_table["base-layer"][0])

    def test_zero_byte_object_delivered_without_patch(self):
        push(self.make_config())
        empty = self.digests["empty-layer"]
        self.assertEqual(self.remote_blob(empty), b"")
        # 零字节对象：无 PATCH（全部 PATCH 都属于其他对象）
        patches = self.requests_for("PATCH", "uploads")
        for record in patches:
            self.assertGreater(record["content_length"], 0)
        # 它的 PUT 完成请求带 digest 查询参数
        puts = [r for r in self.requests_for("PUT", "uploads")
                if empty in r["path"]]
        self.assertEqual(len(puts), 1)
        self.assertIn("digest=", puts[0]["path"])

    def test_existing_remote_blob_reused(self):
        """预先在远端的共享 blob 只有 HEAD，没有上传。"""
        base = self.preload_blob("base-layer")
        result = push(self.make_config())
        self.assertEqual(result.status, "completed")
        self.verify_remote_closure()
        heads = self.requests_for("HEAD", base)
        self.assertEqual(len(heads), 1)
        self.assertEqual(heads[0]["status"], 200)
        # base 没有对应的上传会话：POST 数 = blob 数 - 1
        posts = [r for r in self.read_requests() if r["method"] == "POST"]
        self.assertEqual(len(posts), 5)

    def test_old_tag_unchanged_until_final_publish(self):
        """旧交付标签在最终发布前仍可读取旧指向。"""
        old_digest = self.preload_tag("release-7", "old-manifest")
        push(self.make_config())
        # 全部 GET release-7 都发生在任何 PUT release-7 之前时，
        # 读到的是旧 digest（由接收端记录顺序核对）
        records = self.read_requests()
        tag_puts = [r["seq"] for r in records
                    if r["method"] == "PUT" and r["path"].endswith(
                        "/manifests/release-7")]
        self.assertEqual(len(tag_puts), 1)
        tag_put_seq = tag_puts[0]
        tag_gets = [r for r in records
                    if r["method"] == "GET" and r["path"].endswith(
                        "/manifests/release-7")]
        self.assertTrue(tag_gets, "恢复对账应先 GET 交付标签")
        for record in tag_gets:
            self.assertLess(record["seq"], tag_put_seq)
            self.assertEqual(record["status"], 200)  # 旧标签可读
        # 最终标签指向本次根
        self.assertEqual(self.remote_tags()["release-7"],
                         self.digests["outer-index"])
        # 旧清单字节仍按 digest 可读（内容寻址不受影响）
        self.assertEqual(self.remote_manifest(old_digest),
                         self.bytes_table["old-manifest"][0])

    def test_manifest_publish_order_children_before_parent(self):
        push(self.make_config())
        records = self.read_requests()
        manifest_puts = [r for r in records
                         if r["method"] == "PUT" and "/manifests/" in r["path"]]
        order = [r["path"].rsplit("/manifests/", 1)[1] for r in manifest_puts]
        # 子清单先于父索引，根标签最后
        amd64 = order.index(self.digests["amd64-manifest"])
        arm64 = order.index(self.digests["arm64-manifest"])
        inner = order.index(self.digests["inner-index"])
        outer = order.index(self.digests["outer-index"])
        tag = order.index("release-7")
        self.assertLess(amd64, inner)
        self.assertLess(arm64, inner)
        self.assertLess(inner, outer)
        self.assertEqual(tag, len(order) - 1)
        # 每个清单恰好 PUT 一次
        self.assertEqual(len(order), 5)

    def test_single_platform_root(self):
        """单平台 image manifest 根也可交付。"""
        store = BlobStore(self.store_path)
        try:
            result = store.import_layout(self.layout.layout_dir,
                                         self.digests["amd64-manifest"],
                                         "delivery-amd64")
            self.assertTrue(result.ok, result.to_dict())
        finally:
            store.close()
        result = push(self.make_config(name="delivery-amd64",
                                       tag="amd64-only"))
        self.assertEqual(result.status, "completed")
        self.assertEqual(self.remote_tags()["amd64-only"],
                         self.digests["amd64-manifest"])
        for name in ("base-layer", "amd64-layer", "empty-layer",
                     "amd64-config", "amd64-manifest"):
            data, _ = self.bytes_table[name]
            digest = self.digests[name]
            got = (self.remote_manifest(digest)
                   if "manifest" in name else self.remote_blob(digest))
            self.assertEqual(got, data, name)

    def test_auth_token_forwarded(self):
        self.receiver.token = "secret-token"
        with self.assertRaises(AuthProblem):
            push(self.make_config())
        result = push(self.make_config(token="secret-token"))
        self.assertEqual(result.status, "completed")
        self.verify_remote_closure()

    def test_missing_dependency_blocks_tag_publish(self):
        """接收端报告子清单依赖缺失时，客户端不得发布交付标签。"""
        old_digest = self.preload_tag("release-7", "old-manifest")
        # 谎报 amd64 独有层已存在：客户端跳过上传，接收端在 PUT
        # amd64-manifest 时做真实依赖检查并拒绝
        layer = self.digests["amd64-layer"]
        self.receiver.save_faults({
            "fake_blob_present": {layer: len(self.bytes_table[
                "amd64-layer"][0])}})
        with self.assertRaises(ProtocolProblem) as ctx:
            push(self.make_config())
        self.assertIn("BLOB_UNKNOWN", str(ctx.exception))
        # 没有发布交付标签：无任何 PUT release-7
        tag_puts = [r for r in self.read_requests()
                    if r["method"] == "PUT"
                    and r["path"].endswith("/manifests/release-7")]
        self.assertEqual(tag_puts, [])
        # 旧标签指向未被改动
        self.assertEqual(self.remote_tags()["release-7"], old_digest)

    def test_progress_completed_marker(self):
        push(self.make_config())
        with open(self.progress_path, encoding="utf-8") as fh:
            node = json.load(fh)
        self.assertEqual(node["status"], "completed")
        self.assertEqual(node["tag_state"], "done")
        self.assertTrue(all(entry["state"] == "done"
                            for entry in node["objects"].values()))

    def test_second_run_is_noop(self):
        """已完成交付重跑：全部经对账确认，不再发送任何写请求。"""
        push(self.make_config())
        count = len(self.read_requests())
        result = push(self.make_config())
        self.assertEqual(result.status, "completed")
        new_requests = self.read_requests()[count:]
        writes = [r for r in new_requests
                  if r["method"] in ("POST", "PATCH", "PUT")]
        self.assertEqual(writes, [])


if __name__ == "__main__":
    unittest.main()
