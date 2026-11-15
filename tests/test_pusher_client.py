"""发布侧 HTTP 客户端协议检查（真实接收端，线程内 HTTP）。

覆盖：Location 解析（相对/带查询/每次变化/跨来源拒绝）、Range 校验
（负数/非前缀/越界/合法块内前缀）、416 对账、错误完成摘要、HEAD 矛盾、
401/403 鉴权、5xx 与网络异常分类、零字节对象。
"""

import json
import os
import unittest

from pusher_fixtures import PusherFixture

from oci_catalog.pusher.client import PushHttpClient, parse_prefix_range
from oci_catalog.pusher.errors import (AuthProblem, ProtocolProblem,
                                       RangeMismatch, TransientProblem)
from oci_catalog.pusher.progress import normalize_endpoint


class TestRangeParsing(unittest.TestCase):
    """Range 头解析：只接受 0-<end> 前缀且不越界。"""

    def test_none_means_empty_upload(self):
        self.assertEqual(parse_prefix_range(None, 100, "t"), 0)

    def test_valid_prefix(self):
        self.assertEqual(parse_prefix_range("0-99", 100, "t"), 100)
        self.assertEqual(parse_prefix_range("0-0", 100, "t"), 1)

    def test_negative_rejected(self):
        with self.assertRaises(ProtocolProblem):
            parse_prefix_range("0--5", 100, "t")

    def test_non_prefix_rejected(self):
        with self.assertRaises(ProtocolProblem):
            parse_prefix_range("5-10", 100, "t")

    def test_overflow_rejected(self):
        with self.assertRaises(ProtocolProblem):
            parse_prefix_range("0-100", 100, "t")  # 前缀 101 > size 100

    def test_garbage_rejected(self):
        for value in ("bytes 0-5", "0:5", "abc", "0-", "-5", "0-5-6"):
            with self.assertRaises(ProtocolProblem, msg=value):
                parse_prefix_range(value, 100, "t")


class TestEndpointNormalization(unittest.TestCase):
    def test_trailing_slash_and_case(self):
        self.assertEqual(normalize_endpoint("HTTP://Example.COM:8080/"),
                         "http://example.com:8080")

    def test_default_port_dropped(self):
        self.assertEqual(normalize_endpoint("http://host:80"), "http://host")
        self.assertEqual(normalize_endpoint("https://host:443"),
                         "https://host")

    def test_path_query_userinfo_rejected(self):
        from oci_catalog.pusher.errors import ProgressProblem
        for bad in ("http://host/sub", "http://host/?q=1",
                    "http://user:pw@host", "ftp://host", "http://"):
            with self.assertRaises(ProgressProblem, msg=bad):
                normalize_endpoint(bad)


class TestClientProtocol(PusherFixture):
    """客户端与真实接收端的协议交互。"""

    def client(self, **kw) -> PushHttpClient:
        kw.setdefault("timeout", 5.0)
        return PushHttpClient(self.receiver.base_url, **kw)

    def test_head_blob_200_and_404(self):
        digest = self.preload_blob("base-layer")
        client = self.client()
        size = len(self.bytes_table["base-layer"][0])
        info = client.head_blob("mirror/worker", digest, size)
        self.assertIsNotNone(info)
        self.assertEqual(info.size, size)
        missing = client.head_blob("mirror/worker",
                                   self.digests["amd64-layer"],
                                   len(self.bytes_table["amd64-layer"][0]))
        self.assertIsNone(missing)

    def test_head_blob_size_mismatch_rejected(self):
        digest = self.preload_blob("base-layer")
        with self.assertRaisesRegex(ProtocolProblem, "长度"):
            self.client().head_blob("mirror/worker", digest, 999)

    def test_upload_session_roundtrip_with_query_and_rotation(self):
        """Location 自带查询参数且每次变化；客户端必须原样带回。"""
        client = self.client()
        location = client.start_upload("mirror/worker")
        self.assertIn("session=", location)
        self.assertTrue(location.startswith(self.receiver.base_url))
        # 空上传：204 无 Range -> offset 0
        status = client.get_upload(location, 100)
        self.assertEqual(status.offset, 0)
        # 第一块
        ack = client.patch_chunk(location, 0, b"hello", 100)
        self.assertEqual(ack.offset, 5)
        self.assertIn("session=", ack.location)
        self.assertNotEqual(ack.location, location)  # session 轮换
        # 旧 session 不再可用（客户端必须跟随新 Location）
        self.assertIsNone(client.get_upload(location, 100))
        # 新位置继续
        status = client.get_upload(ack.location, 100)
        self.assertEqual(status.offset, 5)
        ack2 = client.patch_chunk(ack.location, 5, b"world", 100)
        self.assertEqual(ack2.offset, 10)

    def test_patch_misaligned_416_carries_range_and_location(self):
        client = self.client()
        location = client.start_upload("mirror/worker")
        ack = client.patch_chunk(location, 0, b"abc", 10)
        # 错位：从 0 重发 -> 416，携带服务端前缀 3 与新 Location
        with self.assertRaises(RangeMismatch) as ctx:
            client.patch_chunk(ack.location, 0, b"abc", 10)
        self.assertEqual(ctx.exception.offset, 3)
        self.assertIsNotNone(ctx.exception.location)
        # 用 416 的 Range/Location 校正后接上
        ack2 = client.patch_chunk(ctx.exception.location, 3, b"defgh", 10)
        self.assertEqual(ack2.offset, 8)

    def test_complete_upload_and_zero_byte_blob(self):
        client = self.client()
        # 零字节对象：POST 后直接 PUT
        location = client.start_upload("mirror/worker")
        empty_digest = ("sha256:" +
                        "e3b0c44298fc1c149afbf4c8996fb924"
                        "27ae41e4649b934ca495991b7852b855")
        client.complete_upload(location, empty_digest)
        head = client.head_blob("mirror/worker", empty_digest, 0)
        self.assertIsNotNone(head)
        self.assertEqual(head.size, 0)

    def test_complete_upload_wrong_digest_rejected(self):
        client = self.client()
        location = client.start_upload("mirror/worker")
        ack = client.patch_chunk(location, 0, b"abc", 3)
        wrong = "sha256:" + "0" * 64
        with self.assertRaisesRegex(ProtocolProblem, "意外响应"):
            client.complete_upload(ack.location, wrong)

    def test_cross_origin_location_rejected(self):
        self.receiver.save_faults({"cross_origin_location": True})
        client = self.client()
        with self.assertRaisesRegex(ProtocolProblem, "跨来源"):
            client.start_upload("mirror/worker")
        # 跨来源地址不得收到任何数据：faults 已消费，无后续请求发出
        self.assertEqual(self.receiver.load_faults(), {})

    def test_bad_range_variants_rejected(self):
        for mode in ("negative", "nonprefix", "overflow"):
            self.receiver.save_faults({"bad_range": {"mode": mode}})
            client = self.client()
            location = client.start_upload("mirror/worker")
            with self.assertRaises(ProtocolProblem, msg=mode):
                client.get_upload(location, 100)

    def test_wrong_completion_digest_rejected(self):
        client = self.client()
        location = client.start_upload("mirror/worker")
        ack = client.patch_chunk(location, 0, b"abc", 3)
        import hashlib
        digest = "sha256:" + hashlib.sha256(b"abc").hexdigest()
        self.receiver.save_faults(
            {"wrong_complete_digest": {"digest": digest}})
        with self.assertRaisesRegex(ProtocolProblem, "回执摘要"):
            client.complete_upload(ack.location, digest)

    def test_auth_required(self):
        self.receiver.token = "secret-token"
        # 无 token -> 401 明确失败
        with self.assertRaises(AuthProblem):
            self.client().head_blob("mirror/worker",
                                    self.digests["base-layer"], 1)
        # 错误 token -> 401
        with self.assertRaises(AuthProblem):
            self.client(token="wrong").head_blob(
                "mirror/worker", self.digests["base-layer"], 1)
        # 正确 token -> 通过（404 表示对象不存在，但鉴权已过）
        self.assertIsNone(self.client(token="secret-token").head_blob(
            "mirror/worker", self.digests["base-layer"], 1))
        # 401 不得引发重试风暴：请求数有限
        self.assertLessEqual(len(self.read_requests()), 3)

    def test_flaky_500_classified_transient(self):
        digest = self.preload_blob("base-layer")
        size = len(self.bytes_table["base-layer"][0])
        self.receiver.save_faults({"flaky_500": {"count": 2}})
        client = self.client()
        with self.assertRaises(TransientProblem):
            client.head_blob("mirror/worker", digest, size)
        with self.assertRaises(TransientProblem):
            client.head_blob("mirror/worker", digest, size)
        # 故障消费完后恢复
        self.assertIsNotNone(client.head_blob("mirror/worker", digest, size))

    def test_network_error_classified_transient(self):
        client = PushHttpClient("http://127.0.0.1:1", timeout=0.5)
        with self.assertRaises(TransientProblem):
            client.head_blob("mirror/worker", self.digests["base-layer"], 1)

    def test_manifest_put_get_roundtrip(self):
        client = self.client()
        # 先放依赖：old-manifest 的 config 与 layer
        for name in ("old-config", "old-layer"):
            data, _ = self.bytes_table[name]
            location = client.start_upload("mirror/worker")
            if data:
                ack = client.patch_chunk(location, 0, data, len(data))
                location = ack.location
            client.complete_upload(location, self.digests[name])
        raw, mt = self.bytes_table["old-manifest"]
        digest = self.digests["old-manifest"]
        client.put_manifest("mirror/worker", digest, mt, raw)
        got = client.get_manifest("mirror/worker", digest)
        self.assertIsNotNone(got)
        self.assertEqual(got[0], raw)
        self.assertEqual(got[1], digest)
        # 按 tag 读取
        client.put_manifest("mirror/worker", "v1", mt, raw)
        got = client.get_manifest("mirror/worker", "v1")
        self.assertEqual(got[1], digest)
        self.assertIsNone(client.get_manifest("mirror/worker", "no-such"))


if __name__ == "__main__":
    unittest.main()
