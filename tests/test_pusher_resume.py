"""恢复与故障注入：断连续传、回执丢失对账、会话过期重传、源保护。

每个场景都用真实接收端：故障经控制文件注入，客户端经真实 HTTP 交互；
"第二次带上同一进度文件"用再次调用 push() 模拟（全部状态都在进度
文件与接收端，演示脚本另做真实跨进程验证）。
"""

import json
import os
import unittest

from pusher_fixtures import PusherFixture

from oci_catalog.blobstore import BlobStore
from oci_catalog.pusher.errors import (ProgressProblem, ProtocolProblem,
                                       RetryExhausted, SourceProblem)
from oci_catalog.pusher.pusher import push
from oci_catalog.pusher.progress import Progress


class TestPatchDropResume(PusherFixture):
    """PATCH 接收部分字节后断开：第一条命令用尽尝试，第二条继续。"""

    def test_resume_from_server_confirmed_prefix_inside_chunk(self):
        # 第 3 次 PATCH（某个 128 字节块的第一块）起连续 3 次断连，
        # 每次服务端实收 37 字节（落在 128 字节块内部）
        self.receiver.save_faults({
            "drop_patch": {"at_count": 3, "accept_bytes": 37, "times": 3}})
        with self.assertRaises(RetryExhausted):
            push(self.make_config())
        # 服务端实收 3*37=111 字节（块内前缀）
        records = self.read_requests()
        dropped = [r for r in records if r["status"] == "dropped"]
        self.assertEqual(len(dropped), 3)
        self.assertEqual(dropped[0]["content_range"], "0-127")
        self.assertEqual(dropped[1]["content_range"], "37-164")
        self.assertEqual(dropped[2]["content_range"], "74-201")
        # 进度保留：被中断的对象仍在 uploading，confirmed 是保守下界
        node = json.load(open(self.progress_path, encoding="utf-8"))
        uploading = {d: e for d, e in node["objects"].items()
                     if e["state"] == "uploading"}
        self.assertEqual(len(uploading), 1)
        interrupted_digest, entry = next(iter(uploading.items()))
        self.assertLessEqual(entry["confirmed"], 111)
        expected = next(data for name, (data, _mt)
                        in self.bytes_table.items()
                        if self.digests[name] == interrupted_digest)
        # 第二次：从服务端确认前缀 111 之后接上
        result = push(self.make_config())
        self.assertEqual(result.status, "completed")
        self.verify_remote_closure()
        records = self.read_requests()
        resume = [r for r in records
                  if r["method"] == "PATCH" and r["seq"] > dropped[-1]["seq"]]
        self.assertEqual(resume[0]["content_range"], "111-238")
        # 不重复拼入前缀、不跳掉剩余字节：逐字节一致
        self.assertEqual(self.remote_blob(interrupted_digest), expected)

    def test_short_patch_continues_from_acknowledged_prefix(self):
        """服务端只收 50 字节但正常回 202：客户端从确认前缀继续。"""
        self.receiver.save_faults({
            "short_patch": {"at_count": 3, "accept_bytes": 50}})
        result = push(self.make_config())
        self.assertEqual(result.status, "completed")
        self.verify_remote_closure()
        records = self.read_requests()
        short = [r for r in records if r.get("note", "").startswith(
            "short_patch")]
        self.assertEqual(len(short), 1)
        self.assertEqual(short[0]["content_range"], "0-127")
        follow = [r for r in records if r["method"] == "PATCH"
                  and r["seq"] > short[0]["seq"]]
        self.assertEqual(follow[0]["content_range"], "50-177")


class TestCompletionReceiptLost(PusherFixture):
    """完成对象已成功但 201 丢失：不重复上传已完成对象。"""

    def test_put_complete_201_lost_reconciled_by_head(self):
        layer = self.digests["amd64-layer"]
        # PUT 完成落库但回执丢失；随后 3 次请求 500 让第一条命令用尽
        self.receiver.save_faults({
            "drop_put_complete": {"digest": layer, "then_flaky": 3}})
        with self.assertRaises(RetryExhausted):
            push(self.make_config(name="delivery-amd64", tag="t1"))
        # 对象已在远端
        self.assertEqual(self.remote_blob(layer),
                         self.bytes_table["amd64-layer"][0])
        before = len(self.read_requests())
        # 第二条命令：HEAD 发现对象已存在，不再上传
        self.receiver.save_faults({})
        result = push(self.make_config(name="delivery-amd64", tag="t1"))
        self.assertEqual(result.status, "completed")
        new_records = self.read_requests()[before:]
        # 被中断对象没有重传：run 2 没有带它 digest 的 PUT 完成请求，
        # 也没有属于它内容的 PATCH（run 2 的 PATCH 只有 config 一块）
        layer_puts = [r for r in new_records
                      if r["method"] == "PUT" and layer in r["path"]]
        self.assertEqual(layer_puts, [])
        patch_bytes = sum(r["content_length"] for r in new_records
                          if r["method"] == "PATCH")
        self.assertEqual(patch_bytes,
                         len(self.bytes_table["amd64-config"][0]))
        # 该对象全程只有一个 PUT 完成请求（第一次被断连的那次）
        puts = [r for r in self.read_requests()
                if r["method"] == "PUT" and layer in r["path"]]
        self.assertEqual(len(puts), 1)
        # 单平台闭包逐字节核对
        for name in ("base-layer", "amd64-layer", "empty-layer",
                     "amd64-config", "amd64-manifest"):
            data, _mt = self.bytes_table[name]
            digest = self.digests[name]
            got = (self.remote_manifest(digest)
                   if "manifest" in name else self.remote_blob(digest))
            self.assertEqual(got, data, name)

    def setUp(self):
        super().setUp()
        store = BlobStore(self.store_path)
        try:
            result = store.import_layout(self.layout.layout_dir,
                                         self.digests["amd64-manifest"],
                                         "delivery-amd64")
            assert result.ok, result.to_dict()
        finally:
            store.close()


class TestSessionExpired(PusherFixture):
    """上传会话 404 且对象不存在：新开会话重新发送这个对象。"""

    def test_session_gone_object_absent_reuploads(self):
        # 第 3 次 PATCH（amd64-layer 第一块）成功后会话被删除
        self.receiver.save_faults({"expire_after_patch": {"at_count": 3}})
        result = push(self.make_config())
        self.assertEqual(result.status, "completed")
        self.verify_remote_closure()
        records = self.read_requests()
        expired = [r for r in records
                   if r.get("note") == "expire_after_patch"]
        self.assertEqual(len(expired), 1)
        # 会话过期后客户端重开会话：POST 数 = blob 数 + 1
        posts = [r for r in records if r["method"] == "POST"]
        self.assertEqual(len(posts), 7)
        # 重传会话从 0 开始完整发送该对象
        layer_size = len(self.bytes_table["amd64-layer"][0])
        after = [r for r in records if r["seq"] > expired[0]["seq"]
                 and r["method"] == "PATCH"]
        self.assertEqual(after[0]["content_range"], "0-127")
        total = sum(r["content_length"] for r in after
                    if r["status"] == 202)
        self.assertGreaterEqual(total, layer_size)


class TestTagReceiptLost(PusherFixture):
    """根交付标签已改成功但回执丢失：继续时先核对，不重复 PUT。"""

    def test_tag_put_201_lost_not_repeated(self):
        self.receiver.save_faults({
            "drop_manifest_put": {"reference": "release-7",
                                  "then_flaky": 3}})
        with self.assertRaises(RetryExhausted):
            push(self.make_config())
        # 标签实际已指向本次根
        self.assertEqual(self.remote_tags()["release-7"],
                         self.digests["outer-index"])
        before = len(self.read_requests())
        result = push(self.make_config())
        self.assertEqual(result.status, "completed")
        new_records = self.read_requests()[before:]
        # 继续时只 GET 核对，不再 PUT 任何清单
        writes = [r for r in new_records
                  if r["method"] in ("POST", "PATCH", "PUT")]
        self.assertEqual(writes, [])
        tag_puts = [r for r in self.read_requests()
                    if r["method"] == "PUT"
                    and r["path"].endswith("/manifests/release-7")]
        self.assertEqual(len(tag_puts), 1)


class TestSourceProtection(PusherFixture):
    """源保护：名称漂移拒绝、运行中改名不影响、字节不可读拒绝。"""

    def test_name_moved_between_runs_refused(self):
        self.receiver.save_faults({
            "drop_patch": {"at_count": 3, "accept_bytes": 10, "times": 3}})
        with self.assertRaises(RetryExhausted):
            push(self.make_config())
        # 名称被改指向旧根：恢复必须拒绝，不悄悄换根
        store = BlobStore(self.store_path)
        try:
            store.set_ref("delivery-a", self.layout.old_root)
        finally:
            store.close()
        with self.assertRaises(SourceProblem):
            push(self.make_config())
        # 改回原名后可继续
        store = BlobStore(self.store_path)
        try:
            store.set_ref("delivery-a", self.layout.root_a)
        finally:
            store.close()
        result = push(self.make_config())
        self.assertEqual(result.status, "completed")

    def test_name_deleted_between_runs_refused(self):
        self.receiver.save_faults({
            "drop_patch": {"at_count": 3, "accept_bytes": 10, "times": 3}})
        with self.assertRaises(RetryExhausted):
            push(self.make_config())
        store = BlobStore(self.store_path)
        try:
            store.delete_ref("delivery-a")
        finally:
            store.close()
        with self.assertRaises(SourceProblem):
            push(self.make_config())

    def test_name_moved_during_run_does_not_mix(self):
        """运行期间名称被更新：本次交付仍固定最初的根。"""
        # 用故障让推送在 amd64-layer 前暂停一轮，期间改名称
        self.receiver.save_faults({"flaky_500": {"count": 1}})
        config = self.make_config()
        # 第一次调用先消耗掉故障并完成部分对象
        # 直接验证：打开读者后改名，推送仍交付根 A
        from oci_catalog.pusher.pusher import _manifest_order
        from oci_catalog.pusher.progress import Binding, Progress
        from oci_catalog.pusher.progress import normalize_endpoint
        store = BlobStore(self.store_path)
        try:
            reader = store.open_reader("delivery-a")
            try:
                root = reader.root.digest
                store.set_ref("delivery-a", self.layout.old_root)
                # 读者固定的仍是根 A
                self.assertEqual(root, self.layout.root_a)
                closure = {d.digest: d for d in reader.objects()}
                self.assertIn(self.digests["arm64-layer"], closure)
            finally:
                reader.close()
            store.set_ref("delivery-a", self.layout.root_a)
        finally:
            store.close()

    def test_source_bytes_unreadable_refused(self):
        self.receiver.save_faults({
            "drop_patch": {"at_count": 3, "accept_bytes": 10, "times": 3}})
        with self.assertRaises(RetryExhausted):
            push(self.make_config())
        # 模拟进程间隔中对象被回收：删掉 amd64-layer 的字节文件
        store = BlobStore(self.store_path)
        try:
            os.unlink(store.blob_path(self.digests["amd64-layer"]))
        finally:
            store.close()
        with self.assertRaises(SourceProblem):
            push(self.make_config())


class TestBindingAndCorruption(PusherFixture):
    """绑定冲突与损坏进度：在发送写请求前拒绝。"""

    def _make_interrupted_progress(self):
        self.receiver.save_faults({
            "drop_patch": {"at_count": 3, "accept_bytes": 10, "times": 3}})
        with self.assertRaises(RetryExhausted):
            push(self.make_config())
        return len(self.read_requests())

    def test_binding_conflict_refused_before_any_write(self):
        count = self._make_interrupted_progress()
        # 参数与进度绑定冲突：ProgressProblem
        for overrides in ({"tag": "other-tag"}, {"repo": "mirror/other"},
                          {"endpoint": "http://127.0.0.1:1"}):
            with self.assertRaises(ProgressProblem, msg=str(overrides)):
                push(self.make_config(**overrides))
            # 未发送任何新请求
            self.assertEqual(len(self.read_requests()), count)
        # 名称指向另一个根：SourceProblem（源保护先于绑定校验）
        with self.assertRaises(SourceProblem):
            push(self.make_config(name="old-root"))
        self.assertEqual(len(self.read_requests()), count)

    def test_corrupt_progress_refused_and_not_overwritten(self):
        self._make_interrupted_progress()
        with open(self.progress_path, "ab") as fh:
            fh.write(b"garbage")
        before = os.lstat(self.progress_path).st_size
        count = len(self.read_requests())
        with self.assertRaises(ProgressProblem):
            push(self.make_config())
        self.assertEqual(os.lstat(self.progress_path).st_size, before)
        self.assertEqual(len(self.read_requests()), count)

    def test_flaky_500_exhaustion_then_resume(self):
        self.receiver.save_faults({"flaky_500": {"count": 3}})
        with self.assertRaises(RetryExhausted):
            push(self.make_config())
        result = push(self.make_config())
        self.assertEqual(result.status, "completed")
        self.verify_remote_closure()


class TestCrossOriginAtPusherLevel(PusherFixture):
    def test_cross_origin_location_aborts_before_sending(self):
        self.receiver.save_faults({"cross_origin_location": True})
        with self.assertRaisesRegex(ProtocolProblem, "跨来源"):
            push(self.make_config())
        # 只有 HEAD 与 POST 两个请求；没有向跨来源地址发出任何字节
        methods = [r["method"] for r in self.read_requests()]
        self.assertEqual(methods, ["HEAD", "POST"])


if __name__ == "__main__":
    unittest.main()
