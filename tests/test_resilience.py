"""采集中游标失效、中断续办边界、禁止 layer 下载、子 manifest GC 容错。"""

from fixtures import RegistryFixture
from oci_catalog import CursorInvalid, query_platform_references


class FailingOnceClient:
    """客户端包装：指定方法第 N 次调用时抛 CursorInvalid，之后恢复。"""

    def __init__(self, real, method_name: str, fail_on_call: int):
        self._real = real
        self._method = method_name
        self._fail_on = fail_on_call
        self.calls = 0

    def __getattr__(self, item):
        attr = getattr(self._real, item)
        if item != self._method:
            return attr

        def wrapper(*args, **kwargs):
            self.calls += 1
            if self.calls == self._fail_on:
                raise CursorInvalid("injected cursor failure")
            return attr(*args, **kwargs)

        return wrapper


class TestResilience(RegistryFixture):

    def test_catalog_cursor_failure_mid_scan_then_resume(self):
        store = self.new_store()
        # page_size=1 强制 catalog 分 4 页；第 2 页游标失效
        flaky = FailingOnceClient(self.new_client(),
                                  "list_repositories_page", fail_on_call=2)
        collector = self.__build(flaky, store)
        report = collector.run()

        self.assertEqual(report.status, "interrupted")
        self.assertIn("游标失效", report.interrupt_reason)
        # 失效发生在 catalog 阶段：还没有任何 repository 完成
        self.assertEqual(report.repositories_completed, 0)
        self.assertEqual(store.get_checkpoint(self.base_url), None)

        # 用正常客户端续办同一 scan
        report2 = self.__build(self.new_client(), store).run()
        self.assertEqual(report2.status, "completed")
        self.assertTrue(report2.resumed)
        self.assertEqual(report2.scan_id, report.scan_id)
        self.assertEqual(report2.repositories_completed, 4)

    def test_tags_cursor_failure_rolls_back_repo_and_resumes(self):
        store = self.new_store()
        # 调用次序（page_size=1）：
        # call1 = legacy/old 唯一 tag 页（成功）
        # call2 = team-a/app 第 1 页（成功），call3 = 第 2 页（失效）
        flaky = FailingOnceClient(self.new_client(),
                                  "list_tags_page", fail_on_call=3)
        report = self.__build(flaky, store).run()

        self.assertEqual(report.status, "interrupted")
        # 检查点停在最后完整提交的 repository
        self.assertEqual(store.get_checkpoint(self.base_url), "legacy/old")
        # team-a/app 的事务整体回滚：无半截 tag_state
        self.assertEqual(
            store.list_tag_states(self.base_url, "team-a/app"), [])
        # 已完成的仓库保留
        self.assertTrue(
            store.is_repo_completed(report.scan_id, "legacy/old"))

        # 续办：team-a/app 从头重新采集，全部完成
        report2 = self.__build(self.new_client(), store).run()
        self.assertEqual(report2.status, "completed")
        self.assertEqual(report2.scan_id, report.scan_id)
        app_tags = {r["tag"] for r in
                    store.list_tag_states(self.base_url, "team-a/app")}
        self.assertEqual(app_tags, {"latest", "v1.0"})

        # 已完成仓库的 created 事件没有因续办而重复
        legacy_events = store.conn.execute(
            "SELECT COUNT(*) AS c FROM tag_events "
            "WHERE repository = 'legacy/old' AND event_type = 'created'"
        ).fetchone()["c"]
        self.assertEqual(legacy_events, 1)

    def test_layers_are_never_downloaded(self):
        collector = self.new_collector()
        report = collector.run()
        self.assertEqual(report.status, "completed")
        # 只访问 manifest 端点；blob/layer 端点零请求
        self.assertGreater(self.registry.manifest_requests, 0)
        self.assertEqual(self.registry.blob_requests, [])

    def test_garbage_collected_index_child_is_tolerated(self):
        # 索引引用的一个子 manifest 已被 registry GC
        self.registry.delete_manifest("team-a/app", self.arm64_v1_digest)
        collector = self.new_collector()
        report = collector.run()
        # 单个平台缺失不影响整仓库采集
        self.assertEqual(report.status, "completed")

        result = query_platform_references(
            collector.store, self.top_index_digest)
        digests = {r["manifest_digest"] for r in result["references"]}
        # 缺失的子 manifest 以 missing 占位保留引用关系
        self.assertIn(self.arm64_v1_digest, digests)
        missing = next(r for r in result["references"]
                       if r["manifest_digest"] == self.arm64_v1_digest)
        self.assertEqual(missing["kind"], "missing")
        # 其余平台正常
        self.assertIn(self.amd64_digest, digests)
        self.assertIn(self.arm64_v2_digest, digests)

    def __build(self, client, store):
        from oci_catalog import Collector
        return Collector(client, store, registry_name=self.base_url,
                         page_size=1)
