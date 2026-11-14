"""digest 校验不符 -> 仓库隔离；隔离后跳过且不污染其他仓库。"""

from fixtures import RegistryFixture
from oci_catalog import DigestMismatch, QuarantineReason
from oci_catalog.queries import query_tag_history


class TestQuarantine(RegistryFixture):

    def test_digest_mismatch_quarantines_repository(self):
        # 直接对 team-b/util 的 v2 内容注入错误 digest 头
        self.registry.corrupt_manifest_digest(
            "team-b/util", self.util_v2_digest)

        collector = self.new_collector()
        report = collector.run()
        self.assertEqual(report.status, "completed")
        self.assertEqual(report.repositories_quarantined, 1)

        # 隔离表记录了期望/实际 digest
        quarantined = collector.store.list_quarantined(self.base_url)
        self.assertEqual(len(quarantined), 1)
        row = quarantined[0]
        self.assertEqual(row["repository"], "team-b/util")
        self.assertEqual(row["reason"],
                         QuarantineReason.DIGEST_MISMATCH.value)
        self.assertNotEqual(row["expected"], row["actual"])
        self.assertEqual(row["actual"], self.util_v2_digest)

        # 被隔离仓库没有任何半截数据：tag_state 为空
        states = collector.store.list_tag_states(
            self.base_url, "team-b/util")
        self.assertEqual(states, [])
        # 事件表也没有该仓库的记录（事务整体回滚）
        events = collector.store.conn.execute(
            "SELECT COUNT(*) AS c FROM tag_events WHERE repository = ?",
            ("team-b/util",)).fetchone()["c"]
        self.assertEqual(events, 0)
        # 不一致的内容没有进入内容身份表
        self.assertFalse(collector.store.has_manifest(self.util_v2_digest))

        # 其他仓库正常采集
        app = query_tag_history(
            collector.store, self.base_url, "team-a/app", "latest")
        self.assertTrue(app["exists"])

    def test_quarantined_repo_skipped_on_rescan(self):
        self.registry.corrupt_manifest_digest(
            "team-b/util", self.util_v2_digest)
        first = self.new_collector()
        first.run()
        # 第二次扫描：隔离仓库被直接跳过，扫描仍正常完成
        second = self.new_collector(store=first.store).run()
        self.assertEqual(second.status, "completed")
        self.assertEqual(second.repositories_quarantined, 1)

        # 修复 registry 后仍被隔离（隔离是显式人工处置状态，不会自动解除）
        self.registry.corrupted.clear()
        report = self.new_collector(store=first.store).run()
        self.assertEqual(report.repositories_quarantined, 1)
        states = first.store.list_tag_states(self.base_url, "team-b/util")
        self.assertEqual(states, [])

    def test_client_raises_digest_mismatch_directly(self):
        self.registry.corrupt_manifest_digest(
            "team-b/util", self.util_v2_digest)
        client = self.new_client()
        with self.assertRaises(DigestMismatch) as ctx:
            client.get_manifest("team-b/util", "v2")
        self.assertEqual(ctx.exception.actual, self.util_v2_digest)
        self.assertEqual(ctx.exception.repository, "team-b/util")

    def test_corruption_in_index_child_quarantines_whole_repo(self):
        """索引子 manifest 的 digest 不符同样隔离整个仓库。"""
        self.registry.corrupt_manifest_digest(
            "team-a/app", self.amd64_digest)
        collector = self.new_collector()
        report = collector.run()
        self.assertEqual(report.repositories_quarantined, 1)
        rows = {r["repository"] for r in
                collector.store.list_quarantined(self.base_url)}
        self.assertIn("team-a/app", rows)
        # 顶层索引本身也不能入库（整仓库事务回滚）
        self.assertFalse(
            collector.store.has_manifest(self.top_index_digest))
