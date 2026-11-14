"""分页重复条目去重与游标失效后的中断/续办。"""

from fixtures import RegistryFixture
from oci_catalog import CursorInvalid
from oci_catalog.client import RegistryClient


class TestPagination(RegistryFixture):

    def test_duplicate_page_items_are_deduplicated(self):
        # fixture 默认开启 duplicate_injection：每页尾重复本页首个条目
        client = self.new_client()
        tags_page = client.list_tags_page("team-a/app", page_size=1)
        # 原始页含 2 个条目（1 真条目 + 1 重复），去重后只剩 1 个
        self.assertEqual(tags_page.duplicates, 1)
        self.assertEqual(tags_page.items, ["latest"])
        self.assertIsNotNone(tags_page.next_cursor)
        second = client.list_tags_page(
            "team-a/app", cursor=tags_page.next_cursor, page_size=1)
        self.assertEqual(second.duplicates, 1)
        # 去重后第二页只剩真正的新条目
        self.assertEqual(second.items, ["v1.0"])

        collector = self.new_collector()
        report = collector.run()
        # 4 个仓库全部采集成功，没有因重复条目产生脏数据
        self.assertEqual(report.status, "completed")
        self.assertEqual(report.repositories_completed, 4)
        self.assertGreater(report.duplicate_page_items, 0)

        # 每个仓库的 tag 数量与 registry 实际一致
        store = collector.store
        for repo, expected_tags in [
            ("team-a/app", {"latest", "v1.0"}),
            ("team-a/web", {"stable", "v2"}),
            ("team-b/util", {"v1", "v2"}),
            ("legacy/old", {"edge"}),
        ]:
            rows = store.list_tag_states(self.base_url, repo)
            self.assertEqual({r["tag"] for r in rows}, expected_tags, repo)

    def test_cursor_expiration_interrupts_and_resumes(self):
        # 第一次扫描：在完成 2 个仓库后于边界中断（此时还没触发游标失效）
        first = self.new_collector(stop_after_repos=2)
        report1 = first.run()
        self.assertEqual(report1.status, "interrupted")
        self.assertEqual(report1.repositories_completed, 2)
        self.assertTrue(report1.resumed is False)

        # registry 分页状态重置：旧 catalog 游标全部失效
        self.registry.bump_cursor_epoch()

        # 续办：从检查点之后的 repository 继续，已完成的不重复采集
        second = self.new_collector(store=first.store)
        report2 = second.run()
        self.assertEqual(report2.status, "completed")
        self.assertTrue(report2.resumed)
        # 续办批次只处理剩余 2 个仓库
        self.assertEqual(report2.repositories_completed, 2)

        # 全部 4 个仓库在同一个 scan_id 下完成
        completed = first.store.conn.execute(
            "SELECT repository FROM repo_scan_states WHERE scan_id = ? "
            "AND status = 'completed' ORDER BY repository",
            (report1.scan_id,)).fetchall()
        self.assertEqual(len(completed), 4)

        # 事件没有重复：created 事件数等于 tag 总数
        created = first.store.conn.execute(
            "SELECT COUNT(*) AS c FROM tag_events "
            "WHERE event_type = 'created'").fetchone()["c"]
        observed = first.store.conn.execute(
            "SELECT COUNT(*) AS c FROM tag_observations "
            "WHERE scan_id = ?", (report1.scan_id,)).fetchone()["c"]
        self.assertEqual(created, observed)

    def test_cursor_invalid_during_catalog_raises_interrupt(self):
        client = self.new_client()
        page = client.list_repositories_page(page_size=2)
        self.assertIsNotNone(page.next_cursor)
        self.registry.bump_cursor_epoch()
        with self.assertRaises(CursorInvalid):
            client.list_repositories_page(cursor=page.next_cursor, page_size=2)

    def test_resume_is_idempotent_across_restarts(self):
        """分三次跑完，任何仓库都不会被采集两次。"""
        store = self.new_store()
        r1 = self.new_collector(store=store, stop_after_repos=1).run()
        self.assertEqual(r1.status, "interrupted")
        r2 = self.new_collector(store=store, stop_after_repos=1).run()
        self.assertEqual(r2.status, "interrupted")
        self.assertTrue(r2.resumed)
        r3 = self.new_collector(store=store).run()
        self.assertEqual(r3.status, "completed")

        # 同一 scan_id 贯穿三次运行
        self.assertEqual(r1.scan_id, r2.scan_id)
        self.assertEqual(r2.scan_id, r3.scan_id)
        # 内容身份总数与一次跑完一致（9 个唯一 digest）
        identities = store.conn.execute(
            "SELECT COUNT(*) AS c FROM manifests").fetchone()["c"]
        self.assertEqual(identities, 9)
