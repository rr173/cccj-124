"""tag 改指向、删除、重建的历史事件与查询。"""

from fixtures import RegistryFixture
from oci_catalog import TagEventType, query_tag_history


class TestTagHistory(RegistryFixture):

    def test_full_tag_lifecycle(self):
        # --- 第一次扫描：v1 -> util_v1, v2 -> util_v2 ---
        first = self.new_collector()
        report1 = first.run()
        self.assertEqual(report1.status, "completed")
        scan_a = report1.scan_id

        history_v1 = query_tag_history(
            first.store, self.base_url, "team-b/util", "v1")
        self.assertTrue(history_v1["exists"])
        self.assertEqual(history_v1["current"]["digest"], self.util_v1_digest)
        self.assertEqual(len(history_v1["history"]), 1)
        self.assertEqual(history_v1["history"][0]["event_type"],
                         TagEventType.CREATED.value)

        # --- registry 侧变更：v1 改指向 v2 内容；v2 被删除 ---
        self.registry.retag("team-b/util", "v1", self.util_v2_digest)
        self.registry.delete_tag("team-b/util", "v2")

        second = self.new_collector(store=first.store)
        report2 = second.run()
        self.assertEqual(report2.status, "completed")
        scan_b = report2.scan_id
        self.assertNotEqual(scan_a, scan_b)

        # v1 产生 moved 事件，旧/新 digest 都记录
        history_v1 = query_tag_history(
            first.store, self.base_url, "team-b/util", "v1")
        self.assertEqual(history_v1["current"]["digest"], self.util_v2_digest)
        self.assertEqual([e["event_type"] for e in history_v1["history"]],
                         [TagEventType.CREATED.value, TagEventType.MOVED.value])
        moved = history_v1["history"][-1]
        self.assertEqual(moved["old_digest"], self.util_v1_digest)
        self.assertEqual(moved["new_digest"], self.util_v2_digest)

        # v2 产生 deleted 事件，当前不存在
        history_v2 = query_tag_history(
            first.store, self.base_url, "team-b/util", "v2")
        self.assertFalse(history_v2["exists"])
        self.assertIsNone(history_v2["current"])
        self.assertEqual(history_v2["history"][-1]["event_type"],
                         TagEventType.DELETED.value)
        self.assertEqual(history_v2["history"][-1]["old_digest"],
                         self.util_v2_digest)

        # --- v2 重新指向一个新内容（删除后重建）---
        self.registry.retag("team-b/util", "v2", self.util_v1_digest)
        third = self.new_collector(store=first.store)
        third.run()
        history_v2 = query_tag_history(
            first.store, self.base_url, "team-b/util", "v2")
        self.assertTrue(history_v2["exists"])
        self.assertEqual(history_v2["current"]["digest"], self.util_v1_digest)
        self.assertEqual(
            [e["event_type"] for e in history_v2["history"]],
            [TagEventType.CREATED.value,
             TagEventType.DELETED.value,
             TagEventType.CREATED.value])

    def test_unchanged_tag_emits_no_new_events(self):
        first = self.new_collector()
        first.run()
        # 不做任何变更再次扫描
        second = self.new_collector(store=first.store)
        report = second.run()
        self.assertEqual(report.events_created, 0)
        self.assertEqual(report.events_moved, 0)
        self.assertEqual(report.events_deleted, 0)

    def test_tag_pointing_to_deleted_manifest(self):
        """tag 指向的 manifest 被 GC：采集到 404 时该 tag 记为删除。"""
        first = self.new_collector()
        first.run()
        # 直接从 registry 存储里抹掉 v2 的内容
        self.registry.delete_manifest("team-b/util", self.util_v2_digest)

        second = self.new_collector(store=first.store)
        # v2 tag 已随 manifest 删除而消失（fake registry 行为），应记 deleted
        report = second.run()
        self.assertEqual(report.status, "completed")
        history = query_tag_history(
            first.store, self.base_url, "team-b/util", "v2")
        self.assertFalse(history["exists"])
        self.assertEqual(history["history"][-1]["event_type"],
                         TagEventType.DELETED.value)
