"""按 namespace 比较两次目录扫描。"""

from fixtures import RegistryFixture
from oci_catalog import diff_namespace_scans, latest_completed_scans


class TestNamespaceDiff(RegistryFixture):

    def test_diff_captures_moves_adds_removes(self):
        first = self.new_collector()
        r1 = first.run()
        scan_a = r1.scan_id

        # 变更 team-a namespace：
        # 1) team-a/web 的 stable 改指向 app 的 index 内容（moved）
        # 2) team-a/app 新增 tag rc1
        # 3) team-a/web 删除 tag v2
        self.registry.retag("team-a/web", "stable", self.top_index_digest)
        self.registry.retag("team-a/app", "rc1", self.top_index_digest)
        self.registry.delete_tag("team-a/web", "v2")
        # team-b 的变化不应出现在 team-a 的 diff 里
        self.registry.retag("team-b/util", "v1", self.util_v2_digest)

        second = self.new_collector(store=first.store)
        r2 = second.run()
        scan_b = r2.scan_id

        diff = diff_namespace_scans(
            first.store, self.base_url, "team-a", scan_a, scan_b)

        moved = {(d["repository"], d["tag"]) for d in diff["tags_moved"]}
        self.assertIn(("team-a/web", "stable"), moved)
        move = next(d for d in diff["tags_moved"]
                    if d["tag"] == "stable" and d["repository"] == "team-a/web")
        self.assertEqual(move["old_digest"], self.web_digest)
        self.assertEqual(move["new_digest"], self.top_index_digest)

        added = {(d["repository"], d["tag"]) for d in diff["tags_added"]}
        self.assertIn(("team-a/app", "rc1"), added)

        removed = {(d["repository"], d["tag"]) for d in diff["tags_removed"]}
        self.assertIn(("team-a/web", "v2"), removed)

        # team-b 的变动被 namespace 过滤
        all_repos = {d["repository"] for d in
                     diff["tags_moved"] + diff["tags_added"] + diff["tags_removed"]}
        self.assertNotIn("team-b/util", all_repos)

    def test_diff_detects_repository_set_changes(self):
        first = self.new_collector()
        scan_a = first.run().scan_id

        # 新建一个 team-a 下的仓库；legacy/old 的 tag 删掉（仓库从快照消失）
        from oci_catalog import make_image_manifest
        self.registry.put_manifest(
            "team-a/newrepo",
            make_image_manifest("sha256:" + "n1" * 32, []),
            "application/vnd.oci.image.manifest.v1+json", tag="v0")
        self.registry.delete_tag("legacy/old", "edge")

        second = self.new_collector(store=first.store)
        scan_b = second.run().scan_id

        diff_a = diff_namespace_scans(
            first.store, self.base_url, "team-a", scan_a, scan_b)
        self.assertEqual(diff_a["repositories_added"], ["team-a/newrepo"])
        self.assertEqual(diff_a["repositories_removed"], [])

        diff_legacy = diff_namespace_scans(
            first.store, self.base_url, "legacy", scan_a, scan_b)
        self.assertEqual(diff_legacy["repositories_removed"], ["legacy/old"])

    def test_identical_scans_produce_empty_diff(self):
        first = self.new_collector()
        scan_a = first.run().scan_id
        second = self.new_collector(store=first.store)
        scan_b = second.run().scan_id
        diff = diff_namespace_scans(
            first.store, self.base_url, "team-a", scan_a, scan_b)
        self.assertEqual(diff["tags_added"], [])
        self.assertEqual(diff["tags_removed"], [])
        self.assertEqual(diff["tags_moved"], [])
        self.assertEqual(diff["repositories_added"], [])
        self.assertEqual(diff["repositories_removed"], [])

        scans = latest_completed_scans(first.store, self.base_url)
        self.assertEqual([s["scan_id"] for s in scans], [scan_b, scan_a])
