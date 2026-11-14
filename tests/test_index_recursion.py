"""多平台索引递归、内容身份去重、未知 media type。"""

from fixtures import RegistryFixture, UNKNOWN_MEDIA
from oci_catalog import ManifestKind, query_platform_references


class TestIndexRecursion(RegistryFixture):

    def test_nested_index_expands_to_all_platforms(self):
        collector = self.new_collector()
        report = collector.run()
        self.assertEqual(report.status, "completed")
        # 顶层 index + 嵌套 index + 3 个 image + web + 2 个 util + 1 个未知
        # = 9 个不同 digest 的内容身份
        self.assertEqual(report.manifests_ingested, 9)
        # 两次索引展开（顶层 + 嵌套）
        self.assertGreaterEqual(report.index_expansions, 2)

        result = query_platform_references(collector.store, self.top_index_digest)
        self.assertEqual(result["kind"], ManifestKind.INDEX.value)
        kinds = [r["manifest_digest"] for r in result["references"]]
        # 三个叶子 image 全部展开
        self.assertIn(self.amd64_digest, kinds)
        self.assertIn(self.arm64_v1_digest, kinds)
        self.assertIn(self.arm64_v2_digest, kinds)
        # 嵌套路径长度：amd64 为 2 级，arm64 为 3 级
        by_digest = {r["manifest_digest"]: r for r in result["references"]}
        self.assertEqual(len(by_digest[self.amd64_digest]["path"]), 2)
        arm_path = by_digest[self.arm64_v1_digest]["path"]
        self.assertEqual(arm_path, [
            self.top_index_digest, self.nested_index_digest,
            self.arm64_v1_digest])

        # 平台描述随 descriptor 保留
        amd_ref = by_digest[self.amd64_digest]
        self.assertEqual(amd_ref["platform"]["architecture"], "amd64")
        self.assertEqual(amd_ref["platform"]["os"], "linux")
        arm_ref = by_digest[self.arm64_v1_digest]
        self.assertEqual(arm_ref["platform"]["variant"], "v8")

        # config/layer digest 完整保留
        self.assertEqual(amd_ref["config_digest"], "sha256:" + "a1" * 32)
        self.assertEqual(amd_ref["layer_digests"],
                         ["sha256:" + "l1" * 32, "sha256:" + "l2" * 32])

    def test_same_digest_multiple_tags_single_identity(self):
        collector = self.new_collector()
        collector.run()
        store = collector.store

        # team-a/app: latest 与 v1.0 指向同一 index digest
        row_latest = store.get_tag_state(self.base_url,
                                         "team-a/app", "latest")
        row_v1 = store.get_tag_state(self.base_url, "team-a/app", "v1.0")
        self.assertEqual(row_latest["digest"], row_v1["digest"])
        self.assertEqual(row_latest["digest"], self.top_index_digest)

        # manifests 表中该 digest 只有一行（内容身份不重复建立）
        count = store.conn.execute(
            "SELECT COUNT(*) AS c FROM manifests WHERE digest = ?",
            (self.top_index_digest,)).fetchone()["c"]
        self.assertEqual(count, 1)

        # team-a/web 同样两个 tag 一个 digest
        count_web = store.conn.execute(
            "SELECT COUNT(*) AS c FROM manifests WHERE digest = ?",
            (self.web_digest,)).fetchone()["c"]
        self.assertEqual(count_web, 1)

        # digest 反查能找到全部引用 tag
        result = query_platform_references(store, self.web_digest)
        tag_names = {t["tag"] for t in result["referenced_by_tags"]}
        self.assertEqual(tag_names, {"stable", "v2"})

    def test_unknown_media_type_registered_but_not_expanded(self):
        collector = self.new_collector()
        collector.run()
        store = collector.store

        row = store.conn.execute(
            "SELECT * FROM manifests WHERE digest = ?",
            (self.bespoke_digest,)).fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row["kind"], ManifestKind.UNKNOWN.value)
        self.assertEqual(row["media_type"], UNKNOWN_MEDIA)
        # 未知结构不产生 layer/child 行
        layers = store.conn.execute(
            "SELECT COUNT(*) AS c FROM manifest_layers WHERE manifest_digest = ?",
            (self.bespoke_digest,)).fetchone()["c"]
        children = store.conn.execute(
            "SELECT COUNT(*) AS c FROM manifest_children WHERE parent_digest = ?",
            (self.bespoke_digest,)).fetchone()["c"]
        self.assertEqual(layers, 0)
        self.assertEqual(children, 0)

        # 仍可按 digest 查到引用
        result = query_platform_references(store, self.bespoke_digest)
        self.assertEqual(result["references"][0]["kind"],
                         ManifestKind.UNKNOWN.value)

    def test_docker_media_types_recognized(self):
        collector = self.new_collector()
        collector.run()
        row = collector.store.conn.execute(
            "SELECT kind FROM manifests WHERE digest = ?",
            (self.util_v1_digest,)).fetchone()
        self.assertEqual(row["kind"], ManifestKind.IMAGE.value)
