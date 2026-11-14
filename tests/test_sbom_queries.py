"""依赖血缘查询：菱形/环路径稳定性、跨文件隔离、跨镜像反查。"""

import unittest

from sbom_fixtures import SBOMFixture
from oci_catalog.sbom.sbom_queries import (
    query_component_images,
    query_image_components,
    shortest_paths,
)


def cdx(components, dependencies):
    return {"bomFormat": "CycloneDX", "specVersion": "1.5",
            "components": components, "dependencies": dependencies}


def lib(ref, name, purl=None):
    item = {"bom-ref": ref, "name": name, "version": "1"}
    if purl:
        item["purl"] = purl
    return item


class TestPathAlgorithm(unittest.TestCase):

    def setUp(self):
        # 菱形：R -> {A, B} -> T；环：C <-> D，且 R -> C
        self.graph = {
            "R": {"A", "B", "C"},
            "A": {"T"},
            "B": {"T"},
            "T": set(),
            "C": {"D"},
            "D": {"C"},
        }

    def test_diamond_returns_all_shortest_paths_sorted(self):
        paths, truncated, anchored = shortest_paths(self.graph, "T")
        self.assertFalse(truncated)
        self.assertFalse(anchored)
        self.assertEqual(paths, [["R", "A", "T"], ["R", "B", "T"]])

    def test_cycle_terminates_and_keeps_shortest(self):
        paths, _, anchored = shortest_paths(self.graph, "D")
        self.assertFalse(anchored)
        self.assertEqual(paths, [["R", "C", "D"]])  # 环不产生更长的重复路径

    def test_isolated_cycle_uses_anchor(self):
        graph = {"X": {"Y"}, "Y": {"X"}}
        paths, _, anchored = shortest_paths(graph, "Y")
        self.assertTrue(anchored)
        self.assertEqual(paths, [["X", "Y"]])

    def test_unknown_target_empty(self):
        paths, _, anchored = shortest_paths(self.graph, "NOPE")
        self.assertEqual(paths, [])
        self.assertFalse(anchored)

    def test_max_paths_truncation(self):
        # 构造 4 条同长路径，上限 2
        graph = {"R": {"A1", "A2", "A3", "A4"}}
        for a in ("A1", "A2", "A3", "A4"):
            graph[a] = {"T"}
        graph["T"] = set()
        paths, truncated, _ = shortest_paths(graph, "T", max_paths=2)
        self.assertTrue(truncated)
        self.assertEqual(len(paths), 2)
        self.assertEqual(paths, [["R", "A1", "T"], ["R", "A2", "T"]])


class TestQueryImageComponents(SBOMFixture):

    def test_export_groups_per_source_with_direct_deps(self):
        doc1 = cdx(
            [lib("R", "root", "pkg:generic/root@1"),
             lib("L", "leaf", "pkg:generic/leaf@1")],
            [{"ref": "R", "dependsOn": ["L"]}])
        doc2 = cdx([lib("S", "solo", "pkg:generic/solo@1")], [])
        self.import_dict("a.json", doc1, self.image_amd64)
        self.import_dict("b.json", doc2, self.image_amd64)

        report = query_image_components(self.store, self.image_amd64)
        self.assertEqual(report["platform"]["architecture"], "amd64")
        self.assertEqual(len(report["files"]), 2)
        first = report["files"][0]
        root_occ = next(o for o in first["occurrences"]
                        if o["file_ref"] == "R")
        self.assertEqual([d["ref"] for d in root_occ["direct_dependencies"]],
                         ["L"])
        # 源文件与位置随结果返回
        self.assertTrue(first["source_path"].endswith("a.json"))
        self.assertEqual(root_occ["location"], "$.components[0]")

    def test_unknown_image_raises(self):
        with self.assertRaises(KeyError):
            query_image_components(self.store, "sha256:" + "ab" * 32)


class TestQueryComponentReverse(SBOMFixture):

    def test_reverse_lookup_across_images_and_sources(self):
        # amd64 两份清单都含 leaf（同 purl），arm64 一份含不同版本
        amd_doc = cdx(
            [lib("R", "root", "pkg:generic/root@1"),
             lib("L", "leaf", "pkg:generic/leaf@1.0")],
            [{"ref": "R", "dependsOn": ["L"]}])
        amd_doc2 = cdx(
            [lib("TOP", "top", "pkg:generic/top@1"),
             # 故意复用另一份文件里的 bom-ref "L"
             lib("L", "leaf-again", "pkg:generic/leaf@1.0")],
            [{"ref": "TOP", "dependsOn": ["L"]}])
        arm_doc = cdx(
            [lib("G", "gw", "pkg:generic/gw@1"),
             lib("L", "leaf-new", "pkg:generic/leaf@2.0")],
            [{"ref": "G", "dependsOn": ["L"]}])
        self.import_dict("amd1.json", amd_doc, self.image_amd64)
        self.import_dict("amd2.json", amd_doc2, self.image_amd64)
        self.import_dict("arm.json", arm_doc, self.image_arm64)

        result = query_component_images(self.store, "pkg:generic/leaf@1.0")
        digests = {img["image_digest"] for img in result["images"]}
        self.assertEqual(digests, {self.image_amd64})
        sources = result["images"][0]["sources"]
        self.assertEqual(len(sources), 2)  # 两份来源分别给路径
        for src in sources:
            self.assertEqual(len(src["matches"]), 1)
            # 路径只引用本文件内的 ref
            file_refs = {o["file_ref"] for f in
                         query_image_components(self.store,
                                                self.image_amd64)["files"]
                         if f["file_id"] == src["file_id"]
                         for o in f["occurrences"]}
            for match in src["matches"]:
                self.assertEqual(len(match["paths"]), 1)
                for path in match["paths"]:
                    self.assertTrue(all(ref in file_refs for ref in path))

        # 不同版本是不同坐标，只命中 arm64
        v2 = query_component_images(self.store, "pkg:generic/leaf@2.0")
        self.assertEqual({img["image_digest"] for img in v2["images"]},
                         {self.image_arm64})

    def test_reverse_lookup_accepts_equivalent_purl_spelling(self):
        doc = cdx([lib("R", "r", "pkg:pypi/urllib3@1?arch=A&repo=b")], [])
        self.import_dict("e.json", doc, self.image_amd64)
        result = query_component_images(
            self.store, "pkg:pypi/urllib3@1?repo=b&arch=A")
        self.assertEqual(
            result["canonical_purl"],
            "pkg:pypi/urllib3@1?arch=A&repo=b")

    def test_unknown_coordinate_raises(self):
        with self.assertRaises(KeyError):
            query_component_images(self.store, "pkg:generic/nonexistent@9")
        with self.assertRaises(ValueError):
            query_component_images(self.store, "not-a-purl")

    def test_graph_is_scoped_per_file(self):
        # 两份文件复用 bom-ref "L"，边不能跨文件拼接
        doc1 = cdx([lib("R1", "r1", "pkg:generic/r1@1"),
                    lib("L", "l1", "pkg:generic/l@1")],
                   [{"ref": "R1", "dependsOn": ["L"]}])
        doc2 = cdx([lib("R2", "r2", "pkg:generic/r2@1"),
                    lib("L", "l2", "pkg:generic/l@1")],
                   [{"ref": "R2", "dependsOn": ["L"]}])
        self.import_dict("f1.json", doc1, self.image_amd64)
        self.import_dict("f2.json", doc2, self.image_amd64)
        result = query_component_images(self.store, "pkg:generic/l@1")
        sources = result["images"][0]["sources"]
        roots = {match["paths"][0][0] for src in sources
                 for match in src["matches"]}
        self.assertEqual(roots, {"R1", "R2"})  # 各自文件的根，无 R1->...->R2

    def test_multiple_occurrences_in_one_file_consolidated(self):
        # 同一文件内两个 bom-ref 指向同一 purl：反查合并为一个 source、
        # 两个 match，各自的文件内身份与路径分别保留
        doc = cdx(
            [lib("R", "root", "pkg:generic/root@1"),
             lib("L1", "leaf-one", "pkg:generic/leaf@1"),
             lib("L2", "leaf-two", "pkg:generic/leaf@1")],
            [{"ref": "R", "dependsOn": ["L1", "L2"]}])
        self.import_dict("multi.json", doc, self.image_amd64)
        result = query_component_images(self.store, "pkg:generic/leaf@1")
        sources = result["images"][0]["sources"]
        self.assertEqual(len(sources), 1)
        match_refs = {m["file_ref"] for m in sources[0]["matches"]}
        self.assertEqual(match_refs, {"L1", "L2"})

    def test_failed_files_excluded_from_queries(self):
        good = cdx([lib("OK", "ok", "pkg:generic/ok@1")], [])
        bad = cdx([lib("OK", "ok", "pkg:generic/ok@1")],
                  [{"ref": "OK", "dependsOn": ["MISSING"]}])
        self.import_dict("good.json", good, self.image_amd64)
        bad_result = self.import_dict("bad.json", bad, self.image_amd64)
        self.assertFalse(bad_result.ok)
        report = query_image_components(self.store, self.image_amd64)
        self.assertEqual(len(report["files"]), 1)  # 坏文件不可查询


class TestNewProcessPersistence(SBOMFixture):
    """关闭并重新打开 SBOM 库（模拟新进程），数据仍可查询。"""

    def test_reopen_in_new_connection(self):
        doc = cdx([lib("R", "r", "pkg:generic/r@1"),
                   lib("L", "l", "pkg:generic/l@1")],
                  [{"ref": "R", "dependsOn": ["L"]}])
        self.import_dict("p.json", doc, self.image_amd64)
        self.store.close()

        from oci_catalog.sbom import SBOMStore
        reopened = SBOMStore(self.sbom_db, self.catalog_db)
        try:
            report = query_image_components(reopened, self.image_amd64)
            self.assertEqual(len(report["files"]), 1)
            reverse = query_component_images(reopened, "pkg:generic/l@1")
            self.assertEqual(
                reverse["images"][0]["sources"][0]["matches"][0]["paths"],
                [["R", "L"]])
        finally:
            reopened.close()
        # 防止 tearDown 重复 close 报错：替换为已关闭句柄无操作
        self.store = reopened
