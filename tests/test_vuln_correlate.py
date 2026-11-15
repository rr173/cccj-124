"""关联引擎：逐出现项状态、等价组合并、撤回、qualifiers 与只读语义。"""

import json
import os
import sqlite3
import unittest

from vuln_fixtures import (
    VERSIONS_AVAILABLE,
    VulnFixture,
    advisory,
    cdx_component,
    cdx_doc,
    ev,
    npm_claim,
    pypi_claim,
)

from oci_catalog.vuln.advisory import load_advisory_dir
from oci_catalog.vuln.correlate import (
    AFFECTED,
    NOT_AFFECTED,
    UNCOVERED,
    UNKNOWN,
    NoSBOMError,
    UnknownAdvisoryId,
    build_report,
    query_advisory,
)


def occ_by_ref(report, file_ref):
    return next(o for o in report["occurrences"] if o["file_ref"] == file_ref)


@unittest.skipUnless(VERSIONS_AVAILABLE,
                     "需要 packaging 与 semantic_version 包")
class TestOccurrenceStatuses(VulnFixture):

    def _report(self, components, advisories, digest=None):
        self.import_sbom(cdx_doc(components), digest or self.image_amd64,
                         "test.cdx.json")
        aset = load_advisory_dir(self.write_advisories(advisories))
        return build_report(aset, self.sbom_db, self.catalog_db,
                            digest or self.image_amd64, self.advisory_dir)

    def test_hit_via_range(self):
        report = self._report(
            [cdx_component("R", "requests", "2.31.0",
                           "pkg:pypi/requests@2.31.0")],
            {"a.json": advisory("ADV-1", [pypi_claim(
                "requests", events=ev(("introduced", "2.31.0"),
                                      ("fixed", "2.32.3")))])})
        occ = occ_by_ref(report, "R")
        self.assertEqual(occ["status"], AFFECTED)
        self.assertEqual(occ["installed_version"], "2.31.0")
        self.assertEqual(occ["groups"][0]["verdict"], "hit")
        evidence = occ["groups"][0]["evidence"][0]
        self.assertEqual(evidence["advisory_id"], "ADV-1")
        self.assertEqual(evidence["affected_index"], 0)
        self.assertEqual(evidence["kind"], "range")
        self.assertEqual(evidence["range_index"], 0)

    def test_miss_is_not_affected_in_feed(self):
        report = self._report(
            [cdx_component("R", "requests", "2.32.3",
                           "pkg:pypi/requests@2.32.3")],
            {"a.json": advisory("ADV-1", [pypi_claim(
                "requests", events=ev(("introduced", "2.31.0"),
                                      ("fixed", "2.32.3")))])})
        self.assertEqual(occ_by_ref(report, "R")["status"], NOT_AFFECTED)

    def test_uncovered_when_no_valid_claims(self):
        report = self._report(
            [cdx_component("T", "toolkit", "7.7.7",
                           "pkg:npm/%40acme/toolkit@7.7.7")],
            {"a.json": advisory("ADV-1", [pypi_claim(
                "requests", events=ev(("introduced", "1.0"),
                                      ("fixed", "2.0")))])})
        self.assertEqual(occ_by_ref(report, "T")["status"], UNCOVERED)

    def test_missing_purl_is_unknown_not_safe(self):
        report = self._report(
            [cdx_component("BLOB", "internal-blob", "0.1")],
            {"a.json": advisory("ADV-1", [pypi_claim(
                "internal-blob", events=ev(("introduced", "0"),
                                           ("fixed", "9.9")))])})
        occ = occ_by_ref(report, "BLOB")
        self.assertEqual(occ["status"], UNKNOWN)
        self.assertEqual(occ["reasons"][0]["code"], "missing_purl")

    def test_generic_ecosystem_is_unknown_not_safe(self):
        report = self._report(
            [cdx_component("SSL", "openssl", "3.0.13",
                           "pkg:generic/openssl@3.0.13?distro=debian")],
            {"a.json": advisory("ADV-1", [pypi_claim(
                "openssl", events=ev(("introduced", "0"),
                                     ("fixed", "9.9")))])})
        occ = occ_by_ref(report, "SSL")
        self.assertEqual(occ["status"], UNKNOWN)
        self.assertEqual(occ["reasons"][0]["code"], "unsupported_ecosystem")

    def test_missing_version_is_unknown_not_safe(self):
        report = self._report(
            [cdx_component("L", "legacylib", "1.0", "pkg:pypi/legacylib")],
            {"a.json": advisory("ADV-1", [pypi_claim(
                "legacylib", events=ev(("introduced", "1.0"),
                                       ("fixed", "2.0")))])})
        occ = occ_by_ref(report, "L")
        self.assertEqual(occ["status"], UNKNOWN)
        self.assertEqual(occ["reasons"][0]["code"], "missing_version")

    def test_missing_version_without_claims_is_uncovered(self):
        report = self._report(
            [cdx_component("L", "legacylib", "1.0", "pkg:pypi/legacylib")],
            {"a.json": advisory("ADV-1", [pypi_claim(
                "other", events=ev(("introduced", "1.0"),
                                   ("fixed", "2.0")))])})
        self.assertEqual(occ_by_ref(report, "L")["status"], UNCOVERED)

    def test_unparseable_installed_version_is_unknown(self):
        report = self._report(
            [cdx_component("W", "weird", "x", "pkg:npm/weird@1.0")],
            {"a.json": advisory("ADV-1", [npm_claim(
                "weird", events=ev(("introduced", "1.0.0"),
                                   ("fixed", "2.0.0")))])})
        occ = occ_by_ref(report, "W")
        self.assertEqual(occ["status"], UNKNOWN)
        self.assertEqual(occ["reasons"][0]["code"], "unparseable_version")

    def test_unsupported_range_type_is_unknown(self):
        report = self._report(
            [cdx_component("M", "mystery", "3.0.0", "pkg:npm/mystery@3.0.0")],
            {"a.json": advisory("ADV-1", [npm_claim(
                "mystery", events=ev(("introduced", "deadbeef")),
                range_type="GIT")])})
        occ = occ_by_ref(report, "M")
        self.assertEqual(occ["status"], UNKNOWN)
        self.assertEqual(occ["groups"][0]["verdict"], "unknown")
        self.assertEqual(occ["groups"][0]["reasons"][0]["code"],
                         "unsupported_range_type")

    def test_empty_version_set_is_unknown(self):
        report = self._report(
            [cdx_component("E", "emptyset", "9.9", "pkg:pypi/emptyset@9.9")],
            {"a.json": advisory("ADV-1", [pypi_claim("emptyset",
                                                     versions=[])])})
        occ = occ_by_ref(report, "E")
        self.assertEqual(occ["status"], UNKNOWN)
        self.assertEqual(occ["groups"][0]["reasons"][0]["code"],
                         "no_version_set")

    def test_empty_versions_does_not_prove_safe_with_unsupported_range(self):
        claim = pypi_claim("mixed", versions=[],
                           events=ev(("introduced", "deadbeef")),
                           range_type="GIT")
        report = self._report(
            [cdx_component("M", "mixed", "3.0", "pkg:pypi/mixed@3.0")],
            {"a.json": advisory("ADV-1", [claim])})
        self.assertEqual(occ_by_ref(report, "M")["status"], UNKNOWN)

    def test_unknown_and_miss_combine_to_unknown(self):
        report = self._report(
            [cdx_component("M", "mixedpkg", "3.0", "pkg:pypi/mixedpkg@3.0")],
            {"a.json": advisory("ADV-1", [pypi_claim(
                "mixedpkg", events=ev(("introduced", "1.0"),
                                      ("fixed", "2.0")))]),
             "b.json": advisory("ADV-2", [pypi_claim(
                "mixedpkg", events=ev(("introduced", "cafe")),
                range_type="GIT")])})
        occ = occ_by_ref(report, "M")
        self.assertEqual(occ["status"], UNKNOWN)
        verdicts = {g["group_id"]: g["verdict"] for g in occ["groups"]}
        self.assertEqual(verdicts, {"ADV-1": "miss", "ADV-2": "unknown"})

    def test_hit_not_erased_by_unknown(self):
        report = self._report(
            [cdx_component("C", "certifi", "2024.2.2",
                           "pkg:pypi/certifi@2024.2.2")],
            {"a.json": advisory("ADV-1", [pypi_claim(
                "certifi", versions=["2024.2.2"])]),
             "b.json": advisory("ADV-2", [pypi_claim(
                "certifi", events=ev(("introduced", "cafe")),
                range_type="GIT")])})
        occ = occ_by_ref(report, "C")
        self.assertEqual(occ["status"], AFFECTED)

    def test_versions_exact_text_matching(self):
        # 文本不同但排序相等的版本不视作同一个列表项
        report = self._report(
            [cdx_component("G", "gadget", "1.4.0+build.7",
                           "pkg:npm/%40acme/gadget@1.4.0%2Bbuild.7")],
            {"a.json": advisory("ADV-1", [npm_claim(
                "@acme/gadget", versions=["1.4.0"],
                events=ev(("introduced", "1.3.0"), ("fixed", "1.4.0")))])})
        occ = occ_by_ref(report, "G")
        self.assertEqual(occ["status"], NOT_AFFECTED)
        self.assertEqual(occ["installed_version"], "1.4.0+build.7")

    def test_versions_list_hit_is_union_with_ranges(self):
        report = self._report(
            [cdx_component("C", "certifi", "2024.2.2",
                           "pkg:pypi/certifi@2024.2.2")],
            {"a.json": advisory("ADV-1", [pypi_claim(
                "certifi", versions=["2024.2.2"],
                events=ev(("introduced", "2030.1.1"),
                          ("last_affected", "2030.12.31")))])})
        occ = occ_by_ref(report, "C")
        self.assertEqual(occ["status"], AFFECTED)
        evidence = occ["groups"][0]["evidence"][0]
        self.assertEqual(evidence["kind"], "versions")
        self.assertEqual(evidence["versions_index"], 0)

    def test_qualifiers_carried_and_ignored_for_matching(self):
        report = self._report(
            [cdx_component("Q", "qualpkg", "3.1.0",
                           "pkg:pypi/qualpkg@3.1.0?repo=main&arch=%41MD64")],
            {"a.json": advisory("ADV-1", [pypi_claim(
                "qualpkg", events=ev(("introduced", "3.0.0"),
                                     ("fixed", "3.1.0")))])})
        occ = occ_by_ref(report, "Q")
        self.assertEqual(occ["status"], NOT_AFFECTED)
        # qualifiers 原样带回（canonical 与 raw 都保留）
        self.assertEqual(occ["canonical_purl"],
                         "pkg:pypi/qualpkg@3.1.0?arch=AMD64&repo=main")
        self.assertEqual(occ["purl_raw"],
                         "pkg:pypi/qualpkg@3.1.0?repo=main&arch=%41MD64")

    def test_pypi_name_normalization_matching(self):
        report = self._report(
            [cdx_component("F", "Flask_Core.Ext", "3.0.2",
                           "pkg:pypi/Flask_Core.Ext@3.0.2")],
            {"a.json": advisory("ADV-1", [pypi_claim(
                "flask-core-ext", events=ev(("introduced", "3.0"),
                                            ("fixed", "3.1")))])})
        self.assertEqual(occ_by_ref(report, "F")["status"], AFFECTED)

    def test_npm_scope_matching(self):
        report = self._report(
            [cdx_component("W", "@acme/widget", "2.0.0-rc.2",
                           "pkg:npm/%40acme/widget@2.0.0-rc.2")],
            {"a.json": advisory("ADV-1", [npm_claim(
                "@acme/widget", events=ev(("introduced", "2.0.0-rc.1"),
                                          ("fixed", "2.0.0-rc.10")))])})
        self.assertEqual(occ_by_ref(report, "W")["status"], AFFECTED)

    def test_npm_scope_case_difference_does_not_match(self):
        # 包名本体大小写不同是不同包，不匹配
        report = self._report(
            [cdx_component("W", "Widget", "1.0.0", "pkg:npm/Widget@1.0.0")],
            {"a.json": advisory("ADV-1", [npm_claim(
                "widget", events=ev(("introduced", "1.0.0"),
                                    ("fixed", "2.0.0")))])})
        self.assertEqual(occ_by_ref(report, "W")["status"], UNCOVERED)


@unittest.skipUnless(VERSIONS_AVAILABLE,
                     "需要 packaging 与 semantic_version 包")
class TestGroupsAndWithdrawn(VulnFixture):

    def test_alias_group_reported_as_single_vulnerability(self):
        self.import_sbom(cdx_doc([
            cdx_component("C", "certifi", "2024.2.2",
                          "pkg:pypi/certifi@2024.2.2")]),
            self.image_amd64, "test.cdx.json")
        aset = load_advisory_dir(self.write_advisories({
            "a.json": advisory("VULN-AAAA", [pypi_claim(
                "certifi", versions=["2024.2.2"])], aliases=["VULN-BBBB"]),
            "b.json": advisory("VULN-BBBB", [pypi_claim(
                "certifi", versions=["2024.2.2"])], aliases=["VULN-AAAA"]),
        }))
        report = build_report(aset, self.sbom_db, self.catalog_db,
                              self.image_amd64, self.advisory_dir)
        occ = occ_by_ref(report, "C")
        # 同一漏洞多个编号：只报一个组，不是几个不同漏洞
        self.assertEqual(len(occ["groups"]), 1)
        self.assertEqual(occ["groups"][0]["group_id"], "VULN-AAAA")
        self.assertEqual(occ["groups"][0]["member_ids"],
                         ["VULN-AAAA", "VULN-BBBB"])

    def test_same_group_different_packages_do_not_cross_ranges(self):
        self.import_sbom(cdx_doc([
            cdx_component("A", "alphalib", "1.5", "pkg:pypi/alphalib@1.5"),
            cdx_component("B", "betalib", "1.5", "pkg:pypi/betalib@1.5")]),
            self.image_arm64, "edge.cdx.json")
        aset = load_advisory_dir(self.write_advisories({
            "a.json": advisory("PACK-AAAA", [pypi_claim(
                "alphalib", events=ev(("introduced", "1.0"),
                                      ("fixed", "2.0")))]),
            "b.json": advisory("PACK-BBBB", [pypi_claim(
                "betalib", events=ev(("introduced", "3.0"),
                                     ("fixed", "4.0")))],
                aliases=["PACK-AAAA"]),
        }))
        report = build_report(aset, self.sbom_db, self.catalog_db,
                              self.image_arm64, self.advisory_dir)
        self.assertEqual(occ_by_ref(report, "A")["status"], AFFECTED)
        # betalib 1.5 不在 PACK-BBBB 的 [3.0,4.0) 内；PACK-AAAA 的 alphalib
        # 范围不能套到 betalib 上
        self.assertEqual(occ_by_ref(report, "B")["status"], NOT_AFFECTED)

    def test_withdrawn_contributes_no_ranges(self):
        self.import_sbom(cdx_doc([
            cdx_component("G", "ghostpkg", "5.0", "pkg:pypi/ghostpkg@5.0")]),
            self.image_arm64, "edge.cdx.json")
        aset = load_advisory_dir(self.write_advisories({
            "w.json": advisory("GHOST-0001", [pypi_claim(
                "ghostpkg", events=ev(("introduced", "1.0"),
                                      ("fixed", "9.9")))],
                aliases=["CVE-GHOST-0001"], withdrawn="2024-01-15"),
        }))
        report = build_report(aset, self.sbom_db, self.catalog_db,
                              self.image_arm64, self.advisory_dir)
        # 撤回公告的声明不参加命中：没有有效公告 -> uncovered
        self.assertEqual(occ_by_ref(report, "G")["status"], UNCOVERED)
        # 等价组仍保留（编号解释），撤回不传染
        group = report["advisory_groups"][0]
        self.assertEqual(group["group_id"], "CVE-GHOST-0001")
        self.assertEqual(group["withdrawn_ids"], ["GHOST-0001"])

    def test_related_stays_separate_group(self):
        self.import_sbom(cdx_doc([
            cdx_component("C", "certifi", "2024.2.2",
                          "pkg:pypi/certifi@2024.2.2")]),
            self.image_amd64, "test.cdx.json")
        aset = load_advisory_dir(self.write_advisories({
            "a.json": advisory("VULN-AAAA", [pypi_claim(
                "certifi", versions=["2024.2.2"])]),
            "d.json": advisory("VULN-DDDD", [pypi_claim(
                "certifi", events=ev(("introduced", "2024.0.0"),
                                     ("fixed", "2024.1.1")))],
                related=["VULN-AAAA"]),
        }))
        report = build_report(aset, self.sbom_db, self.catalog_db,
                              self.image_amd64, self.advisory_dir)
        occ = occ_by_ref(report, "C")
        groups = {g["group_id"]: g["verdict"] for g in occ["groups"]}
        self.assertEqual(groups, {"VULN-AAAA": "hit", "VULN-DDDD": "miss"})


@unittest.skipUnless(VERSIONS_AVAILABLE,
                     "需要 packaging 与 semantic_version 包")
class TestReportShape(VulnFixture):

    def test_occurrences_keep_per_file_records(self):
        # 同一坐标在两份清单中出现：两条出现记录，不合并成一条库存
        doc = cdx_doc([cdx_component("R", "requests", "2.31.0",
                                     "pkg:pypi/requests@2.31.0")])
        self.import_sbom(doc, self.image_amd64, "one.cdx.json")
        doc2 = cdx_doc([cdx_component("R2", "requests", "2.31.0",
                                      "pkg:pypi/requests@2.31.0")],
                       serial="urn:uuid:two")
        self.import_sbom(doc2, self.image_amd64, "two.cdx.json")
        aset = load_advisory_dir(self.write_advisories({
            "a.json": advisory("ADV-1", [pypi_claim(
                "requests", events=ev(("introduced", "2.31.0"),
                                      ("fixed", "2.32.3")))])}))
        report = build_report(aset, self.sbom_db, self.catalog_db,
                              self.image_amd64, self.advisory_dir)
        self.assertEqual(len(report["occurrences"]), 2)
        refs = sorted(o["file_ref"] for o in report["occurrences"])
        self.assertEqual(refs, ["R", "R2"])
        sources = {o["source_path"] for o in report["occurrences"]}
        self.assertEqual(len(sources), 2)
        for occ in report["occurrences"]:
            self.assertEqual(occ["status"], AFFECTED)

    def test_report_carries_context_and_limitations(self):
        self.import_sbom(cdx_doc([cdx_component(
            "R", "requests", "2.31.0", "pkg:pypi/requests@2.31.0")]),
            self.image_amd64, "test.cdx.json")
        aset = load_advisory_dir(self.write_advisories({
            "a.json": advisory("ADV-1", [pypi_claim(
                "requests", events=ev(("introduced", "2.31.0"),
                                      ("fixed", "2.32.3")))])}))
        report = build_report(aset, self.sbom_db, self.catalog_db,
                              self.image_amd64, self.advisory_dir)
        self.assertEqual(report["image_digest"], self.image_amd64)
        self.assertEqual(report["platform"]["architecture"], "amd64")
        self.assertTrue(report["sbom_present"])
        self.assertEqual(report["summary"]["affected"], 1)
        self.assertTrue(any("不代表" in line or "没有漏洞" in line
                            for line in report["limitations"]))

    def test_no_sbom_image_raises(self):
        aset = load_advisory_dir(self.advisory_dir)
        with self.assertRaises(NoSBOMError):
            build_report(aset, self.sbom_db, self.catalog_db,
                         self.image_quiet, self.advisory_dir)

    def test_bad_digest_rejected(self):
        aset = load_advisory_dir(self.advisory_dir)
        with self.assertRaises(ValueError):
            build_report(aset, self.sbom_db, self.catalog_db,
                         "not-a-digest", self.advisory_dir)

    def test_inputs_are_readonly(self):
        self.import_sbom(cdx_doc([cdx_component(
            "R", "requests", "2.31.0", "pkg:pypi/requests@2.31.0")]),
            self.image_amd64, "test.cdx.json")
        aset = load_advisory_dir(self.write_advisories({
            "a.json": advisory("ADV-1", [pypi_claim(
                "requests", events=ev(("introduced", "2.31.0"),
                                      ("fixed", "2.32.3")))])}))
        before_sbom = _db_tables(self.sbom_db)
        before_catalog = _db_tables(self.catalog_db)
        build_report(aset, self.sbom_db, self.catalog_db,
                     self.image_amd64, self.advisory_dir)
        self.assertEqual(before_sbom, _db_tables(self.sbom_db))
        self.assertEqual(before_catalog, _db_tables(self.catalog_db))

    def test_report_deterministic_under_file_order(self):
        docs = {
            "z.json": advisory("Z-1", [pypi_claim(
                "requests", events=ev(("introduced", "2.31.0"),
                                      ("fixed", "2.32.3")))], aliases=["A-1"]),
            "a.json": advisory("A-1", [pypi_claim(
                "certifi", versions=["2024.2.2"])]),
        }
        self.import_sbom(cdx_doc([
            cdx_component("R", "requests", "2.31.0",
                          "pkg:pypi/requests@2.31.0"),
            cdx_component("C", "certifi", "2024.2.2",
                          "pkg:pypi/certifi@2024.2.2")]),
            self.image_amd64, "test.cdx.json")
        first = build_report(
            load_advisory_dir(self.write_advisories(docs, subdir="d1")),
            self.sbom_db, self.catalog_db, self.image_amd64, "d1")
        second = build_report(
            load_advisory_dir(self.write_advisories(
                dict(reversed(list(docs.items()))), subdir="d2")),
            self.sbom_db, self.catalog_db, self.image_amd64, "d2")
        # 除输入路径外，报告完全一致
        first["inputs"] = second["inputs"] = None
        self.assertEqual(json.dumps(first, sort_keys=True),
                         json.dumps(second, sort_keys=True))


def _db_tables(path):
    conn = sqlite3.connect(path)
    try:
        rows = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "ORDER BY name").fetchall()
        counts = {}
        for (name,) in rows:
            if name.startswith("sqlite_"):
                continue
            counts[name] = conn.execute(
                f"SELECT COUNT(*) FROM '{name}'").fetchone()[0]
        return counts
    finally:
        conn.close()


@unittest.skipUnless(VERSIONS_AVAILABLE,
                     "需要 packaging 与 semantic_version 包")
class TestAdvisoryQuery(VulnFixture):

    def _setup(self):
        self.import_sbom(cdx_doc([
            cdx_component("C", "certifi", "2024.2.2",
                          "pkg:pypi/certifi@2024.2.2"),
            cdx_component("G", "ghostpkg", "5.0", "pkg:pypi/ghostpkg@5.0")]),
            self.image_amd64, "test.cdx.json")
        return load_advisory_dir(self.write_advisories({
            "a.json": advisory("VULN-AAAA", [pypi_claim(
                "certifi", versions=["2024.2.2"])],
                aliases=["VULN-BBBB", "GHSA-NO-FILE"]),
            "b.json": advisory("VULN-BBBB", [pypi_claim(
                "certifi", versions=["2024.2.2"])], aliases=["VULN-AAAA"]),
            "w.json": advisory("GHOST-0001", [pypi_claim(
                "ghostpkg", events=ev(("introduced", "1.0"),
                                      ("fixed", "9.9")))],
                withdrawn="2024-01-15"),
        }))

    def test_query_by_alias_finds_group_hits(self):
        aset = self._setup()
        # 用组内任一编号（含无独立文件的别名）都能查；
        # 展示名是组内字典序最小编号（GHSA-NO-FILE < VULN-AAAA）
        for query_id in ("VULN-AAAA", "VULN-BBBB", "GHSA-NO-FILE"):
            result = query_advisory(aset, self.sbom_db, self.catalog_db,
                                    self.image_amd64, query_id)
            self.assertEqual(result["group"]["group_id"], "GHSA-NO-FILE")
            self.assertEqual(len(result["hits"]), 1)
            hit = result["hits"][0]
            self.assertEqual(hit["file_ref"], "C")
            self.assertEqual(hit["installed_version"], "2024.2.2")
            self.assertEqual(hit["image_digest"], self.image_amd64)
            self.assertTrue(hit["location"].startswith("$."))

    def test_query_withdrawn_group_has_no_hits_but_explained(self):
        aset = self._setup()
        result = query_advisory(aset, self.sbom_db, self.catalog_db,
                                self.image_amd64, "GHOST-0001")
        self.assertEqual(result["hits"], [])
        self.assertTrue(any("撤回" in note for note in result["notes"]))

    def test_query_unknown_id_raises(self):
        aset = self._setup()
        with self.assertRaises(UnknownAdvisoryId):
            query_advisory(aset, self.sbom_db, self.catalog_db,
                           self.image_amd64, "NOPE-1")


if __name__ == "__main__":
    unittest.main()
