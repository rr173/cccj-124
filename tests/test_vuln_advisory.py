"""公告目录加载：结构校验、编号等价组、撤回与遍历顺序无关性。"""

import unittest

from vuln_fixtures import (
    VERSIONS_AVAILABLE,
    VulnFixture,
    advisory,
    ev,
    npm_claim,
    pypi_claim,
)

from oci_catalog.vuln.advisory import (
    DUPLICATE_ADVISORY_ID,
    DUPLICATE_JSON_KEY,
    EMPTY_VALUE,
    INVALID_FIELD_TYPE,
    INVALID_JSON,
    MISSING_FIELD,
    NOT_AN_OBJECT,
    AdvisoryError,
    load_advisory_dir,
)
from oci_catalog.vuln.versions import RANGE_OVERLAP, RANGE_REGRESSED


class TestAdvisoryStructure(VulnFixture):

    def _load_codes(self, mapping):
        path = self.write_advisories(mapping)
        with self.assertRaises(AdvisoryError) as ctx:
            load_advisory_dir(path)
        return [d.code for d in ctx.exception.diagnostics], ctx.exception

    def test_duplicate_json_key_located(self):
        codes, exc = self._load_codes({
            "bad.json": '{\n "id": "A",\n "id": "B",\n "affected": []\n}'})
        self.assertIn(DUPLICATE_JSON_KEY, codes)
        locations = [d.location for d in exc.diagnostics]
        self.assertTrue(any("bad.json:$" in loc for loc in locations))

    def test_invalid_json_located(self):
        codes, _ = self._load_codes({"bad.json": "{not json"})
        self.assertIn(INVALID_JSON, codes)

    def test_top_level_not_object(self):
        codes, _ = self._load_codes({"bad.json": '["not", "object"]'})
        self.assertIn(NOT_AN_OBJECT, codes)

    def test_missing_id(self):
        codes, _ = self._load_codes({"bad.json": {"affected": []}})
        self.assertIn(MISSING_FIELD, codes)

    def test_empty_id(self):
        codes, _ = self._load_codes({"bad.json": {"id": ""}})
        self.assertIn(EMPTY_VALUE, codes)

    def test_duplicate_id_across_files(self):
        codes, exc = self._load_codes({
            "a.json": advisory("SAME-ID", []),
            "b.json": advisory("SAME-ID", []),
        })
        self.assertIn(DUPLICATE_ADVISORY_ID, codes)
        locations = [d.location for d in exc.diagnostics]
        self.assertTrue(any("b.json:$.id" in loc for loc in locations))
        # 诊断同时指出首个文件名
        message = [d.message for d in exc.diagnostics
                   if d.code == DUPLICATE_ADVISORY_ID][0]
        self.assertIn("a.json", message)

    def test_aliases_must_be_string_list(self):
        codes, _ = self._load_codes({
            "bad.json": advisory("A", [], aliases="CVE-1")})
        self.assertIn(INVALID_FIELD_TYPE, codes)

    def test_affected_missing_package_name(self):
        codes, exc = self._load_codes({
            "bad.json": advisory("A", [{
                "package": {"ecosystem": "PyPI"}, "versions": ["1.0"]}])})
        self.assertIn(MISSING_FIELD, codes)
        locations = [d.location for d in exc.diagnostics]
        self.assertTrue(any("$.affected[0].package.name" in loc
                            for loc in locations))

    def test_versions_must_be_string_list(self):
        codes, _ = self._load_codes({
            "bad.json": advisory("A", [pypi_claim("x", versions="1.0")])})
        self.assertIn(INVALID_FIELD_TYPE, codes)

    def test_range_missing_events(self):
        claim = {"package": {"ecosystem": "PyPI", "name": "x"},
                 "ranges": [{"type": "ECOSYSTEM"}]}
        codes, exc = self._load_codes({"bad.json": advisory("A", [claim])})
        self.assertIn(MISSING_FIELD, codes)
        locations = [d.location for d in exc.diagnostics]
        self.assertTrue(any("ranges[0].events" in loc for loc in locations))

    @unittest.skipUnless(VERSIONS_AVAILABLE,
                         "需要 packaging 与 semantic_version 包")
    def test_supported_range_event_errors_fail_job(self):
        # 已支持区间的事件错误：整次作业失败并定位字段
        codes, exc = self._load_codes({
            "bad.json": advisory("A", [pypi_claim(
                "requests", events=ev(("introduced", "2.0.0"),
                                      ("fixed", "1.0.0")))])})
        self.assertIn(RANGE_REGRESSED, codes)
        locations = [d.location for d in exc.diagnostics]
        self.assertTrue(any("$.affected[0].ranges[0].events[1]" in loc
                            for loc in locations))

    @unittest.skipUnless(VERSIONS_AVAILABLE,
                         "需要 packaging 与 semantic_version 包")
    def test_overlap_events_fail_job(self):
        codes, _ = self._load_codes({
            "bad.json": advisory("A", [pypi_claim(
                "requests", events=ev(("introduced", "1.0.0"),
                                      ("fixed", "2.0.0"),
                                      ("introduced", "1.5.0"),
                                      ("fixed", "3.0.0")))])})
        self.assertIn(RANGE_OVERLAP, codes)

    def test_unsupported_range_events_not_validated(self):
        # GIT 区间的事件不是版本号也不校验：保留为无法判断而非作业失败
        path = self.write_advisories({
            "git.json": advisory("A", [pypi_claim(
                "x", events=ev(("introduced", "deadbeef")),
                range_type="GIT")])})
        aset = load_advisory_dir(path)
        claim = aset.advisories[0].affected[0]
        self.assertFalse(claim.ranges[0].supported)

    def test_unknown_ecosystem_events_not_validated(self):
        # 其他生态保留为无法判断，其区间事件不进入校验
        claim = {"package": {"ecosystem": "Maven", "name": "g:a"},
                 "ranges": [{"type": "ECOSYSTEM",
                             "events": [{"introduced": "not-a-version"}]}]}
        path = self.write_advisories({"mvn.json": advisory("A", [claim])})
        aset = load_advisory_dir(path)
        self.assertEqual(len(aset.advisories), 1)

    def test_extra_informative_fields_ignored(self):
        doc = advisory("A", [pypi_claim("x", versions=["1.0"])],
                       summary="s", details="d", severity=[{"type": "CVSS"}],
                       published="2024-01-01", database_specific={"z": 1})
        path = self.write_advisories({"a.json": doc})
        aset = load_advisory_dir(path)
        self.assertEqual(len(aset.advisories), 1)

    def test_missing_directory_fails(self):
        with self.assertRaises(AdvisoryError):
            load_advisory_dir(self.tmpdir + "/no-such-dir")

    def test_empty_directory_is_empty_feed(self):
        aset = load_advisory_dir(self.advisory_dir)
        self.assertEqual(aset.advisories, [])
        self.assertEqual(aset.groups, [])


class TestAdvisoryGroups(VulnFixture):

    def test_alias_transitive_cycle_merges(self):
        path = self.write_advisories({
            "a.json": advisory("VULN-A", [], aliases=["VULN-B"]),
            "b.json": advisory("VULN-B", [], aliases=["VULN-C"]),
            "c.json": advisory("VULN-C", [], aliases=["VULN-A"]),
        })
        aset = load_advisory_dir(path)
        self.assertEqual(len(aset.groups), 1)
        group = aset.groups[0]
        self.assertEqual(group.display_id, "VULN-A")
        self.assertEqual(group.member_ids, ("VULN-A", "VULN-B", "VULN-C"))

    def test_alias_without_file_joins_group(self):
        path = self.write_advisories({
            "a.json": advisory("VULN-A", [], aliases=["GHSA-NO-FILE"])})
        aset = load_advisory_dir(path)
        self.assertEqual(len(aset.groups), 1)
        self.assertIn("GHSA-NO-FILE", aset.groups[0].member_ids)
        # 用无文件的别名也能查到组
        self.assertIs(aset.group_for("GHSA-NO-FILE"), aset.groups[0])

    def test_related_does_not_merge(self):
        path = self.write_advisories({
            "a.json": advisory("VULN-A", [], related=["VULN-B"]),
            "b.json": advisory("VULN-B", []),
        })
        aset = load_advisory_dir(path)
        self.assertEqual(len(aset.groups), 2)
        group_a = aset.group_for("VULN-A")
        self.assertEqual(group_a.related_ids, ("VULN-B",))
        self.assertIsNone(aset.group_for("VULN-B") is group_a or None)
        self.assertIsNot(aset.group_for("VULN-B"), group_a)

    def test_display_id_is_lexicographic_minimum(self):
        path = self.write_advisories({
            "z.json": advisory("ZZZ-9", [], aliases=["AAA-1", "MMM-5"])})
        aset = load_advisory_dir(path)
        self.assertEqual(aset.groups[0].display_id, "AAA-1")

    def test_withdrawn_kept_out_of_valid_but_aliases_still_merge(self):
        path = self.write_advisories({
            "w.json": advisory("W-1", [pypi_claim("x", versions=["1.0"])],
                               aliases=["V-1"], withdrawn="2024-01-01"),
            "v.json": advisory("V-1", [pypi_claim("y", versions=["2.0"])]),
        })
        aset = load_advisory_dir(path)
        self.assertEqual(len(aset.groups), 1)
        group = aset.groups[0]
        self.assertEqual(group.withdrawn_ids, ("W-1",))
        self.assertEqual([a.id for a in group.advisories], ["V-1"])
        # 撤回不传染：V-1 仍有效
        self.assertEqual(len(aset.valid_advisories), 1)

    def test_group_order_independent_of_file_order(self):
        docs = {
            "z.json": advisory("Z-1", [], aliases=["A-1"]),
            "m.json": advisory("M-1", []),
            "a.json": advisory("A-1", []),
        }
        first = load_advisory_dir(self.write_advisories(docs, subdir="d1"))
        # 同样的内容换目录重建（文件名相同但写入顺序不同）
        reordered = dict(reversed(list(docs.items())))
        second = load_advisory_dir(
            self.write_advisories(reordered, subdir="d2"))
        self.assertEqual([g.display_id for g in first.groups],
                         [g.display_id for g in second.groups])
        self.assertEqual([g.member_ids for g in first.groups],
                         [g.member_ids for g in second.groups])


if __name__ == "__main__":
    unittest.main()
