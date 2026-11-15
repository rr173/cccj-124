"""版本引擎：PEP 440 / 严格 SemVer 解析与 OSV 区间校验、求值。"""

import unittest

from vuln_fixtures import VERSIONS_AVAILABLE

from oci_catalog.vuln.versions import (
    ENDPOINT_UNPARSEABLE,
    EVENT_ITEM_STRUCTURE,
    EVENTS_EMPTY,
    EVENTS_MUST_START_WITH_INTRODUCED,
    EVENTS_NOT_ALTERNATING,
    RANGE_OVERLAP,
    RANGE_REGRESSED,
    ZERO_NOT_ALLOWED_HERE,
    VersionParseError,
    parse_ecosystem_version,
    validate_range_events,
)


@unittest.skipUnless(VERSIONS_AVAILABLE,
                     "需要 packaging 与 semantic_version 包")
class TestVersionParsing(unittest.TestCase):

    def test_pypi_pep440_ordering(self):
        # dev < rc < 正式版 < post，由 packaging 库保证
        versions = [parse_ecosystem_version("PyPI", v) for v in
                    ("1.0.dev1", "1.0rc1", "1.0", "1.0.post1")]
        self.assertEqual(versions, sorted(versions))
        self.assertLess(versions[0], versions[1])
        self.assertLess(versions[2], versions[3])

    def test_pypi_unparseable_rejected(self):
        with self.assertRaises(VersionParseError):
            parse_ecosystem_version("PyPI", "not a version!!")

    def test_npm_strict_semver_no_segment_filling(self):
        # 缺段写法直接拒绝，不补写版本段
        for bad in ("1.0", "1", "0", "v1.2.3", "1.2.3.4"):
            with self.assertRaises(VersionParseError, msg=bad):
                parse_ecosystem_version("npm", bad)

    def test_npm_prerelease_numeric_before_alpha(self):
        two = parse_ecosystem_version("npm", "2.0.0-rc.2")
        ten = parse_ecosystem_version("npm", "2.0.0-rc.10")
        alpha = parse_ecosystem_version("npm", "2.0.0-rc.alpha")
        release = parse_ecosystem_version("npm", "2.0.0")
        self.assertLess(two, ten)          # 数字段按数字比较
        self.assertLess(ten, alpha)        # 数字段低于非数字段
        self.assertLess(alpha, release)    # 正式版高于对应预发行

    def test_npm_build_metadata_ignored_in_precedence(self):
        build7 = parse_ecosystem_version("npm", "1.4.0+build.7")
        plain = parse_ecosystem_version("npm", "1.4.0")
        self.assertFalse(build7 < plain)
        self.assertFalse(plain < build7)
        self.assertTrue(build7 <= plain and plain <= build7)

    def test_no_float_conversion(self):
        # 1.10 与 1.9 按浮点会误判；按 SemVer 1.10 > 1.9
        self.assertGreater(parse_ecosystem_version("npm", "1.10.0"),
                           parse_ecosystem_version("npm", "1.9.0"))
        self.assertGreater(parse_ecosystem_version("PyPI", "1.10"),
                           parse_ecosystem_version("PyPI", "1.9"))


def events(*pairs):
    return [{key: value} for key, value in pairs]


@unittest.skipUnless(VERSIONS_AVAILABLE,
                     "需要 packaging 与 semantic_version 包")
class TestRangeValidation(unittest.TestCase):

    def assert_code(self, code, ecosystem, evs):
        intervals, diags = validate_range_events(ecosystem, evs, "$.x")
        self.assertTrue(diags, f"期待诊断 {code}，实际通过")
        self.assertEqual(diags[0].code, code)
        return diags

    def test_empty_events_rejected(self):
        self.assert_code(EVENTS_EMPTY, "PyPI", [])

    def test_multi_key_event_item_rejected(self):
        self.assert_code(EVENT_ITEM_STRUCTURE, "PyPI", [
            {"introduced": "1.0", "fixed": "2.0"}])

    def test_unknown_event_key_rejected(self):
        self.assert_code(EVENT_ITEM_STRUCTURE, "PyPI", [
            {"introduced": "1.0"}, {"patched": "2.0"}])

    def test_non_string_event_value_rejected(self):
        self.assert_code(EVENT_ITEM_STRUCTURE, "PyPI", [
            {"introduced": "1.0"}, {"fixed": 2}])

    def test_must_start_with_introduced(self):
        self.assert_code(EVENTS_MUST_START_WITH_INTRODUCED, "PyPI",
                         events(("fixed", "1.0")))

    def test_alternation_violation_double_introduced(self):
        self.assert_code(EVENTS_NOT_ALTERNATING, "PyPI",
                         events(("introduced", "1.0"), ("introduced", "2.0")))

    def test_alternation_violation_double_close(self):
        self.assert_code(EVENTS_NOT_ALTERNATING, "PyPI",
                         events(("introduced", "1.0"), ("fixed", "2.0"),
                                ("last_affected", "3.0")))

    def test_zero_only_allowed_in_introduced(self):
        for close in ("fixed", "limit", "last_affected"):
            self.assert_code(ZERO_NOT_ALLOWED_HERE, "PyPI",
                             events(("introduced", "1.0"), (close, "0")))

    def test_unparseable_endpoint_rejected_per_ecosystem(self):
        # npm 严格 SemVer 拒绝缺段端点
        self.assert_code(ENDPOINT_UNPARSEABLE, "npm",
                         events(("introduced", "1.0"), ("fixed", "2.0.0")))
        # PyPI 拒绝非 PEP 440 端点
        self.assert_code(ENDPOINT_UNPARSEABLE, "PyPI",
                         events(("introduced", "abc!!"), ("fixed", "2.0")))

    def test_fixed_equal_to_lower_is_regressed(self):
        self.assert_code(RANGE_REGRESSED, "PyPI",
                         events(("introduced", "1.0"), ("fixed", "1.0")))

    def test_fixed_below_lower_is_regressed(self):
        self.assert_code(RANGE_REGRESSED, "PyPI",
                         events(("introduced", "2.0.0"), ("fixed", "1.0.0")))

    def test_last_affected_may_equal_lower(self):
        intervals, diags = validate_range_events(
            "PyPI", events(("introduced", "1.0.0"),
                           ("last_affected", "1.0.0")), "$.x")
        self.assertEqual(diags, [])
        self.assertTrue(intervals[0].contains(
            parse_ecosystem_version("PyPI", "1.0.0")))

    def test_last_affected_below_lower_is_regressed(self):
        self.assert_code(RANGE_REGRESSED, "PyPI",
                         events(("introduced", "2.0"),
                                ("last_affected", "1.0")))

    def test_overlap_after_fixed(self):
        self.assert_code(RANGE_OVERLAP, "PyPI",
                         events(("introduced", "1.0.0"), ("fixed", "2.0.0"),
                                ("introduced", "1.5.0"), ("fixed", "3.0.0")))

    def test_restart_at_fixed_endpoint_allowed(self):
        # 后段可从前段排除的结束端点开始
        intervals, diags = validate_range_events(
            "PyPI", events(("introduced", "1.0.0"), ("fixed", "2.0.0"),
                           ("introduced", "2.0.0"), ("fixed", "3.0.0")), "$.x")
        self.assertEqual(diags, [])
        self.assertEqual(len(intervals), 2)
        self.assertFalse(intervals[0].contains(
            parse_ecosystem_version("PyPI", "2.0.0")))
        self.assertTrue(intervals[1].contains(
            parse_ecosystem_version("PyPI", "2.0.0")))

    def test_restart_at_last_affected_endpoint_rejected(self):
        # 不能再包含前段已经包含的最后版本
        self.assert_code(RANGE_OVERLAP, "PyPI",
                         events(("introduced", "1.0.0"),
                                ("last_affected", "1.5.0"),
                                ("introduced", "1.5.0"), ("fixed", "2.0.0")))

    def test_introduced_zero_after_close_rejected(self):
        self.assert_code(RANGE_OVERLAP, "PyPI",
                         events(("introduced", "1.0.0"), ("fixed", "2.0.0"),
                                ("introduced", "0"), ("fixed", "3.0.0")))

    def test_open_interval_extends_to_future(self):
        intervals, diags = validate_range_events(
            "npm", events(("introduced", "1.0.0")), "$.x")
        self.assertEqual(diags, [])
        self.assertTrue(intervals[0].contains(
            parse_ecosystem_version("npm", "99.0.0")))

    def test_introduced_zero_means_before_all_versions(self):
        intervals, diags = validate_range_events(
            "PyPI", events(("introduced", "0"), ("limit", "1.5.0")), "$.x")
        self.assertEqual(diags, [])
        self.assertTrue(intervals[0].contains(
            parse_ecosystem_version("PyPI", "0.0.1")))
        self.assertFalse(intervals[0].contains(
            parse_ecosystem_version("PyPI", "1.5.0")))


@unittest.skipUnless(VERSIONS_AVAILABLE,
                     "需要 packaging 与 semantic_version 包")
class TestIntervalMembership(unittest.TestCase):

    def test_fixed_and_limit_exclude_endpoint(self):
        for close in ("fixed", "limit"):
            intervals, diags = validate_range_events(
                "PyPI", events(("introduced", "1.0"), (close, "2.0")), "$.x")
            self.assertEqual(diags, [])
            self.assertFalse(intervals[0].contains(
                parse_ecosystem_version("PyPI", "2.0")))
            self.assertTrue(intervals[0].contains(
                parse_ecosystem_version("PyPI", "1.999")))

    def test_last_affected_includes_endpoint(self):
        intervals, diags = validate_range_events(
            "npm", events(("introduced", "0.9.0"),
                          ("last_affected", "0.9.7")), "$.x")
        self.assertEqual(diags, [])
        self.assertTrue(intervals[0].contains(
            parse_ecosystem_version("npm", "0.9.7")))
        self.assertFalse(intervals[0].contains(
            parse_ecosystem_version("npm", "0.9.8")))

    def test_introduced_lower_bound_inclusive(self):
        intervals, diags = validate_range_events(
            "PyPI", events(("introduced", "1.0"), ("fixed", "2.0")), "$.x")
        self.assertEqual(diags, [])
        self.assertTrue(intervals[0].contains(
            parse_ecosystem_version("PyPI", "1.0")))

    def test_reintroduced_gap_not_covered(self):
        intervals, diags = validate_range_events(
            "PyPI", events(("introduced", "0.9.0"), ("fixed", "0.9.3"),
                           ("introduced", "0.9.5"),
                           ("last_affected", "0.9.7")), "$.x")
        self.assertEqual(diags, [])
        gap = parse_ecosystem_version("PyPI", "0.9.4")
        self.assertFalse(any(i.contains(gap) for i in intervals))
        hit = parse_ecosystem_version("PyPI", "0.9.7")
        self.assertTrue(any(i.contains(hit) for i in intervals))

    def test_npm_rc2_vs_rc10(self):
        intervals, diags = validate_range_events(
            "npm", events(("introduced", "2.0.0-rc.1"),
                          ("fixed", "2.0.0-rc.10")), "$.x")
        self.assertEqual(diags, [])
        self.assertTrue(intervals[0].contains(
            parse_ecosystem_version("npm", "2.0.0-rc.2")))
        self.assertFalse(intervals[0].contains(
            parse_ecosystem_version("npm", "2.0.0-rc.10")))

    def test_npm_build_metadata_does_not_extend_range(self):
        intervals, diags = validate_range_events(
            "npm", events(("introduced", "1.3.0"), ("fixed", "1.4.0")), "$.x")
        self.assertEqual(diags, [])
        # 1.4.0+build.7 优先级等于 1.4.0，被 fixed 端点排除
        self.assertFalse(intervals[0].contains(
            parse_ecosystem_version("npm", "1.4.0+build.7")))
        self.assertTrue(intervals[0].contains(
            parse_ecosystem_version("npm", "1.4.0-rc.1+build.7")))


if __name__ == "__main__":
    unittest.main()
