"""purl 解析与规范化契约测试。"""

import unittest

from oci_catalog.sbom.purl import PurlError, parse_purl


class TestPurlParsing(unittest.TestCase):

    def test_supported_types_normalized_lowercase(self):
        for raw, ptype in [
            ("pkg:generic/x@1", "generic"),
            ("pkg:PyPI/x@1", "pypi"),
            ("pkg:NPM/x@1", "npm"),
        ]:
            self.assertEqual(parse_purl(raw).type, ptype)

    def test_unsupported_type_rejected(self):
        with self.assertRaises(PurlError):
            parse_purl("pkg:maven/org.apache/commons@1")
        with self.assertRaises(PurlError):
            parse_purl("pkg:deb/debian/curl@7")

    def test_missing_pkg_prefix_rejected(self):
        with self.assertRaises(PurlError):
            parse_purl("pypi/requests@1")

    def test_pypi_name_normalization(self):
        # PEP 503：连字符/下划线/点的连续组合 -> 单个连字符，转小写
        variants = [
            "pkg:pypi/Flask_Core.Ext@1.2.0",
            "pkg:pypi/flask-core-ext@1.2.0",
            "pkg:pypi/FLASK__CORE..EXT@1.2.0",
        ]
        canonicals = {parse_purl(v).canonical for v in variants}
        self.assertEqual(canonicals, {"pkg:pypi/flask-core-ext@1.2.0"})

    def test_pypi_versions_still_distinguish_identity(self):
        a = parse_purl("pkg:pypi/requests@2.31.0").canonical
        b = parse_purl("pkg:pypi/requests@2.32.3").canonical
        self.assertNotEqual(a, b)

    def test_npm_scope_lowercased_but_name_case_preserved(self):
        self.assertEqual(
            parse_purl("pkg:npm/%40Angular/Animation@1").canonical,
            "pkg:npm/%40angular/Animation@1")
        # 仅包名大小写不同 => 不同身份，不合并
        self.assertNotEqual(
            parse_purl("pkg:npm/Foo@1").canonical,
            parse_purl("pkg:npm/foo@1").canonical)

    def test_npm_encoded_name_roundtrip(self):
        purl = parse_purl("pkg:npm/%40scope/pkg%20name@1")
        # 解码后 namespace 保留 npm scope 的 '@' 前缀；重新编码时 '@' -> %40
        self.assertEqual(purl.namespace, ("@scope",))
        self.assertEqual(purl.name, "pkg name")
        self.assertEqual(purl.canonical, "pkg:npm/%40scope/pkg%20name@1")

    def test_version_with_special_chars_roundtrips(self):
        # npm 构建元数据 '+'：version 保存解码后原文，canonical 只编码一次，
        # parse(canonical) 往返必须稳定（历史双重编码缺陷的回归测试）
        purl = parse_purl("pkg:npm/%40acme/gadget@1.4.0%2Bbuild.7")
        self.assertEqual(purl.version, "1.4.0+build.7")
        self.assertEqual(
            purl.canonical, "pkg:npm/%40acme/gadget@1.4.0%2Bbuild.7")
        self.assertEqual(parse_purl(purl.canonical), purl)

    def test_subpath_with_special_chars_roundtrips(self):
        purl = parse_purl("pkg:generic/x@1#lib/a%20b")
        self.assertEqual(purl.subpath, "lib/a b")
        self.assertEqual(purl.canonical, "pkg:generic/x@1#lib/a%20b")
        self.assertEqual(parse_purl(purl.canonical), purl)

    def test_qualifier_order_and_percent_encoding_normalized(self):
        a = parse_purl("pkg:generic/openssl@3?arch=x86_64&distro=debian")
        b = parse_purl("pkg:generic/openssl@3?distro=debian&arch=x86_64")
        c = parse_purl("pkg:generic/openssl@3?arch=x86%3a64&distro=debian")
        self.assertEqual(a.canonical, b.canonical)
        # x86:64 解码后与 x86_64 是不同值，不能误合并
        self.assertNotEqual(a.canonical, c.canonical)
        self.assertEqual(
            a.canonical,
            "pkg:generic/openssl@3?arch=x86_64&distro=debian")

    def test_duplicate_qualifier_key_rejected(self):
        with self.assertRaises(PurlError):
            parse_purl("pkg:npm/foo@1?a=1&a=2")

    def test_bad_percent_encoding_rejected(self):
        for raw in ("pkg:generic/name%zz@1", "pkg:generic/name%2@1"):
            with self.assertRaises(PurlError):
                parse_purl(raw)

    def test_illegal_subpath_rejected(self):
        with self.assertRaises(PurlError):
            parse_purl("pkg:generic/x@1#../etc/passwd")

    def test_subpath_participates_in_identity(self):
        a = parse_purl("pkg:generic/x@1#lib/a")
        b = parse_purl("pkg:generic/x@1#lib/b")
        self.assertNotEqual(a.canonical, b.canonical)

    def test_empty_name_rejected(self):
        with self.assertRaises(PurlError):
            parse_purl("pkg:generic/")

    def test_namespace_preserved_and_encoded(self):
        purl = parse_purl("pkg:generic/ns/sub/name@1")
        self.assertEqual(purl.namespace, ("ns", "sub"))
        self.assertEqual(purl.canonical, "pkg:generic/ns/sub/name@1")


if __name__ == "__main__":
    unittest.main()
