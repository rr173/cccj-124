"""CycloneDX / SPDX 解析契约测试（不触及数据库）。"""

import unittest

from oci_catalog.sbom.sbom_parser import (
    CYCLONEDX,
    SPDX,
    detect_format,
    parse_document,
)


def cdx(components, dependencies=None):
    return {"bomFormat": "CycloneDX", "specVersion": "1.5",
            "components": components,
            "dependencies": dependencies or []}


class TestCycloneDxParser(unittest.TestCase):

    def test_nested_components_and_locations(self):
        doc = cdx([
            {"bom-ref": "root", "name": "r", "version": "1",
             "components": [
                 {"bom-ref": "child", "name": "c", "version": "2",
                  "licenses": [{"license": {"id": "MIT"}}]}]},
        ])
        parsed = parse_document(_json_bytes(doc))
        self.assertTrue(parsed.ok, parsed.diagnostics)
        refs = {c.ref: c for c in parsed.components}
        self.assertEqual(set(refs), {"root", "child"})
        self.assertEqual(refs["child"].location,
                         "$.components[0].components[0]")
        self.assertIn("MIT", refs["child"].license_raw)

    def test_duplicate_bomref_is_diagnostic(self):
        doc = cdx([{"bom-ref": "DUP", "name": "a"},
                   {"bom-ref": "DUP", "name": "b"}])
        parsed = parse_document(_json_bytes(doc))
        codes = {d.code for d in parsed.diagnostics}
        self.assertIn("duplicate_ref", codes)
        self.assertFalse(parsed.ok)

    def test_missing_bomref_is_diagnostic(self):
        doc = cdx([{"name": "no-ref"}])
        parsed = parse_document(_json_bytes(doc))
        self.assertIn("missing_ref", {d.code for d in parsed.diagnostics})

    def test_dangling_dependency_ref(self):
        doc = cdx([{"bom-ref": "A", "name": "a"}],
                  [{"ref": "A", "dependsOn": ["GHOST"]}])
        parsed = parse_document(_json_bytes(doc))
        self.assertIn("dangling_ref", {d.code for d in parsed.diagnostics})

    def test_invalid_purl_keeps_component_but_flags_diagnostic(self):
        doc = cdx([{"bom-ref": "A", "name": "a", "purl": "bad-purl"}])
        parsed = parse_document(_json_bytes(doc))
        self.assertFalse(parsed.ok)
        comp = parsed.components[0]
        self.assertIsNone(comp.purl)
        self.assertEqual(comp.purl_raw, "bad-purl")  # 原始留痕
        self.assertEqual(parsed.diagnostics[0].location,
                         "$.components[0].purl")

    def test_duplicate_edges_deduplicated(self):
        doc = cdx([{"bom-ref": "A", "name": "a"},
                   {"bom-ref": "B", "name": "b"}],
                  [{"ref": "A", "dependsOn": ["B", "B"]}])
        parsed = parse_document(_json_bytes(doc))
        self.assertTrue(parsed.ok, parsed.diagnostics)
        self.assertEqual(len(parsed.edges), 1)
        self.assertEqual(parsed.duplicate_edges, 1)

    def test_non_string_purl_rejected(self):
        doc = cdx([{"bom-ref": "A", "name": "a", "purl": 123}])
        parsed = parse_document(_json_bytes(doc))
        self.assertFalse(parsed.ok)
        self.assertIsNone(parsed.components[0].purl)
        self.assertEqual(parsed.components[0].purl_raw, "123")

    def test_supplier_and_license_traceability(self):
        doc = cdx([{"bom-ref": "A", "name": "a", "version": "9",
                    "supplier": {"name": "Acme"},
                    "licenses": [{"expression": "GPL-2.0-only WITH Classpath-exception-2.0"}]}])
        parsed = parse_document(_json_bytes(doc))
        comp = parsed.components[0]
        self.assertEqual(comp.supplier, "Acme")
        self.assertIn("GPL-2.0-only", comp.license_raw)


class TestSpdxParser(unittest.TestCase):

    def _spdx(self, packages, relationships):
        return {"spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT",
                "packages": packages, "relationships": relationships}

    def test_depends_on_and_dependency_of_unify_direction(self):
        doc = self._spdx(
            [{"SPDXID": "SPDXRef-A", "name": "a"},
             {"SPDXID": "SPDXRef-B", "name": "b"},
             {"SPDXID": "SPDXRef-C", "name": "c"}],
            [{"spdxElementId": "SPDXRef-A", "relationshipType": "DEPENDS_ON",
              "relatedSpdxElement": "SPDXRef-B"},
             {"spdxElementId": "SPDXRef-C", "relationshipType": "DEPENDENCY_OF",
              "relatedSpdxElement": "SPDXRef-A"}])
        parsed = parse_document(_json_bytes(doc))
        self.assertTrue(parsed.ok, parsed.diagnostics)
        edges = {(f, t) for f, t, _ in parsed.edges}
        # 两种关系都统一为 from 依赖 to
        self.assertEqual(edges, {("SPDXRef-A", "SPDXRef-B"),
                                 ("SPDXRef-A", "SPDXRef-C")})

    def test_non_dependency_relationships_ignored(self):
        doc = self._spdx(
            [{"SPDXID": "SPDXRef-A", "name": "a"},
             {"SPDXID": "SPDXRef-B", "name": "b"}],
            [{"spdxElementId": "SPDXRef-DOCUMENT",
              "relationshipType": "DESCRIBES", "relatedSpdxElement": "SPDXRef-A"},
             {"spdxElementId": "SPDXRef-A", "relationshipType": "CONTAINS",
              "relatedSpdxElement": "SPDXRef-B"},
             {"spdxElementId": "SPDXRef-A", "relationshipType": "PATCH_OF",
              "relatedSpdxElement": "SPDXRef-B"}])
        parsed = parse_document(_json_bytes(doc))
        self.assertEqual(parsed.edges, [])
        self.assertEqual(parsed.ignored_relationships, 3)

    def test_dangling_relationship_ref(self):
        doc = self._spdx(
            [{"SPDXID": "SPDXRef-A", "name": "a"}],
            [{"spdxElementId": "SPDXRef-A", "relationshipType": "DEPENDS_ON",
              "relatedSpdxElement": "SPDXRef-GHOST"}])
        parsed = parse_document(_json_bytes(doc))
        self.assertIn("dangling_ref", {d.code for d in parsed.diagnostics})

    def test_duplicate_spdxid(self):
        doc = self._spdx(
            [{"SPDXID": "DUP", "name": "a"}, {"SPDXID": "DUP", "name": "b"}],
            [])
        parsed = parse_document(_json_bytes(doc))
        self.assertIn("duplicate_ref", {d.code for d in parsed.diagnostics})

    def test_purl_external_ref_parsed_and_multiple_rejected(self):
        single = self._spdx([{
            "SPDXID": "SPDXRef-A", "name": "requests", "versionInfo": "1",
            "externalRefs": [{"referenceType": "purl",
                              "referenceLocator": "pkg:pypi/requests@1"}]}], [])
        parsed = parse_document(_json_bytes(single))
        self.assertTrue(parsed.ok)
        self.assertEqual(parsed.components[0].purl.canonical,
                         "pkg:pypi/requests@1")

        multi = self._spdx([{
            "SPDXID": "SPDXRef-A", "name": "requests",
            "externalRefs": [
                {"referenceType": "purl", "referenceLocator": "pkg:pypi/requests@1"},
                {"referenceType": "purl", "referenceLocator": "pkg:pypi/requests@2"}]}],
            [])
        parsed_multi = parse_document(_json_bytes(multi))
        self.assertIn("duplicate_purl_ref",
                      {d.code for d in parsed_multi.diagnostics})

    def test_relationship_to_document_id_is_dangling(self):
        # DOCUMENT 的 SPDXID 不是 package，依赖关系引用它必须报悬空
        doc = self._spdx(
            [{"SPDXID": "SPDXRef-A", "name": "a"}],
            [{"spdxElementId": "SPDXRef-DOCUMENT",
              "relationshipType": "DEPENDS_ON",
              "relatedSpdxElement": "SPDXRef-A"}])
        parsed = parse_document(_json_bytes(doc))
        self.assertIn("dangling_ref", {d.code for d in parsed.diagnostics})
        self.assertEqual(parsed.edges, [])

    def test_relationships_wrong_type_is_structure_error(self):
        doc = {"spdxVersion": "SPDX-2.3", "SPDXID": "D",
               "packages": [{"SPDXID": "A", "name": "a"}],
               "relationships": "not-a-list"}
        parsed = parse_document(_json_bytes(doc))
        self.assertIn("invalid_structure",
                      {d.code for d in parsed.diagnostics})

    def test_license_original_expression_kept(self):
        doc = self._spdx([{
            "SPDXID": "SPDXRef-A", "name": "a",
            "licenseDeclared": "MIT OR Apache-2.0",
            "licenseConcluded": "NOASSERTION"}], [])
        parsed = parse_document(_json_bytes(doc))
        raw = parsed.components[0].license_raw
        self.assertIn("MIT OR Apache-2.0", raw)
        self.assertIn("NOASSERTION", raw)


class TestFormatDetection(unittest.TestCase):

    def test_detect(self):
        self.assertEqual(detect_format({"bomFormat": "CycloneDX"}), CYCLONEDX)
        self.assertEqual(detect_format({"spdxVersion": "SPDX-2.3"}), SPDX)
        self.assertIsNone(detect_format({"hello": "world"}))

    def test_invalid_json_and_structure(self):
        parsed = parse_document(b"{not json")
        self.assertEqual(parsed.diagnostics[0].code, "invalid_json")
        parsed_list = parse_document(b"[1, 2, 3]")
        self.assertEqual(parsed_list.diagnostics[0].code, "invalid_structure")
        parsed_unknown = parse_document(b'{"hello": 1}')
        self.assertEqual(parsed_unknown.diagnostics[0].code, "unknown_format")


def _json_bytes(payload: dict) -> bytes:
    import json
    return json.dumps(payload).encode("utf-8")


if __name__ == "__main__":
    unittest.main()
