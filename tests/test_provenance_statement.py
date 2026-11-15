"""in-toto Statement v1 / SLSA Provenance v1 payload 解析边界。"""

import json
import unittest

from provenance_fixtures import PREDICATE_TYPE, STATEMENT_TYPE, make_statement

from oci_catalog.provenance.intoto import (
    DUPLICATE_JSON_KEY,
    EMPTY_SUBJECT_LIST,
    INVALID_DIGEST,
    INVALID_JSON,
    MISSING_FIELD,
    UNSUPPORTED_PREDICATE_TYPE,
    UNSUPPORTED_STATEMENT_TYPE,
    parse_statement,
)

IMAGE = "sha256:" + "ab" * 32


def payload_bytes(statement=None, materials=None, **overrides):
    if statement is None:
        statement = make_statement(IMAGE, materials=materials) \
            if materials is not None else make_statement(IMAGE)
    doc = dict(statement)
    doc.update(overrides)
    return json.dumps(doc).encode("utf-8")


class TestStatementTypes(unittest.TestCase):

    def test_valid_statement_parses(self):
        parsed = parse_statement(payload_bytes())
        self.assertTrue(parsed.ok, parsed.diagnostics)
        self.assertEqual(len(parsed.subjects), 1)
        self.assertEqual(parsed.subjects[0].sha256, "ab" * 32)
        self.assertEqual(parsed.builder_id, "https://builder.test/offline-etl")
        self.assertEqual(parsed.build_type,
                         "https://buildtypes.test/offline-etl/v1")
        self.assertEqual(parsed.invocation_id, "task-1")

    def test_wrong_statement_type_rejected(self):
        parsed = parse_statement(payload_bytes(_type="https://in-toto.io/Statement/v0"))
        self.assertFalse(parsed.ok)
        codes = [d.code for d in parsed.diagnostics]
        self.assertIn(UNSUPPORTED_STATEMENT_TYPE, codes)
        diag = next(d for d in parsed.diagnostics
                    if d.code == UNSUPPORTED_STATEMENT_TYPE)
        self.assertEqual(diag.location, "payload:$._type")

    def test_wrong_predicate_type_rejected(self):
        parsed = parse_statement(payload_bytes(
            predicateType="https://slsa.dev/provenance/v0.2"))
        self.assertFalse(parsed.ok)
        codes = [d.code for d in parsed.diagnostics]
        self.assertIn(UNSUPPORTED_PREDICATE_TYPE, codes)

    def test_missing_predicate_fields_located(self):
        statement = make_statement(IMAGE)
        del statement["predicate"]["buildDefinition"]["buildType"]
        del statement["predicate"]["runDetails"]["builder"]
        parsed = parse_statement(payload_bytes(statement))
        self.assertFalse(parsed.ok)
        locations = {d.location for d in parsed.diagnostics}
        self.assertIn("payload:$.predicate.buildDefinition.buildType",
                      locations)
        self.assertIn("payload:$.predicate.runDetails.builder", locations)

    def test_missing_resolved_dependencies_located(self):
        statement = make_statement(IMAGE)
        del statement["predicate"]["buildDefinition"]["resolvedDependencies"]
        parsed = parse_statement(payload_bytes(statement))
        self.assertFalse(parsed.ok)
        self.assertIn(MISSING_FIELD, [d.code for d in parsed.diagnostics])

    def test_invalid_json_and_duplicate_keys(self):
        parsed = parse_statement(b"{broken")
        self.assertEqual(parsed.diagnostics[0].code, INVALID_JSON)
        raw = (b'{"_type": "' + STATEMENT_TYPE.encode() + b'", '
               b'"_type": "x", "subject": [], "predicateType": "'
               + PREDICATE_TYPE.encode() + b'", "predicate": {}}')
        parsed = parse_statement(raw)
        self.assertEqual(parsed.diagnostics[0].code, DUPLICATE_JSON_KEY)
        self.assertEqual(parsed.diagnostics[0].location, "payload:$")

    def test_duplicate_key_nested_in_predicate_rejected(self):
        statement = make_statement(IMAGE)
        # 手工拼 JSON：predicate 内 builder.id 重复
        raw = json.dumps(statement).encode()
        raw = raw.replace(b'"id": "https://builder.test/offline-etl"',
                          b'"id": "a", "id": "b"')
        parsed = parse_statement(raw)
        self.assertFalse(parsed.ok)
        self.assertEqual(parsed.diagnostics[0].code, DUPLICATE_JSON_KEY)
        self.assertEqual(
            parsed.diagnostics[0].location,
            "payload:$.predicate.runDetails.builder")


class TestSubjects(unittest.TestCase):

    def test_empty_subject_list_rejected(self):
        parsed = parse_statement(payload_bytes(subject=[]))
        self.assertFalse(parsed.ok)
        self.assertIn(EMPTY_SUBJECT_LIST, [d.code for d in parsed.diagnostics])

    def test_subject_requires_sha256(self):
        parsed = parse_statement(payload_bytes(
            subject=[{"name": "x", "digest": {"sha512": "ab" * 64}}]))
        self.assertFalse(parsed.ok)
        diag = parsed.diagnostics[0]
        self.assertEqual(diag.code, MISSING_FIELD)
        self.assertEqual(diag.location, "payload:$.subject[0].digest.sha256")

    def test_subject_bad_sha256_rejected(self):
        for bad in ("ab" * 31, "zz" * 32, 12345):
            parsed = parse_statement(payload_bytes(
                subject=[{"name": "x", "digest": {"sha256": bad}}]))
            self.assertFalse(parsed.ok, bad)
            self.assertEqual(parsed.diagnostics[0].code, INVALID_DIGEST)

    def test_multi_subject_positions_preserved(self):
        parsed = parse_statement(payload_bytes(
            subject=[
                {"name": "first", "digest": {"sha256": "01" * 32}},
                {"name": "second", "digest": {"sha256": "02" * 32}},
                {"name": "third", "digest": {"sha256": "03" * 32}},
            ]))
        self.assertTrue(parsed.ok, parsed.diagnostics)
        self.assertEqual([(s.index, s.name) for s in parsed.subjects],
                         [(0, "first"), (1, "second"), (2, "third")])

    def test_uppercase_sha256_normalized_to_lowercase(self):
        parsed = parse_statement(payload_bytes(
            subject=[{"name": "x", "digest": {"sha256": "AB" * 32}}]))
        self.assertTrue(parsed.ok, parsed.diagnostics)
        self.assertEqual(parsed.subjects[0].sha256, "ab" * 32)


class TestMaterials(unittest.TestCase):

    def test_material_positions_and_duplicates_preserved(self):
        materials = [
            {"uri": "https://m.test/a", "digest": {"sha256": "01" * 32}},
            {"uri": "https://m.test/a", "digest": {"sha256": "02" * 32}},
            {"uri": "https://m.test/a", "digest": {"sha256": "01" * 32}},
        ]
        parsed = parse_statement(payload_bytes(materials=materials))
        self.assertTrue(parsed.ok, parsed.diagnostics)
        # 同 URI 不同摘要不合并；完全重复项两处出现都保留
        self.assertEqual([(m.index, m.sha256) for m in parsed.materials],
                         [(0, "01" * 32), (1, "02" * 32), (2, "01" * 32)])

    def test_empty_uri_rejected(self):
        parsed = parse_statement(payload_bytes(materials=[
            {"uri": "", "digest": {"sha256": "01" * 32}}]))
        self.assertFalse(parsed.ok)
        self.assertEqual(parsed.diagnostics[0].location,
                         "payload:$.predicate.buildDefinition."
                         "resolvedDependencies[0].uri")

    def test_material_missing_digest_rejected(self):
        parsed = parse_statement(payload_bytes(materials=[
            {"uri": "https://m.test/a"}]))
        self.assertFalse(parsed.ok)
        self.assertEqual(parsed.diagnostics[0].code, MISSING_FIELD)

    def test_material_bad_sha256_rejected(self):
        parsed = parse_statement(payload_bytes(materials=[
            {"uri": "https://m.test/a", "digest": {"sha256": "xyz"}}]))
        self.assertFalse(parsed.ok)
        self.assertEqual(parsed.diagnostics[0].code, INVALID_DIGEST)

    def test_strings_kept_verbatim(self):
        # 构建者/类型/材料字符串按原值处理：大小写、空白不做归一
        statement = make_statement(
            IMAGE, builder="  HTTPS://Builder.TEST/Team  ",
            build_type="BuildType/V1 ")
        parsed = parse_statement(payload_bytes(statement))
        self.assertTrue(parsed.ok, parsed.diagnostics)
        self.assertEqual(parsed.builder_id, "  HTTPS://Builder.TEST/Team  ")
        self.assertEqual(parsed.build_type, "BuildType/V1 ")

    def test_invocation_id_optional(self):
        statement = make_statement(IMAGE)
        del statement["predicate"]["runDetails"]["metadata"]
        parsed = parse_statement(payload_bytes(statement))
        self.assertTrue(parsed.ok, parsed.diagnostics)
        self.assertIsNone(parsed.invocation_id)


if __name__ == "__main__":
    unittest.main()
