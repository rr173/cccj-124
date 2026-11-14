"""SBOM 存储：镜像绑定校验、单文件事务、重复语义、目录库只读。"""

import json
import os

from sbom_fixtures import SBOMFixture
from oci_catalog.sbom.sbom_parser import parse_document
from oci_catalog.sbom.sbom_store import (
    BINDING_NOT_DIGEST,
    BINDING_NOT_IMAGE,
    BINDING_UNKNOWN_DIGEST,
    DUPLICATE_SKIPPED,
    FAILED,
    IMPORTED,
    REPLACED,
)


def cdx_doc(refs_and_purls, deps):
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.5",
        "components": [
            {"bom-ref": ref, "name": ref.lower(), "version": "1",
             **({"purl": purl} if purl else {})}
            for ref, purl in refs_and_purls],
        "dependencies": deps,
    }


class TestBindingValidation(SBOMFixture):

    def test_valid_image_binding_passes(self):
        self.assertEqual(
            self.store.validate_binding(self.image_amd64), [])

    def test_tag_string_rejected(self):
        diags = self.store.validate_binding("v1")
        self.assertEqual(diags[0].code, BINDING_NOT_DIGEST)

    def test_index_digest_rejected(self):
        diags = self.store.validate_binding(self.index_digest)
        self.assertEqual(diags[0].code, BINDING_NOT_IMAGE)

    def test_unknown_digest_rejected(self):
        diags = self.store.validate_binding("sha256:" + "9f" * 32)
        self.assertEqual(diags[0].code, BINDING_UNKNOWN_DIGEST)

    def test_malformed_digest_rejected(self):
        diags = self.store.validate_binding("not-a-digest")
        self.assertEqual(diags[0].code, BINDING_NOT_DIGEST)


class TestImportTransactions(SBOMFixture):

    def test_failure_diagnostics_carry_file_and_location(self):
        bad = cdx_doc([("A", "not-a-purl")], [])
        result = self.import_dict("loc.json", bad, self.image_amd64)
        self.assertEqual(result.status, FAILED)
        diag = result.diagnostics[0]
        self.assertEqual(diag.code, "invalid_purl")
        self.assertTrue(diag.location.startswith("$.components[0].purl"))
        # 落库的失败记录保留同样的位置信息
        row = self.store.list_failures()[0]
        stored = json.loads(row["diagnostics_json"])
        self.assertEqual(stored[0]["location"], diag.location)
        self.assertEqual(row["source_path"].endswith("loc.json"), True)

    def test_failed_file_leaves_no_queryable_records(self):
        bad = cdx_doc([("A", None)],
                      [{"ref": "A", "dependsOn": ["GHOST"]}])
        result = self.import_dict("bad.json", bad, self.image_amd64)
        self.assertEqual(result.status, FAILED)
        self.assertTrue(result.diagnostics)
        # 没有任何文件/出现/边残留
        self.assertEqual(self.store.conn.execute(
            "SELECT COUNT(*) AS c FROM sbom_files").fetchone()["c"], 0)
        self.assertEqual(self.store.conn.execute(
            "SELECT COUNT(*) AS c FROM occurrences").fetchone()["c"], 0)
        self.assertEqual(self.store.conn.execute(
            "SELECT COUNT(*) AS c FROM dependency_edges").fetchone()["c"], 0)
        # 失败留痕在 import_failures
        self.assertEqual(len(self.store.list_failures()), 1)

    def test_bad_binding_fails_transactionally(self):
        good = cdx_doc([("A", "pkg:generic/a@1")], [])
        result = self.import_dict("good.json", good, self.index_digest)
        self.assertEqual(result.status, FAILED)
        self.assertEqual(self.store.conn.execute(
            "SELECT COUNT(*) AS c FROM components").fetchone()["c"], 0)

    def test_successful_import_persists(self):
        doc = cdx_doc([("A", "pkg:generic/a@1"), ("B", "pkg:generic/b@1")],
                      [{"ref": "A", "dependsOn": ["B"]}])
        result = self.import_dict("ok.json", doc, self.image_amd64)
        self.assertEqual(result.status, IMPORTED)
        self.assertEqual(result.components, 2)
        self.assertEqual(result.edges, 1)
        self.assertEqual(self.store.conn.execute(
            "SELECT COUNT(*) AS c FROM occurrences").fetchone()["c"], 2)

    def test_purless_component_has_null_identity(self):
        doc = cdx_doc([("NO-PURL", None)], [])
        self.import_dict("p.json", doc, self.image_amd64)
        row = self.store.conn.execute(
            "SELECT component_id FROM occurrences").fetchone()
        self.assertIsNone(row["component_id"])

    def test_same_purl_distinct_refs_keep_separate_occurrences(self):
        doc = cdx_doc([
            ("REF-1", "pkg:pypi/x@1?arch=a"),
            ("REF-2", "pkg:pypi/x@1?arch=a"),
        ], [])
        self.import_dict("dup-purl.json", doc, self.image_amd64)
        # components 只有一个身份，occurrences 有两条且位置不同
        self.assertEqual(self.store.conn.execute(
            "SELECT COUNT(*) AS c FROM components").fetchone()["c"], 1)
        refs = [r["file_ref"] for r in self.store.conn.execute(
            "SELECT file_ref FROM occurrences ORDER BY file_ref")]
        self.assertEqual(refs, ["REF-1", "REF-2"])


class TestDuplicateSemantics(SBOMFixture):

    def _doc(self):
        return cdx_doc([("A", "pkg:generic/a@1")], [])

    def test_same_path_reimport_replaces(self):
        path = self.write_sbom("f.json", self._doc())
        with open(path, "rb") as fh:
            first = self.store.import_file(path, self.image_amd64, fh.read())
        self.assertEqual(first.status, IMPORTED)
        with open(path, "rb") as fh:
            second = self.store.import_file(path, self.image_amd64, fh.read())
        self.assertEqual(second.status, REPLACED)
        # 替换后仍然只有一份文件、一条出现
        self.assertEqual(self.store.conn.execute(
            "SELECT COUNT(*) AS c FROM sbom_files").fetchone()["c"], 1)
        self.assertEqual(self.store.conn.execute(
            "SELECT COUNT(*) AS c FROM occurrences").fetchone()["c"], 1)

    def test_same_content_different_path_same_binding_skipped(self):
        first_path = self.write_sbom("a.json", self._doc())
        second_path = self.write_sbom("b.json", self._doc())
        with open(first_path, "rb") as fh:
            self.store.import_file(first_path, self.image_amd64, fh.read())
        with open(second_path, "rb") as fh:
            result = self.store.import_file(second_path, self.image_amd64,
                                            fh.read())
        self.assertEqual(result.status, DUPLICATE_SKIPPED)
        self.assertEqual(self.store.conn.execute(
            "SELECT COUNT(*) AS c FROM sbom_files").fetchone()["c"], 1)

    def test_same_content_different_binding_is_new_file(self):
        path = self.write_sbom("a.json", self._doc())
        with open(path, "rb") as fh:
            data = fh.read()
        r1 = self.store.import_file(path, self.image_amd64, data)
        other_path = os.path.join(self.tmpdir, "c.json")
        r2 = self.store.import_file(other_path, self.image_arm64, data)
        self.assertEqual(r1.status, IMPORTED)
        self.assertEqual(r2.status, IMPORTED)
        self.assertEqual(self.store.conn.execute(
            "SELECT COUNT(*) AS c FROM sbom_files").fetchone()["c"], 2)


class TestCatalogReadOnly(SBOMFixture):

    def test_catalog_connection_is_read_only(self):
        import sqlite3
        with self.assertRaises(sqlite3.OperationalError):
            self.store._catalog_conn.execute("CREATE TABLE hack(x)")

    def test_import_does_not_modify_catalog(self):
        before_events = self.store._catalog_conn.execute(
            "SELECT COUNT(*) AS c FROM tag_events").fetchone()["c"]
        before_manifests = self.store._catalog_conn.execute(
            "SELECT COUNT(*) AS c FROM manifests").fetchone()["c"]
        doc = cdx_doc([("A", "pkg:generic/a@1")], [])
        self.import_dict("x.json", doc, self.image_amd64)
        after_events = self.store._catalog_conn.execute(
            "SELECT COUNT(*) AS c FROM tag_events").fetchone()["c"]
        after_manifests = self.store._catalog_conn.execute(
            "SELECT COUNT(*) AS c FROM manifests").fetchone()["c"]
        self.assertEqual(before_events, after_events)
        self.assertEqual(before_manifests, after_manifests)

    def test_batch_reports_per_file_success_and_failure(self):
        good_path = self.write_sbom(
            "good.json", cdx_doc([("A", "pkg:generic/a@1")], []))
        bad_path = self.write_sbom(
            "bad.json", cdx_doc([("A", None)],
                                [{"ref": "A", "dependsOn": ["X"]}]))
        results = self.store.import_paths([
            (good_path, self.image_amd64),
            (bad_path, self.image_amd64),
        ])
        self.assertEqual([r.ok for r in results], [True, False])
        # 好文件仍可查询，坏文件不影响它
        self.assertEqual(self.store.conn.execute(
            "SELECT COUNT(*) AS c FROM sbom_files").fetchone()["c"], 1)

    def test_unreadable_file_reported_not_raised(self):
        results = self.store.import_paths([
            ("/nonexistent/path/missing.json", self.image_amd64)])
        self.assertFalse(results[0].ok)
        self.assertEqual(results[0].diagnostics[0].code, "unreadable_file")


class TestParsedContractIntegrity(SBOMFixture):

    def test_parser_diagnostic_carries_location(self):
        doc = {"bomFormat": "CycloneDX",
               "components": [{"bom-ref": "A", "name": "a",
                               "purl": "broken"}],
               "dependencies": []}
        parsed = parse_document(json.dumps(doc).encode())
        self.assertEqual(parsed.diagnostics[0].location,
                         "$.components[0].purl")
