"""证明证据库：绑定校验、单文件事务、证据身份与幂等导入。"""

import json
import unittest

from provenance_fixtures import (
    CRYPTO_AVAILABLE,
    ProvenanceFixture,
    make_envelope,
    make_statement,
)

from oci_catalog.provenance.store import (
    BINDING_NOT_DIGEST,
    BINDING_NOT_IMAGE,
    BINDING_SUBJECT_MISMATCH,
    BINDING_UNKNOWN_DIGEST,
    DUPLICATE_SKIPPED,
    FAILED,
    IMPORTED,
)


@unittest.skipUnless(CRYPTO_AVAILABLE, "需要 cryptography 包")
class TestBindingValidation(ProvenanceFixture):

    def test_valid_image_binding_passes(self):
        self.assertEqual(self.store.validate_binding(self.image_amd64), [])

    def test_tag_string_rejected(self):
        diags = self.store.validate_binding("v1")
        self.assertEqual(diags[0].code, BINDING_NOT_DIGEST)

    def test_index_digest_rejected(self):
        diags = self.store.validate_binding(self.index_digest)
        self.assertEqual(diags[0].code, BINDING_NOT_IMAGE)

    def test_unknown_digest_rejected(self):
        diags = self.store.validate_binding("sha256:" + "9f" * 32)
        self.assertEqual(diags[0].code, BINDING_UNKNOWN_DIGEST)


@unittest.skipUnless(CRYPTO_AVAILABLE, "需要 cryptography 包")
class TestImport(ProvenanceFixture):

    def test_import_success_registers_evidence(self):
        result = self.import_statement("ok.json", make_statement(self.image_amd64),
                                       self.image_amd64)
        self.assertEqual(result.status, IMPORTED)
        self.assertEqual(result.matched_subjects, [0])
        row = self.store.get_evidence(result.evidence_id)
        self.assertEqual(row["image_digest"], self.image_amd64)
        self.assertEqual(row["builder_id"], "https://builder.test/offline-etl")
        self.assertEqual(row["invocation_id"], "task-1")
        # 原始字节保留
        self.assertTrue(bytes(row["envelope_bytes"]).startswith(b"{"))
        self.assertTrue(bytes(row["payload_bytes"]).startswith(b"{"))
        # 材料与签名原位置保留
        self.assertEqual(len(self.store.list_materials(result.evidence_id)), 1)
        self.assertEqual(len(self.store.list_signatures(result.evidence_id)), 2)

    def test_structural_failure_leaves_no_evidence(self):
        bad = b'{"payloadType": "text/plain"}'
        result = self.import_envelope("bad.json", bad, self.image_amd64)
        self.assertEqual(result.status, FAILED)
        self.assertTrue(result.diagnostics)
        self.assertEqual(self.store.conn.execute(
            "SELECT COUNT(*) AS c FROM evidence").fetchone()["c"], 0)
        failures = self.store.list_failures()
        self.assertEqual(len(failures), 1)
        stored = json.loads(failures[0]["diagnostics_json"])
        self.assertEqual(stored[0]["location"], "$.payloadType")

    def test_binding_failure_records_locations(self):
        result = self.import_statement(
            "idx.json", make_statement(self.index_digest), self.index_digest)
        self.assertEqual(result.status, FAILED)
        codes = [d.code for d in result.diagnostics]
        self.assertIn(BINDING_NOT_IMAGE, codes)

    def test_subject_mismatch_rejected(self):
        # 声明的 subject 与绑定镜像不一致：不按 name/tag 猜测绑定
        statement = make_statement("sha256:" + "ff" * 32)
        result = self.import_statement("mismatch.json", statement,
                                       self.image_amd64)
        self.assertEqual(result.status, FAILED)
        diag = next(d for d in result.diagnostics
                    if d.code == BINDING_SUBJECT_MISMATCH)
        self.assertEqual(diag.location, "payload:$.subject")

    def test_multi_subject_binds_non_first(self):
        statement = make_statement(
            self.image_amd64,
            extra_subjects=[
                {"name": "source", "digest": {"sha256": "01" * 32}},
                {"name": "other", "digest": {"sha256": "02" * 32}},
            ])
        result = self.import_statement("multi.json", statement,
                                       self.image_amd64)
        self.assertEqual(result.status, IMPORTED)
        # 镜像 subject 在位置 2（前两个是 extra_subjects）
        self.assertEqual(result.matched_subjects, [2])
        subjects = self.store.list_subjects(result.evidence_id)
        self.assertEqual([s["subject_index"] for s in subjects], [0, 1, 2])
        self.assertEqual([s["matched"] for s in subjects], [0, 0, 1])

    def test_duplicate_import_reuses_identity(self):
        statement = make_statement(self.image_amd64)
        envelope = make_envelope(statement, self.signers("key-a", "key-b"))
        first = self.import_envelope("first.json", envelope, self.image_amd64)
        second = self.import_envelope("renamed-copy.json", envelope,
                                      self.image_amd64)
        self.assertEqual(first.status, IMPORTED)
        self.assertEqual(second.status, DUPLICATE_SKIPPED)
        self.assertEqual(first.evidence_id, second.evidence_id)
        self.assertEqual(self.store.conn.execute(
            "SELECT COUNT(*) AS c FROM evidence").fetchone()["c"], 1)

    def test_same_payload_different_signatures_is_new_evidence(self):
        statement = make_statement(self.image_amd64)
        env1 = make_envelope(statement, self.signers("key-a"))
        env2 = make_envelope(statement, self.signers("key-b"))
        first = self.import_envelope("e1.json", env1, self.image_amd64)
        second = self.import_envelope("e2.json", env2, self.image_amd64)
        self.assertEqual(first.status, IMPORTED)
        self.assertEqual(second.status, IMPORTED)
        self.assertNotEqual(first.evidence_id, second.evidence_id)
        # payload 相同 -> payload 摘要相同；信封字节不同 -> 不同证据
        row1 = self.store.get_evidence(first.evidence_id)
        row2 = self.store.get_evidence(second.evidence_id)
        self.assertEqual(row1["payload_sha256"], row2["payload_sha256"])
        self.assertNotEqual(row1["envelope_sha256"], row2["envelope_sha256"])

    def test_same_envelope_different_binding_is_new_evidence(self):
        # 一个信封的 subject 同时列出两个镜像：两个绑定各自登记证据
        statement = make_statement(
            self.image_amd64,
            extra_subjects=[{"name": "arm",
                             "digest": {"sha256": self.image_arm64.split(":")[1]}}])
        envelope = make_envelope(statement, self.signers("key-a", "key-b"))
        amd = self.import_envelope("both.json", envelope, self.image_amd64)
        arm = self.import_envelope("both-again.json", envelope,
                                   self.image_arm64)
        self.assertEqual(amd.status, IMPORTED)
        self.assertEqual(arm.status, IMPORTED)
        self.assertNotEqual(amd.evidence_id, arm.evidence_id)
        self.assertEqual(amd.matched_subjects, [1])
        self.assertEqual(arm.matched_subjects, [0])

    def test_untrusted_but_valid_evidence_is_kept(self):
        # 签名有效但策略不信任的证据照常入库，可查且标注原因
        statement = make_statement(self.image_amd64)
        result = self.import_statement("valid.json", statement,
                                       self.image_amd64)
        self.assertEqual(result.status, IMPORTED)
        from oci_catalog.provenance.queries import (
            REASON_NO_MATCHING_RULE,
            evaluate_evidence,
        )
        from provenance_fixtures import make_policy
        policy = self.load_policy(make_policy(
            ["key-a"], threshold=1, builder="https://builder.test/OTHER"))
        row = self.store.get_evidence(result.evidence_id)
        evaluation = evaluate_evidence(self.store, row, policy)
        self.assertEqual(evaluation.reason, REASON_NO_MATCHING_RULE)
        # 证据仍在库中，未被当成失败
        self.assertEqual(self.store.conn.execute(
            "SELECT COUNT(*) AS c FROM evidence").fetchone()["c"], 1)
        self.assertEqual(len(self.store.list_failures()), 0)


if __name__ == "__main__":
    unittest.main()
