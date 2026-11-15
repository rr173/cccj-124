"""评价与查询：门槛计票、防误信断言与两类治理查询。"""

import json
import unittest

from provenance_fixtures import (
    BUILDER_ID,
    CRYPTO_AVAILABLE,
    ProvenanceFixture,
    make_envelope,
    make_policy,
    make_statement,
)

from oci_catalog.provenance.queries import (
    REASON_NO_MATCHING_RULE,
    REASON_NO_VALID_SIGNATURES,
    REASON_THRESHOLD_MET,
    REASON_THRESHOLD_NOT_MET,
    SIG_INVALID,
    SIG_UNKNOWN_SIGNER,
    SIG_VERIFIED,
    TRUSTED,
    UNTRUSTED,
    evaluate_evidence,
    query_image_provenance,
    query_material_images,
)

MAT_URI = "https://mirror.test/data.tar.gz"
MAT_SHA = "11" * 32


def materials(uri=MAT_URI, sha=MAT_SHA):
    return [{"uri": uri, "digest": {"sha256": sha}}]


@unittest.skipUnless(CRYPTO_AVAILABLE, "需要 cryptography 包")
class TestEvaluation(ProvenanceFixture):

    def evaluate(self, evidence_id, policy_doc):
        policy = self.load_policy(policy_doc)
        row = self.store.get_evidence(evidence_id)
        return evaluate_evidence(self.store, row, policy)

    def test_threshold_met_with_two_authorized_keys(self):
        result = self.import_statement("ok.json", make_statement(self.image_amd64),
                                       self.image_amd64)
        evaluation = self.evaluate(result.evidence_id,
                                   make_policy(["key-a", "key-b"]))
        self.assertEqual(evaluation.verdict, TRUSTED)
        self.assertEqual(evaluation.reason, REASON_THRESHOLD_MET)
        self.assertEqual(sorted(evaluation.counted_fingerprints),
                         sorted([self.fingerprints["key-a"],
                                 self.fingerprints["key-b"]]))
        self.assertTrue(all(s.counted for s in evaluation.signatures))

    def test_threshold_not_met_with_single_vote(self):
        result = self.import_statement(
            "one.json", make_statement(self.image_amd64), self.image_amd64,
            signer_names=("key-a",))
        evaluation = self.evaluate(result.evidence_id,
                                   make_policy(["key-a", "key-b"]))
        self.assertEqual(evaluation.verdict, UNTRUSTED)
        self.assertEqual(evaluation.reason, REASON_THRESHOLD_NOT_MET)
        self.assertEqual(evaluation.counted_fingerprints,
                         [self.fingerprints["key-a"]])

    def test_no_matching_rule(self):
        result = self.import_statement("x.json", make_statement(self.image_amd64),
                                       self.image_amd64)
        evaluation = self.evaluate(result.evidence_id, make_policy(
            ["key-a"], threshold=1, builder="https://builder.test/other"))
        self.assertEqual(evaluation.verdict, UNTRUSTED)
        self.assertEqual(evaluation.reason, REASON_NO_MATCHING_RULE)
        self.assertIsNone(evaluation.rule_id)

    def test_no_valid_signatures(self):
        # 签名被篡改（改 payload 空白后原签名不再成立）-> 签名不成立
        statement = make_statement(self.image_amd64)
        payload = json.dumps(statement, indent=2).encode()
        tampered = payload.replace(b'"_type":', b'"_type" :', 1)  # 合法 JSON 空白变化
        envelope = make_envelope(statement, self.signers("key-a", "key-b"),
                                 payload_override=tampered)
        result = self.import_envelope("tampered.json", envelope,
                                      self.image_amd64)
        self.assertEqual(result.status, "imported")  # 结构合法，照常入库
        evaluation = self.evaluate(result.evidence_id,
                                   make_policy(["key-a", "key-b"]))
        self.assertEqual(evaluation.verdict, UNTRUSTED)
        self.assertEqual(evaluation.reason, REASON_NO_VALID_SIGNATURES)
        self.assertTrue(all(s.status == SIG_INVALID
                            for s in evaluation.signatures))

    # ------------------------------------------------------------------
    # 防误信断言
    # ------------------------------------------------------------------
    def test_alias_and_duplicate_signature_cannot_sum_votes(self):
        # 同一公钥的两个别名 + 重复签名：独立票数仍为 1
        raw = self.publics["key-a"]
        statement = make_statement(self.image_amd64)
        envelope = make_envelope(statement, self.signers("key-a"))
        # 信封里再加一条同一私钥的重复签名（不同 keyid 提示）
        import json as _json
        doc = _json.loads(envelope)
        doc["signatures"].append(dict(doc["signatures"][0]))
        doc["signatures"][1]["keyid"] = "alias-2"
        envelope = _json.dumps(doc).encode()
        result = self.import_envelope("dup.json", envelope, self.image_amd64)
        self.assertEqual(result.signatures, 2)

        policy_doc = make_policy(["alias-1", "alias-2"], threshold=2,
                                 keys={"alias-1": raw, "alias-2": raw})
        # 门槛 2 > 独立公钥数 1：策略本身就必须在载入时被拒
        from oci_catalog.provenance.policy import PolicyError
        with self.assertRaises(PolicyError):
            self.load_policy(policy_doc)
        # 门槛 1 时两条重复签名也只算一票
        evaluation = self.evaluate(result.evidence_id, make_policy(
            ["alias-1", "alias-2"], threshold=1,
            keys={"alias-1": raw, "alias-2": raw}))
        self.assertEqual(evaluation.verdict, TRUSTED)
        self.assertEqual(len(evaluation.counted_fingerprints), 1)
        counted = [s for s in evaluation.signatures if s.counted]
        self.assertEqual(len(counted), 2)  # 两条签名同属一个已计指纹
        self.assertEqual(len({s.fingerprint for s in counted}), 1)

    def test_two_single_signature_envelopes_cannot_combine(self):
        # 两份内容相同但各只有一票的信封：各自评价，不能拼起来凑门槛
        statement = make_statement(self.image_amd64)
        env_a = make_envelope(statement, self.signers("key-a"))
        env_b = make_envelope(statement, self.signers("key-b"))
        ra = self.import_envelope("a.json", env_a, self.image_amd64)
        rb = self.import_envelope("b.json", env_b, self.image_amd64)
        self.assertNotEqual(ra.evidence_id, rb.evidence_id)
        policy_doc = make_policy(["key-a", "key-b"], threshold=2)
        for evidence_id in (ra.evidence_id, rb.evidence_id):
            evaluation = self.evaluate(evidence_id, policy_doc)
            self.assertEqual(evaluation.verdict, UNTRUSTED)
            self.assertEqual(evaluation.reason, REASON_THRESHOLD_NOT_MET)
            self.assertEqual(len(evaluation.counted_fingerprints), 1)

    def test_keyid_spoof_cannot_impersonate(self):
        # 有效签名的 keyid 改成另一名字：身份以验签为准，不能冒认
        statement = make_statement(self.image_amd64)
        envelope = make_envelope(statement, [("key-b", self.keys["key-a"])])
        result = self.import_envelope("spoof.json", envelope, self.image_amd64)
        # 策略只授权 key-b：实际签名者是 key-a，不得计入
        evaluation = self.evaluate(result.evidence_id, make_policy(
            ["key-b"], threshold=1))
        self.assertEqual(evaluation.verdict, UNTRUSTED)
        self.assertEqual(evaluation.reason, REASON_THRESHOLD_NOT_MET)
        self.assertEqual(evaluation.counted_fingerprints, [])
        report = evaluation.signatures[0]
        self.assertEqual(report.status, SIG_VERIFIED)
        self.assertEqual(report.fingerprint, self.fingerprints["key-a"])
        self.assertIn("不符", report.note)

    def test_payload_whitespace_change_breaks_signature(self):
        # 签名后改 payload 空白：验签失败（对原始字节验签，不重序列化）
        statement = make_statement(self.image_amd64)
        payload = json.dumps(statement, indent=2).encode()
        tampered = payload.replace(b'"_type":', b'"_type" :', 1)
        self.assertNotEqual(payload, tampered)
        envelope = make_envelope(statement, self.signers("key-a", "key-b"),
                                 payload_override=tampered)
        result = self.import_envelope("ws.json", envelope, self.image_amd64)
        evaluation = self.evaluate(result.evidence_id,
                                   make_policy(["key-a", "key-b"]))
        self.assertEqual(evaluation.verdict, UNTRUSTED)
        self.assertEqual(evaluation.reason, REASON_NO_VALID_SIGNATURES)

    def test_type_change_detected_at_import(self):
        # 签名后改 _type：结构校验拒绝（unsupported_statement_type）
        statement = make_statement(self.image_amd64)
        payload = json.dumps(statement).encode()
        tampered = payload.replace(
            b"https://in-toto.io/Statement/v1",
            b"https://in-toto.io/Statement/v2")
        envelope = make_envelope(statement, self.signers("key-a", "key-b"),
                                 payload_override=tampered)
        result = self.import_envelope("type.json", envelope, self.image_amd64)
        self.assertEqual(result.status, "failed")
        codes = [d.code for d in result.diagnostics]
        self.assertIn("unsupported_statement_type", codes)

    def test_subject_change_detected_as_binding_failure(self):
        # 签名后改 subject：绑定校验拒绝（不再有任何 subject 匹配镜像）
        statement = make_statement(self.image_amd64)
        payload = json.dumps(statement).encode()
        original_hex = self.image_amd64.split(":")[1]
        tampered = payload.replace(original_hex.encode(), b"ee" * 32)
        envelope = make_envelope(statement, self.signers("key-a", "key-b"),
                                 payload_override=tampered)
        result = self.import_envelope("subj.json", envelope, self.image_amd64)
        self.assertEqual(result.status, "failed")
        codes = [d.code for d in result.diagnostics]
        self.assertIn("binding_subject_mismatch", codes)

    def test_mixed_bad_and_good_signatures_pass(self):
        # 一个坏签名 + 足够好签名：按规则通过，坏签名留诊断
        statement = make_statement(self.image_amd64)
        envelope = make_envelope(statement, self.signers("key-a", "key-b"))
        doc = json.loads(envelope)
        doc["signatures"].append({"keyid": "key-c", "sig": "A" * 86 + "=="})
        envelope = json.dumps(doc).encode()
        result = self.import_envelope("mixed.json", envelope, self.image_amd64)
        evaluation = self.evaluate(result.evidence_id,
                                   make_policy(["key-a", "key-b"]))
        self.assertEqual(evaluation.verdict, TRUSTED)
        statuses = {s.index: s.status for s in evaluation.signatures}
        self.assertEqual(statuses[0], SIG_VERIFIED)
        self.assertEqual(statuses[1], SIG_VERIFIED)
        self.assertEqual(statuses[2], SIG_INVALID)  # keyid 指向已登记公钥但验不出

    def test_unknown_signer_diagnosed(self):
        statement = make_statement(self.image_amd64)
        envelope = make_envelope(statement, self.signers("key-a", "key-b"))
        doc = json.loads(envelope)
        doc["signatures"].append({"keyid": "ghost",
                                  "sig": "A" * 86 + "=="})
        result = self.import_envelope("ghost.json", json.dumps(doc).encode(),
                                      self.image_amd64)
        evaluation = self.evaluate(result.evidence_id,
                                   make_policy(["key-a", "key-b"]))
        self.assertEqual(evaluation.verdict, TRUSTED)
        ghost = next(s for s in evaluation.signatures if s.keyid == "ghost")
        self.assertEqual(ghost.status, SIG_UNKNOWN_SIGNER)

    def test_unauthorized_key_signature_not_counted(self):
        # key-c 已登记但未被规则授权：验出也不计票
        result = self.import_statement(
            "c.json", make_statement(self.image_amd64), self.image_amd64,
            signer_names=("key-a", "key-c"))
        evaluation = self.evaluate(result.evidence_id,
                                   make_policy(["key-a", "key-b"]))
        self.assertEqual(evaluation.verdict, UNTRUSTED)
        self.assertEqual(evaluation.reason, REASON_THRESHOLD_NOT_MET)
        self.assertEqual(evaluation.counted_fingerprints,
                         [self.fingerprints["key-a"]])
        by_keyid = {s.keyid: s for s in evaluation.signatures}
        self.assertEqual(by_keyid["key-c"].status, SIG_VERIFIED)
        self.assertFalse(by_keyid["key-c"].counted)


@unittest.skipUnless(CRYPTO_AVAILABLE, "需要 cryptography 包")
class TestQueries(ProvenanceFixture):

    def _import_amd64(self):
        statement = make_statement(
            self.image_amd64, invocation="task-amd64",
            materials=[{"uri": MAT_URI, "digest": {"sha256": MAT_SHA}},
                       {"uri": "https://mirror.test/other.tar.gz",
                        "digest": {"sha256": "22" * 32}},
                       {"uri": MAT_URI, "digest": {"sha256": MAT_SHA}}])
        return self.import_statement("amd64.json", statement,
                                     self.image_amd64)

    def test_image_provenance_report(self):
        result = self._import_amd64()
        policy = self.load_policy(make_policy(["key-a", "key-b"]))
        report = query_image_provenance(self.store, self.image_amd64, policy)
        self.assertEqual(report["platform"]["architecture"], "amd64")
        self.assertEqual(len(report["evidence"]), 1)
        entry = report["evidence"][0]
        self.assertEqual(entry["builder_id"], BUILDER_ID)
        self.assertEqual(entry["invocation_id"], "task-amd64")
        self.assertEqual(entry["bound_subject_indices"], [0])
        # 完全重复的材料两处出现都保留
        self.assertEqual([m["material_index"] for m in entry["materials"]],
                         [0, 1, 2])
        evaluation = entry["evaluation"]
        self.assertEqual(evaluation["verdict"], TRUSTED)
        self.assertEqual(sorted(evaluation["counted_fingerprints"]),
                         sorted([self.fingerprints["key-a"],
                                 self.fingerprints["key-b"]]))
        self.assertEqual(evaluation["policy_sha256"], policy.policy_sha256)

    def test_image_query_unknown_digest_raises(self):
        policy = self.load_policy(make_policy(["key-a", "key-b"]))
        with self.assertRaises(KeyError):
            query_image_provenance(self.store, "sha256:" + "00" * 32, policy)
        with self.assertRaises(ValueError):
            query_image_provenance(self.store, "not-a-digest", policy)

    def test_differing_statements_shown_side_by_side(self):
        # 同镜像两份相互不同的合法声明：逐份展示，不擅自认定最后导入的
        st1 = make_statement(self.image_amd64, invocation="task-1")
        st2 = make_statement(self.image_amd64, invocation="task-2",
                             materials=[{"uri": "https://mirror.test/v2",
                                         "digest": {"sha256": "33" * 32}}])
        self.import_statement("s1.json", st1, self.image_amd64)
        self.import_statement("s2.json", st2, self.image_amd64)
        policy = self.load_policy(make_policy(["key-a", "key-b"]))
        report = query_image_provenance(self.store, self.image_amd64, policy)
        self.assertEqual(len(report["evidence"]), 2)
        invocations = [e["invocation_id"] for e in report["evidence"]]
        self.assertEqual(invocations, ["task-1", "task-2"])  # 按导入序逐份展示
        self.assertIn("不证明镜像确实按声明执行过构建", report["note"])

    def test_material_reverse_lookup_exact_match(self):
        self._import_amd64()
        # arm64：同 URI 不同摘要
        statement_arm = make_statement(
            self.image_arm64, invocation="task-arm64",
            materials=materials(MAT_URI, "44" * 32))
        self.import_statement("arm64.json", statement_arm, self.image_arm64)
        policy = self.load_policy(make_policy(["key-a", "key-b"]))

        result = query_material_images(self.store, MAT_URI, MAT_SHA, policy)
        self.assertEqual(len(result["matches"]), 1)
        match = result["matches"][0]
        self.assertEqual(match["image_digest"], self.image_amd64)
        self.assertEqual(match["invocation_id"], "task-amd64")
        # 重复材料两处位置都带回
        self.assertEqual(match["material_positions"], [0, 2])

        # 同 URI 的另一摘要 -> 只命中 arm64，互不串结果
        other = query_material_images(self.store, MAT_URI, "44" * 32, policy)
        self.assertEqual([m["image_digest"] for m in other["matches"]],
                         [self.image_arm64])
        # 不存在的摘要 -> 空
        none = query_material_images(self.store, MAT_URI, "99" * 32, policy)
        self.assertEqual(none["matches"], [])

    def test_material_lookup_excludes_untrusted(self):
        self._import_amd64()
        # 未知构建者的证明：结构合法、签名有效，但策略无匹配规则
        statement = make_statement(
            self.image_arm64, builder="https://builder.test/unknown",
            materials=materials())
        self.import_statement("unknown-builder.json", statement,
                              self.image_arm64)
        policy = self.load_policy(make_policy(["key-a", "key-b"]))
        result = query_material_images(self.store, MAT_URI, MAT_SHA, policy)
        self.assertEqual([m["image_digest"] for m in result["matches"]],
                         [self.image_amd64])  # arm64 的未通过证明不混入

    def test_material_lookup_excludes_unauthorized_signer(self):
        self._import_amd64()
        statement = make_statement(self.image_arm64, materials=materials())
        # 只用未授权的 key-c 签名
        self.import_statement("c-only.json", statement, self.image_arm64,
                              signer_names=("key-c",))
        policy = self.load_policy(make_policy(["key-a", "key-b"]))
        result = query_material_images(self.store, MAT_URI, MAT_SHA, policy)
        self.assertEqual([m["image_digest"] for m in result["matches"]],
                         [self.image_amd64])

    def test_reevaluation_uses_current_policy_not_old_flags(self):
        result = self._import_amd64()
        p1 = self.load_policy(make_policy(["key-a", "key-b"]))
        p2 = self.load_policy(make_policy(["key-b", "key-c"]))
        row = self.store.get_evidence(result.evidence_id)
        first = evaluate_evidence(self.store, row, p1)
        self.assertEqual(first.verdict, TRUSTED)
        # 换策略重新评价：不沿用旧通过标志（key-a 授权被撤 -> 只剩一票）
        second = evaluate_evidence(self.store, row, p2)
        self.assertEqual(second.verdict, UNTRUSTED)
        self.assertEqual(second.reason, REASON_THRESHOLD_NOT_MET)
        self.assertEqual(second.counted_fingerprints,
                         [self.fingerprints["key-b"]])
        # 评价历史记录两次结论各自的策略摘要
        history = self.store.list_evaluations(result.evidence_id)
        self.assertEqual(len(history), 2)
        self.assertEqual(history[0]["policy_sha256"], p1.policy_sha256)
        self.assertEqual(history[0]["verdict"], TRUSTED)
        self.assertEqual(history[1]["policy_sha256"], p2.policy_sha256)
        self.assertEqual(history[1]["verdict"], UNTRUSTED)
        # 再换一组足够的授权恢复可信
        p3 = self.load_policy(make_policy(["key-a", "key-b", "key-c"]))
        third = evaluate_evidence(self.store, row, p3)
        self.assertEqual(third.verdict, TRUSTED)


if __name__ == "__main__":
    unittest.main()
