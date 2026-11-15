"""信任策略：载入校验、别名去重、规则冲突与门槛约束。"""

import json
import unittest

from provenance_fixtures import (
    BUILDER_ID,
    BUILD_TYPE,
    CRYPTO_AVAILABLE,
    KEY_NAMES,
    make_key,
    make_policy,
    public_bytes,
)

from oci_catalog.provenance.policy import (
    DUPLICATE_JSON_KEY,
    DUPLICATE_RULE_ID,
    INVALID_KEY_ENCODING,
    INVALID_THRESHOLD,
    MISSING_FIELD,
    PolicyError,
    RULE_CONFLICT,
    THRESHOLD_EXCEEDS_KEYS,
    UNKNOWN_KEY,
    key_fingerprint,
    load_policy,
)


def policy_bytes(policy: dict) -> bytes:
    return json.dumps(policy).encode("utf-8")


@unittest.skipUnless(CRYPTO_AVAILABLE, "需要 cryptography 包")
class TestPolicyLoading(unittest.TestCase):

    def setUp(self):
        self.publics = {name: public_bytes(make_key(name))
                        for name in KEY_NAMES}

    def test_valid_policy_loads(self):
        policy = load_policy(policy_bytes(make_policy(["key-a", "key-b"])))
        self.assertEqual(len(policy.keys), 3)
        self.assertEqual(len(policy.rules), 1)
        rule = policy.find_rule(BUILDER_ID, BUILD_TYPE)
        self.assertIsNotNone(rule)
        self.assertEqual(rule.threshold, 2)
        self.assertEqual(len(rule.authorized_fingerprints), 2)
        self.assertTrue(policy.policy_sha256.startswith("sha256:"))

    def test_hex_and_base64_key_encodings(self):
        raw = self.publics["key-a"]
        import base64
        policy_doc = {
            "keys": {
                "hex-key": raw.hex(),
                "b64-key": base64.b64encode(raw).decode("ascii"),
                "b64url-key": base64.urlsafe_b64encode(raw).decode("ascii"),
            },
            "rules": [{
                "id": "r", "builder_id": "b", "build_type": "t",
                "authorized_keys": ["hex-key"], "threshold": 1,
            }],
        }
        policy = load_policy(policy_bytes(policy_doc))
        # 三种写法解出同一公钥字节 -> 同一指纹（别名）
        self.assertEqual(len(policy.distinct_fingerprints), 1)
        self.assertEqual(policy.names_for_fingerprint(
            key_fingerprint(raw)), ["b64-key", "b64url-key", "hex-key"])

    def test_bad_key_encoding_rejected(self):
        policy_doc = make_policy(["key-a"])
        policy_doc["keys"]["bad"] = "not-a-key"
        with self.assertRaises(PolicyError) as ctx:
            load_policy(policy_bytes(policy_doc))
        codes = [d.code for d in ctx.exception.diagnostics]
        self.assertIn(INVALID_KEY_ENCODING, codes)

    def test_unknown_key_in_rule_rejected(self):
        policy_doc = make_policy(["key-a", "ghost-key"])
        with self.assertRaises(PolicyError) as ctx:
            load_policy(policy_bytes(policy_doc))
        diag = next(d for d in ctx.exception.diagnostics
                    if d.code == UNKNOWN_KEY)
        self.assertIn("ghost-key", diag.message)

    def test_rule_conflict_rejected(self):
        policy_doc = make_policy(["key-a"], threshold=1)
        policy_doc["rules"].append({
            "id": "rule-2", "builder_id": BUILDER_ID,
            "build_type": BUILD_TYPE, "authorized_keys": ["key-b"],
            "threshold": 1,
        })
        with self.assertRaises(PolicyError) as ctx:
            load_policy(policy_bytes(policy_doc))
        self.assertIn(RULE_CONFLICT,
                      [d.code for d in ctx.exception.diagnostics])

    def test_same_pair_different_rule_id_is_conflict(self):
        # 规则 ID 不同但 (builder_id, build_type) 相同仍是冲突
        policy_doc = make_policy(["key-a"], rule_id="r1", threshold=1)
        policy_doc["rules"].append({
            "id": "r2", "builder_id": BUILDER_ID, "build_type": BUILD_TYPE,
            "authorized_keys": ["key-a"], "threshold": 1,
        })
        with self.assertRaises(PolicyError) as ctx:
            load_policy(policy_bytes(policy_doc))
        codes = [d.code for d in ctx.exception.diagnostics]
        self.assertIn(RULE_CONFLICT, codes)

    def test_duplicate_rule_id_rejected(self):
        policy_doc = make_policy(["key-a"], rule_id="same", threshold=1)
        policy_doc["rules"].append({
            "id": "same", "builder_id": "other-builder",
            "build_type": "other-type", "authorized_keys": ["key-a"],
            "threshold": 1,
        })
        with self.assertRaises(PolicyError) as ctx:
            load_policy(policy_bytes(policy_doc))
        self.assertIn(DUPLICATE_RULE_ID,
                      [d.code for d in ctx.exception.diagnostics])

    def test_threshold_must_be_positive_integer(self):
        for bad in (0, -1, 1.5, "2", True):
            policy_doc = make_policy(["key-a"], threshold=bad)
            with self.assertRaises(PolicyError, msg=repr(bad)):
                load_policy(policy_bytes(policy_doc))

    def test_threshold_exceeds_distinct_keys_rejected(self):
        # 同一公钥登记两个名字：独立公钥数只有 1，门槛 2 必须在载入时报错
        raw = self.publics["key-a"]
        policy_doc = make_policy(
            ["alias-1", "alias-2"], threshold=2,
            keys={"alias-1": raw, "alias-2": raw})
        with self.assertRaises(PolicyError) as ctx:
            load_policy(policy_bytes(policy_doc))
        diag = next(d for d in ctx.exception.diagnostics
                    if d.code == THRESHOLD_EXCEEDS_KEYS)
        self.assertIn("别名", diag.message)

    def test_threshold_exceeds_registered_keys_rejected(self):
        policy_doc = make_policy(["key-a"], threshold=2)
        with self.assertRaises(PolicyError) as ctx:
            load_policy(policy_bytes(policy_doc))
        self.assertIn(THRESHOLD_EXCEEDS_KEYS,
                      [d.code for d in ctx.exception.diagnostics])

    def test_alias_counts_as_one_signer(self):
        raw = self.publics["key-a"]
        policy = load_policy(policy_bytes(make_policy(
            ["alias-1", "alias-2"], threshold=1,
            keys={"alias-1": raw, "alias-2": raw})))
        rule = policy.rules[0]
        self.assertEqual(len(rule.authorized_fingerprints), 1)
        self.assertEqual(len(rule.authorized_names), 2)

    def test_duplicate_names_in_rule_collapse(self):
        policy = load_policy(policy_bytes(make_policy(
            ["key-a", "key-a", "key-b"], threshold=2)))
        rule = policy.rules[0]
        self.assertEqual(rule.authorized_names, ("key-a", "key-b"))

    def test_duplicate_json_key_in_policy_rejected(self):
        raw = (b'{"keys": {}, "keys": {}, "rules": []}')
        with self.assertRaises(PolicyError) as ctx:
            load_policy(raw)
        self.assertEqual(ctx.exception.diagnostics[0].code,
                         DUPLICATE_JSON_KEY)
        self.assertEqual(ctx.exception.diagnostics[0].location, "$")

    def test_missing_sections_located(self):
        with self.assertRaises(PolicyError) as ctx:
            load_policy(b"{}")
        locations = {d.location for d in ctx.exception.diagnostics}
        self.assertIn("$.keys", locations)
        self.assertIn("$.rules", locations)

    def test_canonical_digest_stable_across_formatting(self):
        policy_doc = make_policy(["key-a", "key-b"])
        compact = json.dumps(policy_doc, separators=(",", ":")).encode()
        pretty = json.dumps(policy_doc, indent=4, sort_keys=True).encode()
        # 键序不同但内容相同 -> 摘要相同
        shuffled = dict(reversed(list(policy_doc.items())))
        shuffled_raw = json.dumps(shuffled).encode()
        p1 = load_policy(compact)
        p2 = load_policy(pretty)
        p3 = load_policy(shuffled_raw)
        self.assertEqual(p1.policy_sha256, p2.policy_sha256)
        self.assertEqual(p1.policy_sha256, p3.policy_sha256)

    def test_different_ruleset_different_digest(self):
        p1 = load_policy(policy_bytes(make_policy(["key-a", "key-b"])))
        p2 = load_policy(policy_bytes(make_policy(["key-b", "key-c"])))
        self.assertNotEqual(p1.policy_sha256, p2.policy_sha256)


if __name__ == "__main__":
    unittest.main()
