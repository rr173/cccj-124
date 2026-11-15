"""DSSE 信封解析：结构、base64、重复键、PAE 与验签边界。"""

import base64
import json
import unittest

from provenance_fixtures import (
    CRYPTO_AVAILABLE,
    PAYLOAD_TYPE,
    fixture_pae,
    make_envelope,
    make_key,
    make_statement,
    public_bytes,
)

from oci_catalog.provenance.dsse import (
    DUPLICATE_JSON_KEY,
    EMPTY_SIGNATURES,
    INVALID_BASE64,
    INVALID_FIELD_TYPE,
    INVALID_JSON,
    INVALID_STRUCTURE,
    MISSING_FIELD,
    UNSUPPORTED_PAYLOAD_TYPE,
    ed25519_verify,
    pae,
    parse_envelope,
)


def envelope_bytes(**overrides):
    doc = {
        "payloadType": PAYLOAD_TYPE,
        "payload": base64.b64encode(b'{"_type":"x"}').decode("ascii"),
        "signatures": [{"keyid": "k", "sig": base64.b64encode(b"s").decode()}],
    }
    doc.update(overrides)
    return json.dumps(doc).encode("utf-8")


class TestEnvelopeStructure(unittest.TestCase):

    def test_valid_envelope_parses(self):
        parsed = parse_envelope(envelope_bytes())
        self.assertTrue(parsed.ok)
        self.assertEqual(parsed.payload_type, PAYLOAD_TYPE)
        self.assertEqual(parsed.payload, b'{"_type":"x"}')
        self.assertEqual(len(parsed.signatures), 1)
        self.assertEqual(parsed.signatures[0].keyid, "k")
        self.assertEqual(parsed.signatures[0].index, 0)

    def test_urlsafe_base64_accepted(self):
        payload = bytes(range(256)) * 3  # 产生 +/ 的字节序列
        std = base64.b64encode(payload).decode("ascii")
        # 确认语料在标准编码下确实含特殊字符，URL 安全编码与之不同
        self.assertTrue("+" in std or "/" in std)
        urlsafe = base64.urlsafe_b64encode(payload).decode("ascii")
        self.assertNotEqual(std, urlsafe)
        doc = {
            "payloadType": PAYLOAD_TYPE,
            "payload": urlsafe,
            "signatures": [{"sig": base64.urlsafe_b64encode(b"\xff\x00").decode()}],
        }
        parsed = parse_envelope(json.dumps(doc).encode())
        self.assertTrue(parsed.ok, parsed.diagnostics)
        self.assertEqual(parsed.payload, payload)
        self.assertEqual(parsed.signatures[0].sig, b"\xff\x00")

    def test_bad_base64_payload_rejected(self):
        for bad in ("not*base64", "abc", "====", "a=a="):
            parsed = parse_envelope(envelope_bytes(payload=bad))
            self.assertFalse(parsed.ok, bad)
            self.assertEqual(parsed.diagnostics[0].code, INVALID_BASE64)
            self.assertEqual(parsed.diagnostics[0].location, "$.payload")

    def test_bad_base64_signature_rejected(self):
        parsed = parse_envelope(envelope_bytes(
            signatures=[{"sig": "!!not-base64!!"}]))
        self.assertFalse(parsed.ok)
        self.assertEqual(parsed.diagnostics[0].code, INVALID_BASE64)
        self.assertEqual(parsed.diagnostics[0].location, "$.signatures[0].sig")

    def test_payload_type_must_be_in_toto(self):
        parsed = parse_envelope(envelope_bytes(payloadType="text/plain"))
        self.assertFalse(parsed.ok)
        codes = [d.code for d in parsed.diagnostics]
        self.assertIn(UNSUPPORTED_PAYLOAD_TYPE, codes)

    def test_missing_fields_located(self):
        parsed = parse_envelope(json.dumps({"payloadType": PAYLOAD_TYPE}).encode())
        self.assertFalse(parsed.ok)
        locations = {d.location for d in parsed.diagnostics}
        self.assertIn("$.payload", locations)
        self.assertIn("$.signatures", locations)

    def test_missing_sig_in_signature_entry(self):
        parsed = parse_envelope(envelope_bytes(signatures=[{"keyid": "k"}]))
        self.assertFalse(parsed.ok)
        self.assertEqual(parsed.diagnostics[0].code, MISSING_FIELD)
        self.assertEqual(parsed.diagnostics[0].location, "$.signatures[0].sig")

    def test_empty_signatures_rejected(self):
        parsed = parse_envelope(envelope_bytes(signatures=[]))
        self.assertFalse(parsed.ok)
        self.assertEqual(parsed.diagnostics[0].code, EMPTY_SIGNATURES)

    def test_non_object_envelope_rejected(self):
        parsed = parse_envelope(b"[1, 2, 3]")
        self.assertFalse(parsed.ok)
        self.assertEqual(parsed.diagnostics[0].code, INVALID_STRUCTURE)

    def test_invalid_json_rejected(self):
        parsed = parse_envelope(b"{not json")
        self.assertFalse(parsed.ok)
        self.assertEqual(parsed.diagnostics[0].code, INVALID_JSON)

    def test_non_utf8_rejected(self):
        parsed = parse_envelope(b"\xff\xfe{}")
        self.assertFalse(parsed.ok)
        self.assertEqual(parsed.diagnostics[0].code, INVALID_JSON)

    def test_duplicate_key_in_envelope_rejected(self):
        raw = (b'{"payloadType": "' + PAYLOAD_TYPE.encode() + b'", '
               b'"payloadType": "text/plain", "payload": "eA==", '
               b'"signatures": [{"sig": "eA=="}]}')
        parsed = parse_envelope(raw)
        self.assertFalse(parsed.ok)
        self.assertEqual(parsed.diagnostics[0].code, DUPLICATE_JSON_KEY)
        self.assertEqual(parsed.diagnostics[0].location, "$")

    def test_duplicate_key_nested_in_signatures_rejected(self):
        raw = (b'{"payloadType": "' + PAYLOAD_TYPE.encode() + b'", '
               b'"payload": "eA==", '
               b'"signatures": [{"sig": "eA==", "sig": "eQ=="}]}')
        parsed = parse_envelope(raw)
        self.assertFalse(parsed.ok)
        self.assertEqual(parsed.diagnostics[0].code, DUPLICATE_JSON_KEY)
        self.assertEqual(parsed.diagnostics[0].location, "$.signatures[0]")

    def test_keyid_wrong_type_rejected(self):
        parsed = parse_envelope(envelope_bytes(
            signatures=[{"keyid": 7, "sig": "eA=="}]))
        self.assertFalse(parsed.ok)
        self.assertEqual(parsed.diagnostics[0].code, INVALID_FIELD_TYPE)


class TestPAE(unittest.TestCase):

    def test_pae_exact_bytes(self):
        # PAE: DSSEv1 SP len(type) SP type SP len(payload) SP payload
        expected = (b"DSSEv1 28 application/vnd.in-toto+json 11 "
                    b"hello world")
        self.assertEqual(
            pae("application/vnd.in-toto+json", b"hello world"), expected)

    def test_pae_lengths_have_no_leading_zeros(self):
        result = pae("t", b"")
        self.assertEqual(result, b"DSSEv1 1 t 0 ")

    def test_pae_uses_utf8_length_of_type(self):
        # 类型含多字节字符时按 UTF-8 字节数计
        result = pae("类型", b"x")
        self.assertEqual(result, "DSSEv1 6 类型 1 x".encode("utf-8"))

    def test_fixture_pae_matches_production_pae(self):
        # 夹具独立实现与接入器实现必须一致（交叉验证，而非单方自证）
        payload = b'{"_type":"https://in-toto.io/Statement/v1"}'
        self.assertEqual(fixture_pae(PAYLOAD_TYPE, payload),
                         pae(PAYLOAD_TYPE, payload))


@unittest.skipUnless(CRYPTO_AVAILABLE, "需要 cryptography 包")
class TestEd25519Verify(unittest.TestCase):

    def test_verify_roundtrip_and_tamper(self):
        key = make_key("key-a")
        message = b"the message"
        sig = key.sign(message)
        self.assertTrue(ed25519_verify(public_bytes(key), message, sig))
        self.assertFalse(ed25519_verify(public_bytes(key), message + b" ", sig))
        other = make_key("key-b")
        self.assertFalse(ed25519_verify(public_bytes(other), message, sig))

    def test_malformed_signature_returns_false(self):
        key = make_key("key-a")
        self.assertFalse(ed25519_verify(public_bytes(key), b"m", b"short"))
        self.assertFalse(ed25519_verify(b"not-a-key", b"m", b"x" * 64))

    def test_envelope_signed_with_fixture_pae_verifies(self):
        # 夹具用独立 PAE 构造的信封，接入器必须能验出（编码一致性交叉验证）
        key = make_key("key-a")
        statement = make_statement("sha256:" + "ab" * 32)
        envelope = make_envelope(statement, [("key-a", key)])
        parsed = parse_envelope(envelope)
        self.assertTrue(parsed.ok, parsed.diagnostics)
        message = pae(parsed.payload_type, parsed.payload)
        self.assertTrue(ed25519_verify(public_bytes(key), message,
                                       parsed.signatures[0].sig))


if __name__ == "__main__":
    unittest.main()
