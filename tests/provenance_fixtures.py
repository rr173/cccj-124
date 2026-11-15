"""构建证明测试共享 fixture：内存目录库 + 确定性测试密钥 + 信封构造助手。

签名夹具用自己的 ``fixture_pae`` 构造 PAE、用 ``cryptography`` 直接签名，
不调用正式接入器（``oci_catalog.provenance.dsse.pae``）的编码函数来制造
预期，保证接入器编码错误能被测试暴露。
"""

import base64
import hashlib
import json
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:  # 密码运算依赖 cryptography；缺失时相关测试整体跳过
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
    )
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        PublicFormat,
    )
    CRYPTO_AVAILABLE = True
except ImportError:  # pragma: no cover
    Ed25519PrivateKey = None
    CRYPTO_AVAILABLE = False

from oci_catalog import (
    CatalogStore,
    Collector,
    FakeRegistry,
    RegistryClient,
    make_image_manifest,
    make_index_manifest,
)
from oci_catalog.provenance.store import ProvenanceStore

IMAGE_MEDIA = "application/vnd.oci.image.manifest.v1+json"
INDEX_MEDIA = "application/vnd.oci.image.index.v1+json"

PAYLOAD_TYPE = "application/vnd.in-toto+json"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "https://slsa.dev/provenance/v1"

BUILDER_ID = "https://builder.test/offline-etl"
BUILD_TYPE = "https://buildtypes.test/offline-etl/v1"

KEY_NAMES = ("key-a", "key-b", "key-c")


def fixture_pae(payload_type: str, payload: bytes) -> bytes:
    """夹具侧独立 PAE 实现（不调用正式接入器）。"""
    type_bytes = payload_type.encode("utf-8")
    return (b"DSSEv1 " + str(len(type_bytes)).encode("ascii") + b" "
            + type_bytes + b" " + str(len(payload)).encode("ascii") + b" "
            + payload)


def make_key(name: str):
    seed = hashlib.sha256(f"provenance-test-{name}".encode()).digest()
    return Ed25519PrivateKey.from_private_bytes(seed)


def public_bytes(key) -> bytes:
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def fingerprint_of(public: bytes) -> str:
    return "sha256:" + hashlib.sha256(public).hexdigest()


def make_statement(image_digest: str, *, builder=BUILDER_ID,
                   build_type=BUILD_TYPE, invocation="task-1",
                   materials=None, extra_subjects=None) -> dict:
    if materials is None:
        materials = [{"uri": "https://mirror.test/data.tar.gz",
                      "digest": {"sha256": "11" * 32}}]
    subjects = list(extra_subjects or [])
    subjects.append({"name": "img",
                     "digest": {"sha256": image_digest.split(":", 1)[1]}})
    return {
        "_type": STATEMENT_TYPE,
        "subject": subjects,
        "predicateType": PREDICATE_TYPE,
        "predicate": {
            "buildDefinition": {
                "buildType": build_type,
                "resolvedDependencies": materials,
            },
            "runDetails": {
                "builder": {"id": builder},
                "metadata": {"invocationId": invocation},
            },
        },
    }


def make_envelope(statement: dict, signers: list[tuple[str, "Ed25519PrivateKey"]],
                  *, payload_type: str = PAYLOAD_TYPE,
                  urlsafe: bool = False,
                  payload_override: bytes | None = None) -> bytes:
    """用夹具 PAE 直接签名构造信封字节。

    ``signers`` 为 [(keyid, 私钥), ...]；keyid 可任意（用于伪造提示的
    测试）。``payload_override`` 模拟“签名后改 payload”：签名始终针对
    ``statement`` 的原始序列化，信封里嵌入的却是 ``payload_override``。
    """
    signed_payload = json.dumps(statement, indent=2).encode("utf-8")
    envelope_payload = payload_override if payload_override is not None \
        else signed_payload
    signatures = []
    for keyid, key in signers:
        sig = key.sign(fixture_pae(payload_type, signed_payload))
        signatures.append({"keyid": keyid,
                           "sig": base64.b64encode(sig).decode("ascii")})
    if urlsafe:
        encoded = base64.urlsafe_b64encode(envelope_payload).decode("ascii")
    else:
        encoded = base64.b64encode(envelope_payload).decode("ascii")
    envelope = {"payloadType": payload_type, "payload": encoded,
                "signatures": signatures}
    return json.dumps(envelope, indent=2).encode("utf-8")


def make_policy(authorized: list[str], *, threshold: int = 2,
                builder=BUILDER_ID, build_type=BUILD_TYPE,
                keys: dict[str, bytes] | None = None,
                rule_id: str = "rule-1") -> dict:
    if keys is None:
        keys = {name: public_bytes(make_key(name)) for name in KEY_NAMES}
    return {
        "keys": {name: raw.hex() for name, raw in keys.items()},
        "rules": [{
            "id": rule_id, "builder_id": builder, "build_type": build_type,
            "authorized_keys": authorized, "threshold": threshold,
        }],
    }


class ProvenanceFixture(unittest.TestCase):
    """两个平台 image + 一个 index 的目录库，以及空证明库与测试密钥。"""

    def setUp(self):
        self.registry = FakeRegistry(auth_enabled=False, default_page_size=10)
        self.base_url = self.registry.start()
        self.tmpdir = tempfile.mkdtemp(prefix="prov-test-")
        self.catalog_db = os.path.join(self.tmpdir, "catalog.db")
        self.prov_db = os.path.join(self.tmpdir, "provenance.db")

        self.registry.put_manifest(
            "img/amd64",
            make_image_manifest("sha256:" + "c1" * 32,
                                ["sha256:" + "d1" * 32]),
            IMAGE_MEDIA, tag="v1")
        self.image_amd64 = next(
            iter(self.registry.repos["img/amd64"].manifests.keys()))
        self.registry.put_manifest(
            "img/arm64",
            make_image_manifest("sha256:" + "c2" * 32,
                                ["sha256:" + "d2" * 32]),
            IMAGE_MEDIA, tag="v1")
        self.image_arm64 = next(
            iter(self.registry.repos["img/arm64"].manifests.keys()))
        self.index_digest = self.registry.put_manifest(
            "img/amd64",
            make_index_manifest([
                (self.image_amd64, IMAGE_MEDIA,
                 {"architecture": "amd64", "os": "linux"}),
                (self.image_arm64, IMAGE_MEDIA,
                 {"architecture": "arm64", "os": "linux", "variant": "v8"}),
            ]), INDEX_MEDIA, tag="multi")

        self.catalog = CatalogStore(self.catalog_db)
        collector = Collector(RegistryClient(self.base_url), self.catalog,
                              registry_name=self.base_url)
        report = collector.run()
        assert report.status == "completed"
        self.catalog.close()

        self.keys = {name: make_key(name) for name in KEY_NAMES}
        self.publics = {name: public_bytes(key)
                        for name, key in self.keys.items()}
        self.fingerprints = {name: fingerprint_of(raw)
                             for name, raw in self.publics.items()}

        self.store = ProvenanceStore(self.prov_db, self.catalog_db)

    def tearDown(self):
        self.store.close()
        self.registry.stop()
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    # -- 辅助 ---------------------------------------------------------------
    def signers(self, *names: str) -> list[tuple[str, Ed25519PrivateKey]]:
        return [(name, self.keys[name]) for name in names]

    def import_envelope(self, name: str, envelope: bytes, digest: str):
        path = os.path.join(self.tmpdir, name)
        with open(path, "wb") as fh:
            fh.write(envelope)
        return self.store.import_file(path, digest, envelope)

    def import_statement(self, name: str, statement: dict, digest: str,
                         signer_names=("key-a", "key-b")):
        envelope = make_envelope(statement, self.signers(*signer_names))
        return self.import_envelope(name, envelope, digest)

    def load_policy(self, policy: dict):
        from oci_catalog.provenance.policy import load_policy
        return load_policy(json.dumps(policy).encode("utf-8"))
