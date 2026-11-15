"""可重建的演示样例：三对测试密钥、供应商证明信封与三份信任策略。

密钥由固定种子派生（``sha256("...demo-key-x")`` 的 32 字节作为 Ed25519
私钥种子），每次运行得到完全相同的密钥对与指纹；**私钥只用于本地夹具**，
演示与测试之外不应出现。

签名夹具的独立性：本模块用自己的 ``_fixture_pae`` 构造 PAE、用
``cryptography`` 直接签名，**不调用**正式接入器（``dsse.pae`` 等）的编码
函数来制造预期——这样接入器编码出错时夹具能暴露问题，而不是自证自圆。

演示故事（与 run_provenance_demo.py 配合）：

* 两个平台镜像（amd64/arm64）各有一份供应商证明：同一构建者、同一构建
  类型、不同任务标识；amd64 信封由 key-a + key-b 签名，arm64 信封由
  key-b + key-c 签名；
* 两份声明登记同一个共享材料（URI 与摘要都相同）；另有一个**同 URI 不同
  摘要**的参考字典（amd64 与 arm64 各一版），用来验证反查不会串结果；
* amd64 声明里共享材料**完全重复出现两次**（位置 0 与 3），两处都保留；
* amd64 声明的 subject 列表首项是源码包，镜像摘要在**非首项**（位置 1），
  验证精确绑定不靠 subject 顺序；
* 策略 P1 授权 {key-a, key-b} 门槛 2：amd64 可信、arm64 只有一票不可信；
* 策略 P2 撤掉 key-a 改授权 {key-b, key-c} 门槛 2：amd64 不再通过，
  arm64 转为可信；
* 策略 P3 授权 {key-a, key-b, key-c} 门槛 2（另一组足够的授权）：两者
  都恢复可信。
"""

from __future__ import annotations

import base64
import hashlib
import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

# ---------------------------------------------------------------------------
# 常量：构建者 / 构建类型 / 任务标识（按原值处理，不做等价推断）
# ---------------------------------------------------------------------------
BUILDER_ID = "https://builder.example.com/offline-etl"
BUILD_TYPE = "https://buildtypes.example.com/offline-etl/v1"
INVOCATION_AMD64 = "etl-task-amd64-2026-11-01"
INVOCATION_ARM64 = "etl-task-arm64-2026-11-01"

PAYLOAD_TYPE = "application/vnd.in-toto+json"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "https://slsa.dev/provenance/v1"

# ---------------------------------------------------------------------------
# 材料坐标：摘要由固定内容算出，便于文档与验收脚本独立列出字面量
# ---------------------------------------------------------------------------
def _sha256_hex(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


SHARED_URI = "https://mirror.example.com/datasets/etl-input-2026.11.tar.gz"
SHARED_SHA256 = _sha256_hex(b"etl-input-2026.11 dataset bytes")

REF_URI = "https://mirror.example.com/datasets/reference-dict.csv"
REF_AMD64_SHA256 = _sha256_hex(b"reference-dict amd64 build")
REF_ARM64_SHA256 = _sha256_hex(b"reference-dict arm64 build")

TOOLCHAIN_URI = "https://mirror.example.com/toolchains/etl-builder-4.2.0.tar.gz"
TOOLCHAIN_SHA256 = _sha256_hex(b"etl-builder toolchain 4.2.0")

# amd64 声明中一个非镜像 subject（源码包），使镜像绑定落在非首项
SOURCE_BUNDLE_SHA256 = _sha256_hex(b"etl source bundle 2026.11")

# ---------------------------------------------------------------------------
# 三对确定性测试密钥（私钥仅用于本地夹具）
# ---------------------------------------------------------------------------
KEY_NAMES = ("key-a", "key-b", "key-c")


def _seed(name: str) -> bytes:
    return hashlib.sha256(f"oci-catalog-provenance-demo-{name}".encode()).digest()


def private_keys() -> dict[str, Ed25519PrivateKey]:
    """三对测试私钥（仅夹具使用）。"""
    return {name: Ed25519PrivateKey.from_private_bytes(_seed(name))
            for name in KEY_NAMES}


def public_keys() -> dict[str, bytes]:
    """三个 32 字节原始公钥。"""
    return {name: key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
            for name, key in private_keys().items()}


def key_fingerprints() -> dict[str, str]:
    """夹具侧独立计算的公钥指纹（sha256 of raw public bytes）。"""
    return {name: "sha256:" + hashlib.sha256(raw).hexdigest()
            for name, raw in public_keys().items()}


# ---------------------------------------------------------------------------
# 夹具侧 PAE 与签名（独立实现，不调用正式接入器的编码函数）
# ---------------------------------------------------------------------------
def _fixture_pae(payload_type: str, payload: bytes) -> bytes:
    type_bytes = payload_type.encode("utf-8")
    return (b"DSSEv1 " + str(len(type_bytes)).encode("ascii") + b" "
            + type_bytes + b" " + str(len(payload)).encode("ascii") + b" "
            + payload)


def _fixture_sign(payload: bytes, signer_names: list[str]) -> list[dict]:
    keys = private_keys()
    signatures = []
    for name in signer_names:
        sig = keys[name].sign(_fixture_pae(PAYLOAD_TYPE, payload))
        signatures.append({"keyid": name,
                           "sig": base64.b64encode(sig).decode("ascii")})
    return signatures


def _fixture_envelope(payload: bytes, signer_names: list[str],
                      urlsafe: bool = False) -> bytes:
    """构造信封 JSON 字节；urlsafe=True 时 payload 用 URL 安全 base64。"""
    if urlsafe:
        encoded = base64.urlsafe_b64encode(payload).decode("ascii")
    else:
        encoded = base64.b64encode(payload).decode("ascii")
    envelope = {
        "payloadType": PAYLOAD_TYPE,
        "payload": encoded,
        "signatures": _fixture_sign(payload, signer_names),
    }
    return json.dumps(envelope, indent=2).encode("utf-8")


# ---------------------------------------------------------------------------
# 供应商声明（statement）与信封
# ---------------------------------------------------------------------------
def statement_amd64(image_digest: str) -> dict:
    """amd64 镜像的 SLSA provenance：镜像摘要在 subject 非首项。"""
    return {
        "_type": STATEMENT_TYPE,
        "subject": [
            {"name": "etl-source-bundle",
             "digest": {"sha256": SOURCE_BUNDLE_SHA256}},
            {"name": "offline-etl/amd64",
             "digest": {"sha256": image_digest.split(":", 1)[1]}},
        ],
        "predicateType": PREDICATE_TYPE,
        "predicate": {
            "buildDefinition": {
                "buildType": BUILD_TYPE,
                "resolvedDependencies": [
                    {"uri": SHARED_URI, "digest": {"sha256": SHARED_SHA256}},
                    {"uri": REF_URI,
                     "digest": {"sha256": REF_AMD64_SHA256}},
                    {"uri": TOOLCHAIN_URI,
                     "digest": {"sha256": TOOLCHAIN_SHA256}},
                    # 完全重复的材料：两处出现都必须保留
                    {"uri": SHARED_URI, "digest": {"sha256": SHARED_SHA256}},
                ],
            },
            "runDetails": {
                "builder": {"id": BUILDER_ID},
                "metadata": {"invocationId": INVOCATION_AMD64},
            },
        },
    }


def statement_arm64(image_digest: str) -> dict:
    """arm64 镜像的 SLSA provenance：同 URI 的参考字典是另一摘要。"""
    return {
        "_type": STATEMENT_TYPE,
        "subject": [
            {"name": "offline-etl/arm64",
             "digest": {"sha256": image_digest.split(":", 1)[1]}},
        ],
        "predicateType": PREDICATE_TYPE,
        "predicate": {
            "buildDefinition": {
                "buildType": BUILD_TYPE,
                "resolvedDependencies": [
                    {"uri": SHARED_URI, "digest": {"sha256": SHARED_SHA256}},
                    {"uri": REF_URI,
                     "digest": {"sha256": REF_ARM64_SHA256}},
                ],
            },
            "runDetails": {
                "builder": {"id": BUILDER_ID},
                "metadata": {"invocationId": INVOCATION_ARM64},
            },
        },
    }


def envelope_amd64(image_digest: str) -> bytes:
    """amd64 供应商信封：标准 base64，key-a + key-b 签名。"""
    payload = json.dumps(statement_amd64(image_digest),
                         indent=2).encode("utf-8")
    return _fixture_envelope(payload, ["key-a", "key-b"], urlsafe=False)


def envelope_arm64(image_digest: str) -> bytes:
    """arm64 供应商信封：URL 安全 base64，key-b + key-c 签名。"""
    payload = json.dumps(statement_arm64(image_digest),
                         indent=2).encode("utf-8")
    return _fixture_envelope(payload, ["key-b", "key-c"], urlsafe=True)


# ---------------------------------------------------------------------------
# 三份信任策略
# ---------------------------------------------------------------------------
def _policy(authorized: list[str], rule_id: str) -> dict:
    keys = {name: raw.hex() for name, raw in public_keys().items()}
    return {
        "keys": keys,
        "rules": [{
            "id": rule_id,
            "builder_id": BUILDER_ID,
            "build_type": BUILD_TYPE,
            "authorized_keys": authorized,
            "threshold": 2,
        }],
    }


def policy_p1() -> dict:
    """P1：授权 {key-a, key-b} 门槛 2（amd64 可信，arm64 只有一票）。"""
    return _policy(["key-a", "key-b"], "etl-provenance-p1")


def policy_p2() -> dict:
    """P2：撤掉 key-a，授权 {key-b, key-c} 门槛 2（amd64 不再通过）。"""
    return _policy(["key-b", "key-c"], "etl-provenance-p2")


def policy_p3() -> dict:
    """P3：另一组足够的授权 {key-a, key-b, key-c} 门槛 2（两者都可信）。"""
    return _policy(["key-a", "key-b", "key-c"], "etl-provenance-p3")
