"""DSSE 信封解析、PAE 构造与 Ed25519 验签（密码运算全部委托 cryptography）。

支持的信封范围（明确边界，不声称兼容所有证明格式）：

* 顶层 JSON 对象含 ``payloadType``、``payload``（base64）与 ``signatures``
  列表；列表元素为对象，含可选 ``keyid`` 与必需 ``sig``（base64）；
* ``payloadType`` 必须为 ``application/vnd.in-toto+json``；
* base64 接受标准与 URL 安全字母表，要求正确填充；非法编码明确拒绝；
* 重复 JSON 键拒绝（见 :mod:`jsonutil`），``signatures`` 为空列表拒绝；
* 验签数据为 PAE（Pre-Authentication Encoding）::

      DSSEv1 <len(payloadType)> <payloadType> <len(payload)> <payload>

  其中 ``DSSEv1`` 为 ASCII 字节，长度是**无前导零的十进制 ASCII**，
  分隔符为单个空格；``payload`` 是 base64 解码后的**原始字节**——
  对解码后的原始 payload 验签，绝不把 JSON 重新序列化后验签。

Ed25519 验签使用 ``cryptography`` 库，本模块不自行实现任何密码算法。
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass, field

from .jsonutil import (
    Diagnostic,
    DuplicateKeyError,
    StrictJSONError,
    load_json,
)

#: 本接入器唯一支持的 payloadType
IN_TOTO_PAYLOAD_TYPE = "application/vnd.in-toto+json"

# 诊断错误码
INVALID_JSON = "invalid_json"
DUPLICATE_JSON_KEY = "duplicate_json_key"
INVALID_STRUCTURE = "invalid_structure"
MISSING_FIELD = "missing_field"
INVALID_FIELD_TYPE = "invalid_field_type"
UNSUPPORTED_PAYLOAD_TYPE = "unsupported_payload_type"
INVALID_BASE64 = "invalid_base64"
EMPTY_SIGNATURES = "empty_signatures"

# 标准与 URL 安全字母表的并集；填充符 = 至多两个且只在末尾
_B64_RE = re.compile(r"^[A-Za-z0-9+/\-_]*={0,2}$")


def b64decode_strict(text: object, location: str,
                     diagnostics: list[Diagnostic]) -> bytes | None:
    """严格 base64 解码（标准/URL 安全字母表、要求正确填充）。

    失败时向 ``diagnostics`` 追加 ``invalid_base64`` 诊断并返回 None；
    非法字符、错误填充、长度不合法都明确拒绝，绝不静默容错。
    """
    if not isinstance(text, str):
        diagnostics.append(Diagnostic(
            INVALID_FIELD_TYPE,
            f"期望 base64 字符串，实际类型 {type(text).__name__}", location))
        return None
    if not _B64_RE.fullmatch(text):
        diagnostics.append(Diagnostic(
            INVALID_BASE64,
            "base64 含字母表外字符或填充符位置非法（接受标准与 URL 安全"
            "字母表，填充符 = 至多两个且仅在末尾）", location))
        return None
    translated = text.replace("-", "+").replace("_", "/")
    try:
        return base64.b64decode(translated, validate=True)
    except (binascii.Error, ValueError) as exc:
        diagnostics.append(Diagnostic(
            INVALID_BASE64, f"base64 编码非法: {exc}", location))
        return None


def pae(payload_type: str, payload: bytes) -> bytes:
    """构造 PAE（Pre-Authentication Encoding）验签数据。

    ``DSSEv1`` 空格 ``len(payloadType)`` 空格 ``payloadType`` 空格
    ``len(payload)`` 空格 ``payload``；两个长度都是无前导零的十进制
    ASCII，分别按 payloadType 的 UTF-8 字节数与 payload 原始字节数计算。
    """
    type_bytes = payload_type.encode("utf-8")
    return b" ".join([
        b"DSSEv1",
        str(len(type_bytes)).encode("ascii"),
        type_bytes,
        str(len(payload)).encode("ascii"),
        payload,
    ])


def ed25519_verify(public_key_bytes: bytes, message: bytes,
                   signature: bytes) -> bool:
    """用 32 字节原始 Ed25519 公钥验签；任何失败都返回 False（不抛出）。

    ``cryptography`` 在此惰性导入：未安装时只有真正验签的调用才报错，
    不影响本子系统其他纯解析能力与项目其余子系统。
    """
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PublicKey,
        )
    except ImportError as exc:  # pragma: no cover - 环境缺依赖时明确报错
        raise RuntimeError(
            "Ed25519 验签需要 cryptography 包（pip install cryptography）；"
            "本项目不自行实现密码算法") from exc
    try:
        key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
        key.verify(signature, message)
        return True
    except (InvalidSignature, ValueError):
        return False


@dataclass(frozen=True)
class Signature:
    """信封中的一条签名（保留列表原位置）。"""

    index: int                 # 在 signatures 列表中的位置
    keyid: str | None          # 可选提示；绝不作为身份结论依据
    sig: bytes                 # base64 解码后的签名原始字节

    def to_dict(self) -> dict:
        return {"index": self.index, "keyid": self.keyid,
                "sig_hex": self.sig.hex()}


@dataclass
class ParsedEnvelope:
    """信封解析结果：成功时各字段齐备；诊断非空即失败。"""

    payload_type: str | None = None
    payload: bytes | None = None          # base64 解码后的原始 payload 字节
    signatures: list[Signature] = field(default_factory=list)
    diagnostics: list[Diagnostic] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.diagnostics


def parse_envelope(raw_bytes: bytes) -> ParsedEnvelope:
    """解析 DSSE 信封原始字节；所有结构问题以诊断返回，不抛出。"""
    parsed = ParsedEnvelope()
    diagnostics = parsed.diagnostics

    try:
        doc = load_json(raw_bytes)
    except StrictJSONError as exc:
        diagnostics.append(Diagnostic(INVALID_JSON, str(exc), "$"))
        return parsed
    except DuplicateKeyError as exc:
        diagnostics.append(Diagnostic(
            DUPLICATE_JSON_KEY,
            f"信封含重复 JSON 键 {exc.key!r}（拒绝后值覆盖前值）", exc.path))
        return parsed

    if not isinstance(doc, dict):
        diagnostics.append(Diagnostic(
            INVALID_STRUCTURE, "信封顶层必须是 JSON 对象", "$"))
        return parsed

    # payloadType
    payload_type = doc.get("payloadType")
    if "payloadType" not in doc:
        diagnostics.append(Diagnostic(
            MISSING_FIELD, "缺少必需字段 payloadType", "$.payloadType"))
    elif not isinstance(payload_type, str):
        diagnostics.append(Diagnostic(
            INVALID_FIELD_TYPE,
            f"payloadType 必须是字符串，实际 {type(payload_type).__name__}",
            "$.payloadType"))
    elif payload_type != IN_TOTO_PAYLOAD_TYPE:
        diagnostics.append(Diagnostic(
            UNSUPPORTED_PAYLOAD_TYPE,
            f"payloadType 必须是 {IN_TOTO_PAYLOAD_TYPE!r}，"
            f"实际 {payload_type!r}", "$.payloadType"))
    else:
        parsed.payload_type = payload_type

    # payload（base64）
    if "payload" not in doc:
        diagnostics.append(Diagnostic(
            MISSING_FIELD, "缺少必需字段 payload", "$.payload"))
    else:
        decoded = b64decode_strict(doc.get("payload"), "$.payload", diagnostics)
        if decoded is not None:
            parsed.payload = decoded

    # signatures
    if "signatures" not in doc:
        diagnostics.append(Diagnostic(
            MISSING_FIELD, "缺少必需字段 signatures", "$.signatures"))
        return parsed
    signatures = doc["signatures"]
    if not isinstance(signatures, list):
        diagnostics.append(Diagnostic(
            INVALID_FIELD_TYPE,
            f"signatures 必须是列表，实际 {type(signatures).__name__}",
            "$.signatures"))
        return parsed
    if not signatures:
        diagnostics.append(Diagnostic(
            EMPTY_SIGNATURES,
            "signatures 为空列表：没有任何可验签的签名，"
            "对本接入器属于结构不完整", "$.signatures"))
        return parsed
    for index, entry in enumerate(signatures):
        location = f"$.signatures[{index}]"
        if not isinstance(entry, dict):
            diagnostics.append(Diagnostic(
                INVALID_STRUCTURE,
                f"签名项必须是对象，实际 {type(entry).__name__}", location))
            continue
        keyid = entry.get("keyid")
        if keyid is not None and not isinstance(keyid, str):
            diagnostics.append(Diagnostic(
                INVALID_FIELD_TYPE,
                f"keyid 若提供必须是字符串，实际 {type(keyid).__name__}",
                f"{location}.keyid"))
            continue
        if "sig" not in entry:
            diagnostics.append(Diagnostic(
                MISSING_FIELD, "签名项缺少必需字段 sig", f"{location}.sig"))
            continue
        sig = b64decode_strict(entry["sig"], f"{location}.sig", diagnostics)
        if sig is None:
            continue
        parsed.signatures.append(Signature(index=index, keyid=keyid, sig=sig))
    return parsed
