"""摘要（digest）工具：按 OCI/Docker 规范对 manifest 内容做 SHA-256 摘要。

摘要格式遵循 OCI Digest Specification：``algorithm:encoded``，本项目只支持
``sha256``。摘要寻址的内容天然不可变，digest 同时承担内容身份的角色。
"""

from __future__ import annotations

import hashlib

SUPPORTED_ALGORITHMS = frozenset({"sha256"})


class DigestError(ValueError):
    """digest 字符串非法或使用了不支持的算法。"""


def parse_digest(value: str) -> tuple[str, str]:
    """把 ``algorithm:encoded`` 拆成 (algorithm, encoded)，并做基本校验。"""
    if not value or ":" not in value:
        raise DigestError(f"非法 digest: {value!r}")
    algorithm, _, encoded = value.partition(":")
    if algorithm not in SUPPORTED_ALGORITHMS:
        raise DigestError(f"不支持的摘要算法: {algorithm!r}")
    if not encoded:
        raise DigestError(f"digest 缺少编码部分: {value!r}")
    return algorithm, encoded


def validate_digest(value: str) -> str:
    """校验 digest 字符串格式，原样返回。"""
    parse_digest(value)
    return value


def sha256_digest(data: bytes) -> str:
    """对原始字节计算 ``sha256:<hex>`` 摘要。"""
    return "sha256:" + hashlib.sha256(data).hexdigest()


def matches(data: bytes, expected: str) -> bool:
    """计算 ``data`` 的摘要并与期望 digest 比较（恒定时间比较）。"""
    import hmac

    try:
        algorithm, _ = parse_digest(expected)
    except DigestError:
        return False
    if algorithm != "sha256":
        return False
    return hmac.compare_digest(sha256_digest(data), expected)
