"""Package URL（purl）解析与规范化。

purl 是跨两种清单格式的**可合并坐标**：只有带合法 purl 的组件才能建立全局
归一化身份；没有 purl 的组件只保留文件内身份（bom-ref / SPDXID），绝不从
名称与版本臆造 purl。

支持范围（超出范围即报 :class:`PurlError`，作为坏坐标诊断）：

* 类型：``generic``、``pypi``、``npm``（大小写不敏感，统一归一为小写）；
* 语法遵循 Package URL Spec v1（``pkg:type/namespace/name@version?qualifiers#subpath``）；
* 各段必须是合法的百分号编码（``%`` 后必须跟两个十六进制位），解码后再按
  规范字符集重新编码；
* qualifiers：键名按字母序排列，值规范化后百分号编码；重复键为非法；
* 子路径（subpath）与版本、qualifier 一样属于身份的一部分，参与区分；
* PyPI 名称按 PEP 503 归一：``re.sub(r"[-_.]+", "-", name).lower()``，
  即连字符/下划线/点的连续组合统一为单个连字符并转小写；
* npm：scope（namespace 第一段）按 npm 包名规则转小写；包名本体保留大小写，
  不会把仅大小写不同的两个名字合并；带编码字符的名称先解码再规范编码。

两个 purl 当且仅当规范化字符串完全相同时指向同一个组件身份。因此：

* 同名不同版本、不同 qualifiers、不同 subpath 不会被合并；
* npm scope 不同不会被合并；
* 类型不同不会被合并（即使名称相同）。
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import quote, unquote

SUPPORTED_PURL_TYPES = frozenset({"generic", "pypi", "npm"})

# purl 各段规范字符集（与 Package URL spec 的 "should not be percent-encoded"
# 集合一致）：字母数字及少量符号原样保留，其余一律百分号编码。
_SEGMENT_SAFE = ".-_~"
_QUALIFIER_KEY_RE = re.compile(r"^[a-zA-Z0-9._-]+$")
_PYPI_NORMALIZE_RE = re.compile(r"[-_.]+")
_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")


class PurlError(ValueError):
    """purl 字符串非法或落在支持范围之外。"""


def _decode_verified(value: str, what: str) -> str:
    """解码百分号编码，并拒绝裸 ``%`` 与残缺转义序列。"""
    if "%" in value:
        for idx, ch in enumerate(value):
            if ch == "%" and (
                idx + 2 >= len(value)
                or value[idx + 1] not in _HEX_DIGITS
                or value[idx + 2] not in _HEX_DIGITS
            ):
                raise PurlError(f"{what} 含非法百分号编码: {value!r}")
    return unquote(value)


def _encode_segment(value: str) -> str:
    return quote(value, safe=_SEGMENT_SAFE)


def _encode_namespace(namespace: str) -> str:
    # namespace 按 '/' 分段编码，分隔符本身保留
    return "/".join(_encode_segment(part) for part in namespace.split("/"))


def _encode_subpath(subpath: str) -> str:
    # subpath 同样按 '/' 分段；"." 与 ".." 段在语义上无意义，视为非法
    parts = subpath.split("/")
    for part in parts:
        if part in (".", "..", ""):
            raise PurlError(f"purl subpath 含非法段: {subpath!r}")
    return "/".join(_encode_segment(part) for part in parts)


@dataclass(frozen=True)
class Purl:
    """规范化后的 purl 坐标（不可变值对象）。"""

    type: str
    name: str
    namespace: tuple[str, ...] = ()
    version: str | None = None
    # qualifiers 保持为已排序的 (key, value) 元组序列，值为解码后的原文
    qualifiers: tuple[tuple[str, str], ...] = ()
    subpath: str | None = None

    @property
    def canonical(self) -> str:
        """规范化 purl 字符串，同时作为组件身份键。"""
        text = "pkg:" + self.type + "/"
        if self.namespace:
            text += "/".join(_encode_segment(p) for p in self.namespace) + "/"
        text += _encode_segment(self.name)
        if self.version is not None:
            text += "@" + _encode_segment(self.version)
        if self.qualifiers:
            pairs = "&".join(
                f"{key}={quote(value, safe=_SEGMENT_SAFE)}"
                for key, value in self.qualifiers
            )
            text += "?" + pairs
        if self.subpath is not None:
            text += "#" + _encode_subpath(self.subpath)
        return text

    def __str__(self) -> str:
        return self.canonical


def parse_purl(raw: str) -> Purl:
    """把原始 purl 字符串解析为规范化 :class:`Purl`。

    任何语法错误、非法编码、不支持的类型都会抛 :class:`PurlError`，
    由调用方转换为带文件位置的诊断。
    """
    if not isinstance(raw, str) or not raw:
        raise PurlError("purl 为空或不是字符串")
    if not raw.startswith("pkg:"):
        raise PurlError(f"purl 必须以 'pkg:' 开头: {raw!r}")

    remainder = raw[len("pkg:"):]

    # 1. 依次切出 subpath（#）、qualifiers（?）、version（@，最后一个 @）
    subpath: str | None = None
    if "#" in remainder:
        remainder, _, subpath_raw = remainder.partition("#")
        subpath_decoded = _decode_verified(subpath_raw, "purl subpath")
        subpath = _encode_subpath(subpath_decoded)

    qualifiers_raw: str | None = None
    if "?" in remainder:
        remainder, _, qualifiers_raw = remainder.partition("?")

    version: str | None = None
    if "@" in remainder:
        # namespace/name 段内不允许出现未编码的 @，取最后一个切分点即可
        remainder, _, version_raw = remainder.rpartition("@")
        version = _encode_segment(_decode_verified(version_raw, "purl version"))

    # 2. type 与 path
    if "/" not in remainder:
        raise PurlError(f"purl 缺少 type/name 结构: {raw!r}")
    type_raw, _, path_raw = remainder.partition("/")
    ptype = _decode_verified(type_raw, "purl type").lower()
    if ptype not in SUPPORTED_PURL_TYPES:
        raise PurlError(
            f"不支持的 purl 类型 {type_raw!r}；支持范围: "
            f"{sorted(SUPPORTED_PURL_TYPES)}")
    if not path_raw:
        raise PurlError(f"purl 缺少 name: {raw!r}")

    # 3. namespace + name（逐段解码，空段非法）
    raw_parts = path_raw.split("/")
    if any(part == "" for part in raw_parts):
        raise PurlError(f"purl path 含空段: {raw!r}")
    decoded_parts = [_decode_verified(p, "purl path") for p in raw_parts]
    name = decoded_parts[-1]
    namespace = tuple(decoded_parts[:-1])

    # 4. qualifiers：解析、校验重复键、按键排序
    qualifiers: tuple[tuple[str, str], ...] = ()
    if qualifiers_raw is not None:
        if qualifiers_raw == "":
            raise PurlError(f"purl qualifiers 为空: {raw!r}")
        pairs: list[tuple[str, str]] = []
        seen_keys: set[str] = set()
        for item in qualifiers_raw.split("&"):
            if "=" not in item:
                raise PurlError(f"purl qualifier 缺少 '=': {item!r}")
            key_raw, _, value_raw = item.partition("=")
            key = _decode_verified(key_raw, "purl qualifier key").lower()
            if not _QUALIFIER_KEY_RE.fullmatch(key):
                raise PurlError(f"purl qualifier 键名非法: {key_raw!r}")
            if key in seen_keys:
                raise PurlError(f"purl qualifier 键重复: {key!r}")
            seen_keys.add(key)
            value = _decode_verified(value_raw, f"purl qualifier {key}")
            pairs.append((key, value))
        pairs.sort(key=lambda kv: kv[0])
        qualifiers = tuple(pairs)

    # 5. 类型相关的名称归一化
    if ptype == "pypi":
        name = _PYPI_NORMALIZE_RE.sub("-", name).lower()
        namespace = tuple(ns.lower() for ns in namespace)
    elif ptype == "npm":
        # npm scope（@scope/name 中的 scope）按规则必须小写；包名本体保留大小写
        namespace = tuple(ns.lower() for ns in namespace)

    return Purl(
        type=ptype,
        name=name,
        namespace=namespace,
        version=version,
        qualifiers=qualifiers,
        subpath=subpath,
    )
