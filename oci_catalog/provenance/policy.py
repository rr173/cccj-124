"""本地信任策略：Ed25519 公钥登记 + 授权规则（非信封自述，独立提供）。

策略是 JSON 文档，结构::

    {
      "keys": {
        "<本地公钥名>": "<64位十六进制 或 base64 的 32 字节 Ed25519 公钥>",
        ...
      },
      "rules": [
        {
          "id": "<唯一规则 ID>",
          "builder_id": "<与声明 builder.id 精确匹配的字符串>",
          "build_type": "<与声明 buildType 精确匹配的字符串>",
          "authorized_keys": ["<keys 中登记的名字>", ...],
          "threshold": <正整数>
        },
        ...
      ]
    }

语义边界：

* 公钥身份是**公钥字节本身**（指纹 = 原始 32 字节的 sha256）。同一公钥
  登记两个名字只是别名，仍只算一个独立签名者；
* 每条规则按 ``(builder_id, build_type)`` 精确匹配声明；两条规则命中同一
  对 ``(builder_id, build_type)`` 是**规则冲突**，载入即报错；
* 规则引用未登记的公钥名、门槛不是正整数、门槛超过授权集合中**独立公钥
  数**（按字节去重），都在处理任何证据之前报错；
* 策略内容摘要对**规范化 JSON**（键排序、紧凑分隔符、UTF-8）计算，
  同样的规则集不因排版差异得到不同摘要；
* 评估时按声明里的构建者与构建类型找唯一规则；keyid 只是提示，结论只由
  实际公钥验签与规则授权决定。
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field

from .dsse import b64decode_strict
from .jsonutil import (
    Diagnostic,
    DuplicateKeyError,
    StrictJSONError,
    load_json,
)

# 策略诊断错误码
INVALID_JSON = "invalid_json"
DUPLICATE_JSON_KEY = "duplicate_json_key"
INVALID_STRUCTURE = "invalid_structure"
MISSING_FIELD = "missing_field"
INVALID_FIELD_TYPE = "invalid_field_type"
INVALID_KEY_ENCODING = "invalid_key_encoding"
UNKNOWN_KEY = "unknown_key"
DUPLICATE_RULE_ID = "duplicate_rule_id"
RULE_CONFLICT = "rule_conflict"
INVALID_THRESHOLD = "invalid_threshold"
THRESHOLD_EXCEEDS_KEYS = "threshold_exceeds_keys"

_HEX64_RE = re.compile(r"^[0-9a-fA-F]{64}$")


class PolicyError(ValueError):
    """策略不合法：携带全部诊断，在处理证据前抛出。"""

    def __init__(self, diagnostics: list[Diagnostic]):
        self.diagnostics = diagnostics
        summary = "; ".join(f"{d.location}: {d.message}" for d in diagnostics)
        super().__init__(f"信任策略不合法（{len(diagnostics)} 项）: {summary}")


def key_fingerprint(public_key_bytes: bytes) -> str:
    """公钥指纹 = 原始 32 字节公钥的 sha256（``sha256:<hex>``）。"""
    return "sha256:" + hashlib.sha256(public_key_bytes).hexdigest()


def _decode_public_key(value: object, location: str,
                       diagnostics: list[Diagnostic]) -> bytes | None:
    """读取一个公钥：64 位十六进制，或 base64（标准/URL 安全）的 32 字节。"""
    if not isinstance(value, str):
        diagnostics.append(Diagnostic(
            INVALID_FIELD_TYPE,
            f"公钥必须是字符串，实际 {type(value).__name__}", location))
        return None
    candidate: bytes | None = None
    if _HEX64_RE.fullmatch(value):
        candidate = bytes.fromhex(value)
    else:
        probe: list[Diagnostic] = []
        decoded = b64decode_strict(value, location, probe)
        if decoded is not None and len(decoded) == 32:
            candidate = decoded
    if candidate is None or len(candidate) != 32:
        diagnostics.append(Diagnostic(
            INVALID_KEY_ENCODING,
            "公钥必须是 64 位十六进制或 base64 编码的 32 字节 Ed25519 公钥",
            location))
        return None
    return candidate


@dataclass(frozen=True)
class Rule:
    """一条授权规则：精确匹配 (builder_id, build_type) + 授权公钥 + 门槛。"""

    rule_id: str
    builder_id: str
    build_type: str
    # 授权公钥指纹（按字节去重，排序后定值）；authorized_names 为原始名字
    authorized_fingerprints: tuple[str, ...]
    authorized_names: tuple[str, ...]
    threshold: int

    def to_dict(self) -> dict:
        return {
            "id": self.rule_id,
            "builder_id": self.builder_id,
            "build_type": self.build_type,
            "authorized_keys": list(self.authorized_names),
            "authorized_fingerprints": list(self.authorized_fingerprints),
            "threshold": self.threshold,
        }


@dataclass
class Policy:
    """已校验的信任策略。"""

    # 公钥名 -> 原始 32 字节公钥
    keys: dict[str, bytes] = field(default_factory=dict)
    rules: list[Rule] = field(default_factory=list)
    policy_sha256: str = ""

    @property
    def distinct_fingerprints(self) -> dict[str, bytes]:
        """指纹 -> 公钥字节（按字节去重后的全部登记公钥）。"""
        return {key_fingerprint(raw): raw for raw in self.keys.values()}

    def names_for_fingerprint(self, fingerprint: str) -> list[str]:
        """某指纹对应的所有本地公钥名（别名可能不止一个）。"""
        return sorted(name for name, raw in self.keys.items()
                      if key_fingerprint(raw) == fingerprint)

    def find_rule(self, builder_id: str, build_type: str) -> Rule | None:
        """按声明里的构建者与构建类型精确匹配唯一规则。"""
        for rule in self.rules:
            if rule.builder_id == builder_id and rule.build_type == build_type:
                return rule
        return None

    def to_dict(self) -> dict:
        return {
            "policy_sha256": self.policy_sha256,
            "keys": {name: key_fingerprint(raw)
                     for name, raw in sorted(self.keys.items())},
            "rules": [rule.to_dict() for rule in self.rules],
        }


def canonical_policy_digest(materialized: object) -> str:
    """对规范化 JSON（键排序、紧凑分隔符、UTF-8）计算策略内容摘要。"""
    canonical = json.dumps(materialized, sort_keys=True,
                           separators=(",", ":"), ensure_ascii=False)
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def load_policy(raw_bytes: bytes) -> Policy:
    """载入并全量校验策略；任何问题都在处理证据前以 PolicyError 抛出。"""
    diagnostics: list[Diagnostic] = []
    try:
        doc = load_json(raw_bytes)
    except StrictJSONError as exc:
        raise PolicyError([Diagnostic(INVALID_JSON, str(exc), "$")]) from exc
    except DuplicateKeyError as exc:
        raise PolicyError([Diagnostic(
            DUPLICATE_JSON_KEY,
            f"策略含重复 JSON 键 {exc.key!r}（拒绝后值覆盖前值）",
            exc.path)]) from exc

    if not isinstance(doc, dict):
        raise PolicyError([Diagnostic(
            INVALID_STRUCTURE, "策略顶层必须是 JSON 对象", "$")])

    policy = Policy()

    # ---- keys ----
    raw_keys = doc.get("keys")
    if "keys" not in doc:
        diagnostics.append(Diagnostic(
            MISSING_FIELD, "缺少必需字段 keys", "$.keys"))
    elif not isinstance(raw_keys, dict):
        diagnostics.append(Diagnostic(
            INVALID_STRUCTURE,
            f"keys 必须是对象（名字 -> 公钥），实际 {type(raw_keys).__name__}",
            "$.keys"))
    else:
        for name, value in raw_keys.items():
            location = f"$.keys.{name}"
            if not name:
                diagnostics.append(Diagnostic(
                    INVALID_FIELD_TYPE, "公钥名不能为空", "$.keys"))
                continue
            decoded = _decode_public_key(value, location, diagnostics)
            if decoded is not None:
                # 同一公钥登记两个名字是合法别名；指纹去重在评估时进行
                policy.keys[name] = decoded

    # ---- rules ----
    raw_rules = doc.get("rules")
    if "rules" not in doc:
        diagnostics.append(Diagnostic(
            MISSING_FIELD, "缺少必需字段 rules", "$.rules"))
    elif not isinstance(raw_rules, list):
        diagnostics.append(Diagnostic(
            INVALID_STRUCTURE,
            f"rules 必须是列表，实际 {type(raw_rules).__name__}", "$.rules"))
    else:
        seen_ids: set[str] = set()
        seen_pairs: dict[tuple[str, str], str] = {}
        for index, entry in enumerate(raw_rules):
            location = f"$.rules[{index}]"
            rule = _parse_rule(entry, location, policy, diagnostics)
            if rule is None:
                continue
            if rule.rule_id in seen_ids:
                diagnostics.append(Diagnostic(
                    DUPLICATE_RULE_ID,
                    f"规则 ID {rule.rule_id!r} 重复", f"{location}.id"))
                continue
            seen_ids.add(rule.rule_id)
            pair = (rule.builder_id, rule.build_type)
            if pair in seen_pairs:
                diagnostics.append(Diagnostic(
                    RULE_CONFLICT,
                    f"规则 {rule.rule_id!r} 与 {seen_pairs[pair]!r} 命中同一 "
                    f"(builder_id, build_type)，无法确定唯一规则",
                    f"{location}"))
                continue
            seen_pairs[pair] = rule.rule_id
            policy.rules.append(rule)

    if diagnostics:
        raise PolicyError(diagnostics)
    policy.policy_sha256 = canonical_policy_digest(doc)
    return policy


def _parse_rule(entry: object, location: str, policy: Policy,
                diagnostics: list[Diagnostic]) -> Rule | None:
    if not isinstance(entry, dict):
        diagnostics.append(Diagnostic(
            INVALID_STRUCTURE,
            f"规则必须是对象，实际 {type(entry).__name__}", location))
        return None
    ok = True

    rule_id = entry.get("id")
    if "id" not in entry:
        diagnostics.append(Diagnostic(
            MISSING_FIELD, "规则缺少 id", f"{location}.id"))
        ok = False
    elif not isinstance(rule_id, str) or not rule_id:
        diagnostics.append(Diagnostic(
            INVALID_FIELD_TYPE, "规则 id 必须是非空字符串", f"{location}.id"))
        ok = False

    builder_id = entry.get("builder_id")
    if "builder_id" not in entry:
        diagnostics.append(Diagnostic(
            MISSING_FIELD, "规则缺少 builder_id", f"{location}.builder_id"))
        ok = False
    elif not isinstance(builder_id, str) or not builder_id:
        diagnostics.append(Diagnostic(
            INVALID_FIELD_TYPE, "builder_id 必须是非空字符串",
            f"{location}.builder_id"))
        ok = False

    build_type = entry.get("build_type")
    if "build_type" not in entry:
        diagnostics.append(Diagnostic(
            MISSING_FIELD, "规则缺少 build_type", f"{location}.build_type"))
        ok = False
    elif not isinstance(build_type, str) or not build_type:
        diagnostics.append(Diagnostic(
            INVALID_FIELD_TYPE, "build_type 必须是非空字符串",
            f"{location}.build_type"))
        ok = False

    names = entry.get("authorized_keys")
    authorized_names: list[str] = []
    fingerprints: set[str] = set()
    if "authorized_keys" not in entry:
        diagnostics.append(Diagnostic(
            MISSING_FIELD, "规则缺少 authorized_keys",
            f"{location}.authorized_keys"))
        ok = False
    elif not isinstance(names, list) or not names:
        diagnostics.append(Diagnostic(
            INVALID_FIELD_TYPE, "authorized_keys 必须是非空字符串列表",
            f"{location}.authorized_keys"))
        ok = False
    else:
        for position, name in enumerate(names):
            name_location = f"{location}.authorized_keys[{position}]"
            if not isinstance(name, str) or not name:
                diagnostics.append(Diagnostic(
                    INVALID_FIELD_TYPE, "授权公钥名必须是非空字符串",
                    name_location))
                ok = False
                continue
            if name not in policy.keys:
                diagnostics.append(Diagnostic(
                    UNKNOWN_KEY, f"规则引用了未登记的公钥名 {name!r}",
                    name_location))
                ok = False
                continue
            if name not in authorized_names:
                authorized_names.append(name)
            # 按公钥字节去重：别名与重复名字都不增加独立公钥数
            fingerprints.add(key_fingerprint(policy.keys[name]))

    threshold = entry.get("threshold")
    if "threshold" not in entry:
        diagnostics.append(Diagnostic(
            MISSING_FIELD, "规则缺少 threshold", f"{location}.threshold"))
        ok = False
    elif not isinstance(threshold, int) or isinstance(threshold, bool) \
            or threshold < 1:
        diagnostics.append(Diagnostic(
            INVALID_THRESHOLD, "threshold 必须是正整数",
            f"{location}.threshold"))
        ok = False
    elif fingerprints and threshold > len(fingerprints):
        diagnostics.append(Diagnostic(
            THRESHOLD_EXCEEDS_KEYS,
            f"门槛 {threshold} 超过授权集合的独立公钥数 "
            f"{len(fingerprints)}（同一公钥的多个别名只算一个）",
            f"{location}.threshold"))
        ok = False

    if not ok:
        return None
    return Rule(
        rule_id=rule_id, builder_id=builder_id, build_type=build_type,
        authorized_fingerprints=tuple(sorted(fingerprints)),
        authorized_names=tuple(authorized_names),
        threshold=threshold,
    )
