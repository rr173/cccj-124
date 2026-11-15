"""字段契约：类型、空值规则与确定性的单记录校验。

一份输入表的契约由字段列表（名称 / 类型 / 是否允许空）与表级空值策略组成。
所有转换都是**纯函数、无隐式截断、不经过二进制浮点**：

* ``string``  —— 原样保留 Unicode 字符串；
* ``integer`` —— 只接受可选正负号加十进制数字（``"12"``、``-3``），
  拒绝 ``1.0``、``" 1 "``、布尔等一切疑似截断输入；
* ``decimal`` —— 十进制定点数，只接受定点字符串（``"0.10"``）或 JSON 整数，
  拒绝科学计数法、``NaN``/``Infinity`` 与 JSON 浮点（二进制浮点不可信），
  内部以 :class:`decimal.Decimal` 精确表示，求和保留参与值的小数位语义。

空值三类输入的规则由表级策略显式声明（契约里说清，不靠隐式行为）：

* 缺失：JSON 行缺键 / （CSV 表头缺字段属于文件级致命错误，不在此列）；
* 空字符串：CSV 的 ``""`` 或 JSON 字符串 ``""``；
* 显式 null：JSON ``null``（CSV 没有 null 字面量，空串走空字符串策略）。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
from typing import Any, Optional

TYPE_STRING = "string"
TYPE_INTEGER = "integer"
TYPE_DECIMAL = "decimal"
SUPPORTED_TYPES = frozenset((TYPE_STRING, TYPE_INTEGER, TYPE_DECIMAL))

# 表级策略取值
MISSING_NULL = "null"
MISSING_REJECT = "reject"
EMPTY_NULL = "null"
EMPTY_REJECT = "reject"
EMPTY_KEEP = "keep"          # 仅 string 字段合法：空串作为普通字符串保留
EXTRA_IGNORE = "ignore"
EXTRA_REJECT = "reject"

_INTEGER_RE = re.compile(r"^[+-]?\d+$")
_DECIMAL_RE = re.compile(r"^[+-]?\d+(?:\.\d+)?$")

# 记录级拒绝原因码
REASON_NULL_NOT_ALLOWED = "null_not_allowed"
REASON_MISSING_FIELD = "missing_field"
REASON_EMPTY_NOT_ALLOWED = "empty_not_allowed"
REASON_EXTRA_FIELD = "extra_field"
REASON_NOT_CONVERTIBLE = "not_convertible"
REASON_JSON_NOT_OBJECT = "json_not_object"
REASON_JSON_INVALID_LINE = "json_invalid_line"


class ContractSpecError(ValueError):
    """契约/计划声明本身不合法（计划级错误，整份计划拒绝）。"""


@dataclass(frozen=True)
class FieldSpec:
    """一个字段的声明：名称、类型、是否允许空。"""

    name: str
    data_type: str
    nullable: bool

    @classmethod
    def from_dict(cls, raw: dict) -> "FieldSpec":
        if not isinstance(raw, dict):
            raise ContractSpecError(f"字段声明必须是对象: {raw!r}")
        name = raw.get("name")
        if not isinstance(name, str) or not name:
            raise ContractSpecError(f"字段名必须是非空字符串: {raw!r}")
        data_type = raw.get("type")
        if data_type not in SUPPORTED_TYPES:
            raise ContractSpecError(
                f"字段 {name!r} 的类型 {data_type!r} 不受支持，"
                f"可选 {sorted(SUPPORTED_TYPES)}")
        nullable = raw.get("nullable", False)
        if not isinstance(nullable, bool):
            raise ContractSpecError(
                f"字段 {name!r} 的 nullable 必须是布尔值: {nullable!r}")
        return cls(name=name, data_type=data_type, nullable=nullable)


@dataclass(frozen=True)
class TableContract:
    """输入表契约：字段 + 缺失/空串/额外字段策略。"""

    fields: tuple[FieldSpec, ...]
    missing: str = MISSING_REJECT          # null | reject
    empty_string: str = EMPTY_REJECT       # null | reject | keep
    extra_fields: str = EXTRA_REJECT       # ignore | reject
    field_map: dict[str, FieldSpec] = field(
        init=False, default_factory=dict, compare=False, repr=False)

    def __post_init__(self) -> None:
        # frozen dataclass 中用 object.__setattr__ 建立派生索引
        object.__setattr__(self, "field_map",
                           {spec.name: spec for spec in self.fields})

    @classmethod
    def from_dict(cls, raw: dict) -> "TableContract":
        if not isinstance(raw, dict):
            raise ContractSpecError(f"契约必须是对象: {raw!r}")
        fields_raw = raw.get("fields")
        if not isinstance(fields_raw, list) or not fields_raw:
            raise ContractSpecError("契约 fields 必须是非空数组")
        specs: list[FieldSpec] = []
        seen: set[str] = set()
        for item in fields_raw:
            spec = FieldSpec.from_dict(item)
            if spec.name in seen:
                raise ContractSpecError(f"契约内字段重名: {spec.name!r}")
            seen.add(spec.name)
            specs.append(spec)

        missing = raw.get("missing", MISSING_REJECT)
        if missing not in (MISSING_NULL, MISSING_REJECT):
            raise ContractSpecError(
                f"missing 策略只能是 null/reject: {missing!r}")
        empty_string = raw.get("empty_string", EMPTY_REJECT)
        if empty_string not in (EMPTY_NULL, EMPTY_REJECT, EMPTY_KEEP):
            raise ContractSpecError(
                f"empty_string 策略只能是 null/reject/keep: "
                f"{empty_string!r}")
        extra_fields = raw.get("extra_fields", EXTRA_REJECT)
        if extra_fields not in (EXTRA_IGNORE, EXTRA_REJECT):
            raise ContractSpecError(
                f"extra_fields 策略只能是 ignore/reject: {extra_fields!r}")

        contract = cls(tuple(specs), missing, empty_string, extra_fields)
        contract._validate_policy_coherence()
        return contract

    def _validate_policy_coherence(self) -> None:
        """策略与字段声明的自洽性检查。

        空值策略是**逐字段**生效的：nullable 字段按策略接收 null，
        不可空字段遇到缺失/空串/null 一律走记录级拒绝。因此混合契约
        （部分字段可空、部分不可空）本身合法，这里只拦截客观上无法
        执行的组合（``keep`` 用在非字符串字段上）。
        """
        if self.empty_string == EMPTY_KEEP:
            bad = [f.name for f in self.fields
                   if f.data_type != TYPE_STRING]
            if bad:
                raise ContractSpecError(
                    f"empty_string=keep 只适用于 string 字段，"
                    f"非字符串字段 {bad} 无法保留空串")

    @property
    def column_names(self) -> tuple[str, ...]:
        return tuple(f.name for f in self.fields)


@dataclass
class RejectedRecord(Exception):
    """单条记录不合约：携带原因码与说明（不中断其他记录）。

    定位信息（文件、记录序号、物理行）由解析层补齐，这里只带原因。
    """

    reason_code: str
    reason_message: str

    def __str__(self) -> str:
        return f"{self.reason_code}: {self.reason_message}"


def _reject(code: str, message: str) -> None:
    raise RejectedRecord(code, message)


def parse_integer(raw: Any, field_name: str) -> int:
    """严格整数转换：只接受整数字面量字符串或 JSON 整数（拒绝 bool）。"""
    if isinstance(raw, bool):
        _reject(REASON_NOT_CONVERTIBLE,
                f"字段 {field_name!r} 期望 integer，布尔值不可作为整数")
    if isinstance(raw, int):
        return raw
    if isinstance(raw, str):
        if _INTEGER_RE.match(raw):
            try:
                return int(raw, 10)
            except ValueError:  # pragma: no cover - 正则已保证
                pass
    _reject(REASON_NOT_CONVERTIBLE,
            f"字段 {field_name!r} 期望 integer，值 {raw!r} 不是合法整数字面量")


def parse_decimal(raw: Any, field_name: str) -> Decimal:
    """定点数十进制转换：定点字符串或 JSON 整数，拒绝浮点与科学计数法。"""
    if isinstance(raw, bool):
        _reject(REASON_NOT_CONVERTIBLE,
                f"字段 {field_name!r} 期望 decimal，布尔值不可作为十进制数")
    if isinstance(raw, int):
        return Decimal(raw)
    if isinstance(raw, float):
        # 二进制浮点已经丢失精度，绝不静默接受
        _reject(REASON_NOT_CONVERTIBLE,
                f"字段 {field_name!r} 期望 decimal 定点数，JSON 浮点 "
                f"{raw!r} 是二进制浮点，拒绝以避免精度丢失")
    if isinstance(raw, str):
        if _DECIMAL_RE.match(raw):
            try:
                return Decimal(raw)
            except InvalidOperation:  # pragma: no cover - 正则已保证
                pass
    _reject(REASON_NOT_CONVERTIBLE,
            f"字段 {field_name!r} 期望 decimal 定点数，值 {raw!r} "
            f"不是合法定点字面量（不支持科学计数法/NaN/Infinity）")


def convert_value(spec: FieldSpec, raw: Any) -> Any:
    """把已确定“存在且非空”的原始值按类型转换。"""
    if spec.data_type == TYPE_STRING:
        if isinstance(raw, str):
            return raw
        if isinstance(raw, bool) or not isinstance(raw, (str, int, float)):
            _reject(REASON_NOT_CONVERTIBLE,
                    f"字段 {spec.name!r} 期望 string，值 {raw!r} 不是字符串")
        # 数字标量进字符串字段属于类型不符，拒绝而不是悄悄 str()
        _reject(REASON_NOT_CONVERTIBLE,
                f"字段 {spec.name!r} 期望 string，数字标量 {raw!r} 不隐式转字符串")
    if spec.data_type == TYPE_INTEGER:
        return parse_integer(raw, spec.name)
    return parse_decimal(raw, spec.name)


def coerce_record(contract: TableContract, raw_values: dict[str, Optional[Any]],
                  presence: dict[str, str]) -> dict[str, Any]:
    """按契约把一条原始记录转成合约记录；不合约抛 :class:`RejectedRecord`。

    :param raw_values: 字段名 -> 原始值（CSV 全为字符串；JSON 为 JSON 标量）。
    :param presence: 字段名 -> ``present`` / ``missing`` / ``explicit_null``
        / ``empty_string`` 四种存在形态。
    """
    # 额外字段先判（确定性：先结构后类型）
    extras = sorted(set(raw_values) - set(contract.field_map))
    if extras and contract.extra_fields == EXTRA_REJECT:
        _reject(REASON_EXTRA_FIELD,
                f"出现契约未声明的额外字段 {extras}")

    result: dict[str, Any] = {}
    for spec in contract.fields:
        state = presence.get(spec.name, "missing")
        if state == "missing":
            if contract.missing == MISSING_REJECT:
                _reject(REASON_MISSING_FIELD,
                        f"记录缺少契约字段 {spec.name!r} 且 missing=reject")
            if not spec.nullable:  # 契约自检已拦，防御性分支
                _reject(REASON_NULL_NOT_ALLOWED,
                        f"字段 {spec.name!r} 不可空")
            result[spec.name] = None
            continue
        if state == "explicit_null":
            if not spec.nullable:
                _reject(REASON_NULL_NOT_ALLOWED,
                        f"字段 {spec.name!r} 显式为 null 但声明不可空")
            result[spec.name] = None
            continue
        if state == "empty_string":
            if contract.empty_string == EMPTY_REJECT:
                _reject(REASON_EMPTY_NOT_ALLOWED,
                        f"字段 {spec.name!r} 为空字符串且 empty_string=reject")
            if contract.empty_string == EMPTY_KEEP:
                if spec.data_type != TYPE_STRING:  # 契约自检已拦
                    _reject(REASON_EMPTY_NOT_ALLOWED,
                            f"字段 {spec.name!r} 非字符串无法保留空串")
                result[spec.name] = ""
                continue
            # empty_string -> null
            if not spec.nullable:
                _reject(REASON_NULL_NOT_ALLOWED,
                        f"字段 {spec.name!r} 空串按策略转 null 但字段不可空")
            result[spec.name] = None
            continue
        result[spec.name] = convert_value(spec, raw_values[spec.name])
    return result


def decimal_sum(values: list[Optional[Decimal]]) -> Decimal:
    """精确十进制求和：null 跳过；空列表返回 Decimal('0')（无组时不调用）。"""
    total = Decimal("0")
    for value in values:
        if value is not None:
            total += value
    return total
