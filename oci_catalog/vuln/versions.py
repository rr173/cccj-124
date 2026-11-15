"""版本解析与 OSV 风格区间求值。

版本比较全部委托成熟库，不自行实现排序规则：

* PyPI：``packaging.version.Version``（PEP 440，含 dev/rc/post 次序）；
* npm：``semantic_version.Version``（严格 SemVer，拒绝缺段写法如 ``1.0``，
  不补写缺少的版本段；预发行数字段按数字比较、数字段低于非数字段、正式版
  高于对应预发行；构建元数据不参与先后判定——求值只使用 ``<``/``<=``
  等优先级比较运算符，从不把 ``==`` 当作区间依据）。

不转成浮点、不按文本排序。两个库都在函数内延迟导入，纯标准库环境下
``import oci_catalog`` 不受影响（与 provenance 子系统对 cryptography 的
处理一致）。

区间模型（OSV events 列表，按原顺序解释，绝不通过排序“修复”输入）：

* ``introduced`` 开始一个**包含**下界的区间；值为字符串 ``"0"`` 时表示
  从所有版本之前开始（负无穷下界），``"0"`` 只允许出现在 introduced；
* ``fixed`` / ``limit`` 结束区间且**不包含**端点；``last_affected`` 结束
  区间且**包含**端点；
* 结束后可以再次 ``introduced``；最后一个未结束的区间延伸到未来；
* 事件必须从 introduced 开始、开闭交替，每项只能有一个事件键；
* 除 introduced 的 ``"0"`` 外，端点必须能按该生态解析；
* 区间不能倒退或互相重叠：``last_affected`` 可与本段下界相等，其余结束
  端点必须高于下界；后段可从前段**排除的**结束端点（fixed/limit）开始，
  但不能等于前段 ``last_affected`` 已包含的最后版本。
"""

from __future__ import annotations

from dataclasses import dataclass

EVENT_KEYS = ("introduced", "fixed", "limit", "last_affected")
CLOSE_KEYS = ("fixed", "limit", "last_affected")

# 事件校验诊断码
EVENTS_EMPTY = "events_empty"
EVENT_ITEM_STRUCTURE = "event_item_structure"
EVENTS_MUST_START_WITH_INTRODUCED = "events_must_start_with_introduced"
EVENTS_NOT_ALTERNATING = "events_not_alternating"
ZERO_NOT_ALLOWED_HERE = "zero_not_allowed_here"
ENDPOINT_UNPARSEABLE = "endpoint_unparseable"
RANGE_REGRESSED = "range_regressed"
RANGE_OVERLAP = "range_overlap"


class VersionParseError(ValueError):
    """版本字符串不能按对应生态解析。"""


class MissingVersionDependency(RuntimeError):
    """缺少 packaging / semantic_version 依赖。"""


def versions_available() -> bool:
    """两个版本库是否都可用（测试据此决定跳过）。"""
    try:
        import packaging.version  # noqa: F401
        import semantic_version  # noqa: F401
    except ImportError:
        return False
    return True


def parse_pypi_version(text: str):
    """按 PEP 440 解析 PyPI 版本；失败抛 :class:`VersionParseError`。"""
    try:
        from packaging.version import InvalidVersion, Version
    except ImportError as exc:  # pragma: no cover
        raise MissingVersionDependency(
            "缺少依赖 packaging（PyPI 版本判定需要）") from exc
    try:
        return Version(text)
    except InvalidVersion as exc:
        raise VersionParseError(f"不是合法 PEP 440 版本: {text!r}") from exc


def parse_npm_version(text: str):
    """按严格 SemVer 解析 npm 版本；失败抛 :class:`VersionParseError`。

    不使用 ``Version.coerce``：缺段写法（``1.0``）直接拒绝，不补写版本段。
    """
    try:
        from semantic_version import Version
    except ImportError as exc:  # pragma: no cover
        raise MissingVersionDependency(
            "缺少依赖 semantic_version（npm 版本判定需要）") from exc
    try:
        return Version(text)
    except ValueError as exc:
        raise VersionParseError(f"不是合法严格 SemVer 版本: {text!r}") from exc


def parse_ecosystem_version(ecosystem: str, text: str):
    """按公告生态名（``PyPI`` / ``npm``）解析版本。"""
    if ecosystem == "PyPI":
        return parse_pypi_version(text)
    if ecosystem == "npm":
        return parse_npm_version(text)
    raise ValueError(f"不支持的生态: {ecosystem!r}")


@dataclass(frozen=True)
class Interval:
    """一个已校验的受影响区间（下界包含，上界按 close_kind 定开闭）。"""

    lower: object | None        # 解析后的版本；None 表示负无穷（introduced "0"）
    upper: object | None        # 解析后的版本；None 表示延伸到未来
    upper_inclusive: bool       # last_affected 为 True，fixed/limit 为 False
    introduced: str             # 原始 introduced 事件值（证据展示用）
    close_kind: str | None      # fixed / limit / last_affected / None（未结束）
    close: str | None           # 原始结束事件值
    introduced_index: int       # 在 events 列表中的下标（证据定位用）
    close_index: int | None

    def contains(self, version) -> bool:
        """版本是否落在区间内（只用优先级比较运算符）。"""
        if self.lower is not None and version < self.lower:
            return False
        if self.upper is None:
            return True
        if self.upper_inclusive:
            return version <= self.upper
        return version < self.upper

    def to_dict(self) -> dict:
        return {
            "introduced": self.introduced,
            "close_kind": self.close_kind,
            "close": self.close,
            "introduced_index": self.introduced_index,
            "close_index": self.close_index,
        }


def _diag(code: str, message: str, location: str):
    # 延迟导入避免循环：Diagnostic 结构由 advisory 模块统一定义
    from ..provenance.jsonutil import Diagnostic
    return Diagnostic(code, message, location)


def validate_range_events(ecosystem: str, events: object, location: str
                          ) -> tuple[list[Interval], list]:
    """把一条已支持类型区间的 events 列表校验并编译为区间列表。

    :param ecosystem: 公告生态名（``PyPI`` / ``npm``），决定端点解析规则；
    :param events: 公告 ``ranges[].events`` 原值；
    :param location: 该 events 字段的 JSONPath（诊断定位用）；
    :return: ``(区间列表, 诊断列表)``；诊断非空时区间列表为空。
    """
    diagnostics = []
    if not isinstance(events, list) or not events:
        return [], [_diag(EVENTS_EMPTY,
                          "events 必须是非空列表", location)]

    # 1. 逐项结构校验：每项必须恰好一个事件键，值为非空字符串
    parsed: list[tuple[str, str, str]] = []  # (kind, raw_value, item_location)
    for index, item in enumerate(events):
        item_loc = f"{location}[{index}]"
        if not isinstance(item, dict) or len(item) != 1:
            diagnostics.append(_diag(
                EVENT_ITEM_STRUCTURE,
                f"事件项必须是恰好含一个事件键的对象（{EVENT_KEYS}）: {item!r}",
                item_loc))
            continue
        key = next(iter(item))
        value = item[key]
        if key not in EVENT_KEYS:
            diagnostics.append(_diag(
                EVENT_ITEM_STRUCTURE,
                f"未知事件键 {key!r}（允许 {EVENT_KEYS}）", item_loc))
            continue
        if not isinstance(value, str) or not value:
            diagnostics.append(_diag(
                EVENT_ITEM_STRUCTURE,
                f"事件 {key!r} 的值必须是非空字符串: {value!r}", item_loc))
            continue
        parsed.append((key, value, item_loc))
    if diagnostics:
        return [], diagnostics

    # 2. 开闭交替结构：必须从 introduced 开始，开闭交替
    if parsed[0][0] != "introduced":
        return [], [_diag(
            EVENTS_MUST_START_WITH_INTRODUCED,
            f"事件必须以 introduced 开始，实际为 {parsed[0][0]!r}",
            parsed[0][2])]
    for index, (kind, _value, item_loc) in enumerate(parsed):
        expect_introduced = (index % 2 == 0)  # 偶数位开区间，奇数位闭区间
        if expect_introduced and kind != "introduced":
            return [], [_diag(
                EVENTS_NOT_ALTERNATING,
                f"事件必须开闭交替：第 {index} 项应为 introduced，实际 {kind!r}",
                item_loc)]
        if not expect_introduced and kind not in CLOSE_KEYS:
            return [], [_diag(
                EVENTS_NOT_ALTERNATING,
                f"事件必须开闭交替：第 {index} 项应为 "
                f"fixed/limit/last_affected，实际 {kind!r}",
                item_loc)]

    # 3. 端点解析与区间顺序校验
    intervals: list[Interval] = []
    lower = None
    lower_raw: str | None = None
    lower_index = 0
    open_pending = False       # 上一个事件是 introduced，等待结束事件
    prev_close = None          # 上一段结束端点（解析后）
    prev_close_kind: str | None = None
    prev_close_loc: str | None = None
    prev_close_index = 0

    for index, (kind, raw, item_loc) in enumerate(parsed):
        if kind == "introduced":
            # 与前一段的重叠/倒退校验
            if raw == "0":
                new_lower = None  # 负无穷
            else:
                try:
                    new_lower = parse_ecosystem_version(ecosystem, raw)
                except VersionParseError as exc:
                    return [], [_diag(ENDPOINT_UNPARSEABLE, str(exc), item_loc)]
            if prev_close_kind is not None:
                if prev_close_kind == "last_affected":
                    # 不能再包含前段已经包含的最后版本：必须严格高于
                    ok = new_lower is not None and prev_close < new_lower
                    rule = "必须严格高于前段 last_affected 端点"
                else:
                    # 可从前段排除的结束端点开始：允许等于 fixed/limit 端点
                    ok = new_lower is not None and not (new_lower < prev_close)
                    rule = "不得低于前段 fixed/limit 端点"
                if not ok:
                    return [], [_diag(
                        RANGE_OVERLAP,
                        f"区间倒退或重叠：introduced {raw!r} {rule}"
                        f"（前段结束于 {prev_close_kind} "
                        f"{parsed[prev_close_index][1]!r}，位置 {prev_close_loc}）",
                        item_loc)]
            lower, lower_raw, lower_index = new_lower, raw, index
            open_pending = True
            continue

        # 结束事件
        if raw == "0":
            return [], [_diag(
                ZERO_NOT_ALLOWED_HERE,
                f"字符串 '0' 只允许出现在 introduced 中（表示从所有版本之前"
                f"开始），不能作为 {kind} 端点", item_loc)]
        try:
            endpoint = parse_ecosystem_version(ecosystem, raw)
        except VersionParseError as exc:
            return [], [_diag(ENDPOINT_UNPARSEABLE, str(exc), item_loc)]

        if open_pending and lower is not None:
            if kind == "last_affected":
                # 包含端点：允许与下界相等（单版本区间）
                regressed = endpoint < lower
            else:
                # fixed/limit 排除端点：必须严格高于下界，否则区间为空
                regressed = not (lower < endpoint)
            if regressed:
                return [], [_diag(
                    RANGE_REGRESSED,
                    f"区间倒退：{kind} 端点 {raw!r} 未高于本段下界 "
                    f"{lower_raw!r}（last_affected 允许相等，其余必须更高）",
                    item_loc)]

        intervals.append(Interval(
            lower=lower, upper=endpoint,
            upper_inclusive=(kind == "last_affected"),
            introduced=lower_raw, close_kind=kind, close=raw,
            introduced_index=lower_index, close_index=index))
        prev_close, prev_close_kind = endpoint, kind
        prev_close_loc = item_loc
        prev_close_index = index
        lower = None
        open_pending = False

    if open_pending:
        # 最后一个 introduced 未结束：区间延伸到未来
        intervals.append(Interval(
            lower=lower, upper=None, upper_inclusive=False,
            introduced=lower_raw, close_kind=None, close=None,
            introduced_index=lower_index, close_index=None))
    return intervals, []
