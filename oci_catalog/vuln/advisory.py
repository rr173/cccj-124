"""本地 OSV 风格公告目录的读取、校验与编号等价组构建。

本模块实现的是**本次接受的公告子集**（完整说明见 ``oci_catalog/vuln/README.md``）：

* 目录下每个 ``*.json`` 文件是一份公告，顶层为 JSON 对象；
* 必需字段：``id``（非空字符串，全目录唯一）；
* 可选字段：``aliases`` / ``related``（非空字符串列表）、``withdrawn``
  （字符串，非空表示已撤回）、``affected``（列表）；
* 每个 affected：``package.ecosystem`` 与 ``package.name``（非空字符串）必需，
  ``versions``（非空字符串列表）与 ``ranges``（列表）可选；
* 每个 range：``type``（非空字符串）与 ``events``（列表）必需；
  仅 PyPI 的 ``ECOSYSTEM`` 与 npm 的 ``SEMVER`` 类型参与确定判定，
  其事件错误会使整次作业失败；其余类型不校验事件，只记为无法判断；
* 其他说明性字段（summary/details/severity/published 等）一律忽略；
* 重复 JSON 键、重复 id、字段结构错误都会定位文件与字段并使本次作业失败，
  不跳过坏公告输出貌似完整的评估。

编号等价组：``id`` 与 ``aliases`` 构成无向关系，取传递闭包（允许环，允许
指向没有独立文件的编号）；组内字典序最小编号为稳定展示名。``related``
只是关联而非等价，不参与并组。撤回公告的 aliases 仍参与并组（编号解释），
但其 affected 声明不参加命中，撤回也不传染同组其他有效公告。
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from ..provenance.jsonutil import (
    Diagnostic,
    DuplicateKeyError,
    StrictJSONError,
    load_json,
)
from .versions import validate_range_events

# 结构校验诊断码
INVALID_JSON = "invalid_json"
DUPLICATE_JSON_KEY = "duplicate_json_key"
NOT_AN_OBJECT = "not_an_object"
MISSING_FIELD = "missing_field"
INVALID_FIELD_TYPE = "invalid_field_type"
EMPTY_VALUE = "empty_value"
DUPLICATE_ADVISORY_ID = "duplicate_advisory_id"

# 可确定判定的 (生态, 区间类型) 组合
SUPPORTED_RANGE_TYPES = frozenset({("PyPI", "ECOSYSTEM"), ("npm", "SEMVER")})


class AdvisoryError(ValueError):
    """公告目录不合法；携带全部诊断（文件 + 字段位置），本次作业必须失败。"""

    def __init__(self, diagnostics: list[Diagnostic]):
        self.diagnostics = diagnostics
        summary = "; ".join(
            f"{d.location}: {d.message}" for d in diagnostics[:5])
        super().__init__(
            f"公告目录校验失败（{len(diagnostics)} 处问题）: {summary}")


@dataclass(frozen=True)
class Range:
    """一条 affected 下的 range（事件已按支持情况校验或原样保留）。"""

    type: str
    events: tuple           # 原始 events（tuple 化的 list[dict]）
    intervals: tuple | None  # 已编译区间；不支持的类型为 None
    index: int              # 在 affected.ranges 中的下标

    @property
    def supported(self) -> bool:
        return self.intervals is not None


@dataclass(frozen=True)
class Affected:
    """一条 affected 声明。"""

    ecosystem: str
    name: str
    versions: tuple | None   # None 表示字段缺失；空 tuple 表示空列表
    ranges: tuple            # Range 元组（可能为空）
    index: int               # 在 advisory.affected 中的下标


@dataclass
class Advisory:
    """一份公告（有效或已撤回）。"""

    id: str
    aliases: tuple
    related: tuple
    withdrawn: str | None    # 非空字符串表示已撤回
    affected: list[Affected]
    source_file: str         # 文件名（相对公告目录）

    @property
    def is_withdrawn(self) -> bool:
        return self.withdrawn is not None and self.withdrawn != ""


@dataclass
class Group:
    """编号等价组（id + aliases 的传递闭包）。"""

    display_id: str                 # 组内字典序最小编号
    member_ids: tuple               # 全部成员编号（含无文件的别名），字典序
    advisories: list = field(default_factory=list)  # 组内有效（未撤回）公告
    withdrawn_ids: tuple = ()       # 组内已撤回公告 id
    related_ids: tuple = ()         # 组内公告声明的 related 并集（不并组）

    def to_dict(self) -> dict:
        return {
            "group_id": self.display_id,
            "member_ids": list(self.member_ids),
            "valid_advisories": sorted(a.id for a in self.advisories),
            "withdrawn_ids": list(self.withdrawn_ids),
            "related_ids": list(self.related_ids),
        }


@dataclass
class AdvisorySet:
    """校验通过的公告目录：公告列表 + 编号等价组。"""

    advisories: list                # 全部公告（含撤回），按 id 排序
    groups: list                    # Group 列表，按 display_id 排序
    files: list                     # 参与加载的文件名（字典序）
    by_id: dict                     # 任意编号（含别名）-> Group

    @property
    def valid_advisories(self) -> list:
        return [a for a in self.advisories if not a.is_withdrawn]

    def group_for(self, any_id: str) -> Group | None:
        return self.by_id.get(any_id)


# ---------------------------------------------------------------------------
# 单文件结构校验
# ---------------------------------------------------------------------------
def _require_string(value: object, what: str, location: str,
                    diagnostics: list[Diagnostic],
                    allow_empty: bool = False) -> str | None:
    if value is None:
        diagnostics.append(Diagnostic(
            MISSING_FIELD, f"缺少必需字段 {what}", location))
        return None
    if not isinstance(value, str):
        diagnostics.append(Diagnostic(
            INVALID_FIELD_TYPE, f"{what} 必须是字符串: {value!r}", location))
        return None
    if not allow_empty and value == "":
        diagnostics.append(Diagnostic(
            EMPTY_VALUE, f"{what} 不能为空字符串", location))
        return None
    return value


def _require_string_list(value: object, what: str, location: str,
                         diagnostics: list[Diagnostic]) -> tuple | None:
    if not isinstance(value, list):
        diagnostics.append(Diagnostic(
            INVALID_FIELD_TYPE, f"{what} 必须是字符串列表: {value!r}",
            location))
        return None
    result = []
    for index, item in enumerate(value):
        item_loc = f"{location}[{index}]"
        parsed = _require_string(item, f"{what} 元素", item_loc, diagnostics)
        if parsed is not None:
            result.append(parsed)
    return tuple(result)


def _validate_affected(raw: object, index: int, location: str,
                       diagnostics: list[Diagnostic]) -> Affected | None:
    if not isinstance(raw, dict):
        diagnostics.append(Diagnostic(
            INVALID_FIELD_TYPE, f"affected 项必须是对象: {raw!r}", location))
        return None

    package = raw.get("package")
    if package is None:
        diagnostics.append(Diagnostic(
            MISSING_FIELD, "affected 缺少 package 对象",
            f"{location}.package"))
        return None
    if not isinstance(package, dict):
        diagnostics.append(Diagnostic(
            INVALID_FIELD_TYPE, f"package 必须是对象: {package!r}",
            f"{location}.package"))
        return None
    ecosystem = _require_string(
        package.get("ecosystem"), "package.ecosystem",
        f"{location}.package.ecosystem", diagnostics)
    name = _require_string(
        package.get("name"), "package.name",
        f"{location}.package.name", diagnostics)

    versions: tuple | None = None
    versions_ok = True
    if "versions" in raw:
        parsed_versions = _require_string_list(
            raw["versions"], "versions", f"{location}.versions", diagnostics)
        if parsed_versions is None:
            versions_ok = False
        else:
            versions = parsed_versions

    ranges: list[Range] = []
    ranges_ok = True
    if "ranges" in raw:
        raw_ranges = raw["ranges"]
        if not isinstance(raw_ranges, list):
            diagnostics.append(Diagnostic(
                INVALID_FIELD_TYPE, f"ranges 必须是列表: {raw_ranges!r}",
                f"{location}.ranges"))
            ranges_ok = False
        else:
            for r_index, raw_range in enumerate(raw_ranges):
                r_loc = f"{location}.ranges[{r_index}]"
                parsed_range = _validate_range(
                    raw_range, ecosystem, r_index, r_loc, diagnostics)
                if parsed_range is None:
                    ranges_ok = False
                else:
                    ranges.append(parsed_range)

    if ecosystem is None or name is None or not versions_ok or not ranges_ok:
        return None
    return Affected(
        ecosystem=ecosystem, name=name, versions=versions,
        ranges=tuple(ranges), index=index)


def _validate_range(raw: object, ecosystem: str | None, index: int,
                    location: str,
                    diagnostics: list[Diagnostic]) -> Range | None:
    if not isinstance(raw, dict):
        diagnostics.append(Diagnostic(
            INVALID_FIELD_TYPE, f"range 必须是对象: {raw!r}", location))
        return None
    rtype = _require_string(raw.get("type"), "range.type",
                            f"{location}.type", diagnostics)
    if "events" not in raw:
        diagnostics.append(Diagnostic(
            MISSING_FIELD, "range 缺少 events 列表", f"{location}.events"))
        return None
    events = raw["events"]
    if not isinstance(events, list):
        diagnostics.append(Diagnostic(
            INVALID_FIELD_TYPE, f"range.events 必须是列表: {events!r}",
            f"{location}.events"))
        return None
    if rtype is None:
        return None

    # 仅已支持的 (生态, 类型) 组合校验事件；其余类型保留原样、记为无法判断
    intervals = None
    if (ecosystem, rtype) in SUPPORTED_RANGE_TYPES:
        built, event_diags = validate_range_events(
            ecosystem, events, f"{location}.events")
        diagnostics.extend(event_diags)
        if event_diags:
            return None
        intervals = tuple(built)
    return Range(type=rtype, events=tuple(events), intervals=intervals,
                 index=index)


def _validate_advisory(raw: object, source_file: str,
                       diagnostics: list[Diagnostic]) -> Advisory | None:
    location = "$"
    if not isinstance(raw, dict):
        diagnostics.append(Diagnostic(
            NOT_AN_OBJECT, f"公告顶层必须是 JSON 对象: {type(raw).__name__}",
            location))
        return None

    advisory_id = _require_string(raw.get("id"), "id", "$.id", diagnostics)

    aliases: tuple = ()
    if "aliases" in raw:
        parsed = _require_string_list(raw["aliases"], "aliases",
                                      "$.aliases", diagnostics)
        aliases = parsed if parsed is not None else ()

    related: tuple = ()
    if "related" in raw:
        parsed = _require_string_list(raw["related"], "related",
                                      "$.related", diagnostics)
        related = parsed if parsed is not None else ()

    withdrawn: str | None = None
    if "withdrawn" in raw:
        withdrawn = _require_string(raw["withdrawn"], "withdrawn",
                                    "$.withdrawn", diagnostics,
                                    allow_empty=True)

    affected: list[Affected] = []
    if "affected" in raw:
        raw_affected = raw["affected"]
        if not isinstance(raw_affected, list):
            diagnostics.append(Diagnostic(
                INVALID_FIELD_TYPE,
                f"affected 必须是列表: {raw_affected!r}", "$.affected"))
        else:
            for a_index, raw_item in enumerate(raw_affected):
                item = _validate_affected(
                    raw_item, a_index, f"$.affected[{a_index}]", diagnostics)
                if item is not None:
                    affected.append(item)

    if advisory_id is None:
        return None
    return Advisory(
        id=advisory_id, aliases=aliases, related=related,
        withdrawn=withdrawn, affected=affected, source_file=source_file)


# ---------------------------------------------------------------------------
# 目录加载
# ---------------------------------------------------------------------------
def load_advisory_dir(advisory_dir: str) -> AdvisorySet:
    """读取并校验公告目录；任何诊断都使本次作业失败（抛 AdvisoryError）。

    文件按文件名字典序处理，结果与目录遍历顺序无关。
    """
    if not os.path.isdir(advisory_dir):
        raise AdvisoryError([Diagnostic(
            INVALID_JSON, f"公告目录不存在或不是目录: {advisory_dir}",
            "$.advisory_dir")])

    diagnostics: list[Diagnostic] = []
    advisories: list[Advisory] = []
    files = sorted(name for name in os.listdir(advisory_dir)
                   if name.endswith(".json"))

    seen_ids: dict[str, str] = {}  # id -> 首个文件名
    for name in files:
        path = os.path.join(advisory_dir, name)
        try:
            with open(path, "rb") as fh:
                raw_bytes = fh.read()
        except OSError as exc:
            diagnostics.append(Diagnostic(
                INVALID_JSON, f"无法读取公告文件 {name}: {exc}",
                f"{name}:$"))
            continue
        try:
            document = load_json(raw_bytes)
        except DuplicateKeyError as exc:
            diagnostics.append(Diagnostic(
                DUPLICATE_JSON_KEY,
                f"重复 JSON 键 {exc.key!r}（文件 {name}）",
                f"{name}:{exc.path}"))
            continue
        except StrictJSONError as exc:
            diagnostics.append(Diagnostic(
                INVALID_JSON, f"文件 {name} 不是合法 JSON: {exc}",
                f"{name}:$"))
            continue

        file_diags: list[Diagnostic] = []
        advisory = _validate_advisory(document, name, file_diags)
        for diag in file_diags:
            diagnostics.append(Diagnostic(
                diag.code, diag.message, f"{name}:{diag.location}"))
        if advisory is None:
            continue
        if advisory.id in seen_ids:
            diagnostics.append(Diagnostic(
                DUPLICATE_ADVISORY_ID,
                f"公告 id {advisory.id!r} 与文件 {seen_ids[advisory.id]} 重复",
                f"{name}:$.id"))
            continue
        seen_ids[advisory.id] = name
        advisories.append(advisory)

    if diagnostics:
        raise AdvisoryError(diagnostics)
    return _build_set(advisories, files)


def _build_set(advisories: list[Advisory], files: list[str]) -> AdvisorySet:
    """由校验通过的公告构建等价组（与文件遍历顺序无关）。"""
    # 并查集：节点 = 公告 id 与全部别名
    parent: dict[str, str] = {}

    def find(node: str) -> str:
        root = node
        while parent[root] != root:
            root = parent[root]
        while parent[node] != root:
            parent[node], node = root, parent[node]
        return root

    def union(a: str, b: str) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[rb] = ra

    for advisory in advisories:
        parent.setdefault(advisory.id, advisory.id)
        for alias in advisory.aliases:
            parent.setdefault(alias, alias)
            union(advisory.id, alias)

    buckets: dict[str, set[str]] = {}
    for node in parent:
        buckets.setdefault(find(node), set()).add(node)

    advisory_by_id = {a.id: a for a in advisories}
    groups: list[Group] = []
    by_id: dict[str, Group] = {}
    for members in buckets.values():
        ordered = tuple(sorted(members))
        group = Group(display_id=ordered[0], member_ids=ordered)
        withdrawn = []
        related: set[str] = set()
        for member in ordered:
            advisory = advisory_by_id.get(member)
            if advisory is None:
                continue
            related.update(advisory.related)
            if advisory.is_withdrawn:
                withdrawn.append(member)
            else:
                group.advisories.append(advisory)
        group.advisories.sort(key=lambda a: a.id)
        group.withdrawn_ids = tuple(sorted(withdrawn))
        group.related_ids = tuple(sorted(related))
        groups.append(group)
        for member in ordered:
            by_id[member] = group

    groups.sort(key=lambda g: g.display_id)
    advisories_sorted = sorted(advisories, key=lambda a: a.id)
    return AdvisorySet(
        advisories=advisories_sorted, groups=groups,
        files=list(files), by_id=by_id)
