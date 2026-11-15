"""关系加工执行引擎：在已校验计划上做纯内存变换，并全程携带血缘。

设计要点：

* 输入行在解析阶段即获得**源记录标识**（输入表 + 文件 + 记录序号），
  之后每一步只做引用合并，不复制数据、不丢失来源；
* 血缘是**多重集**：``(source_key, multiplicity)``。同一源记录经一对多
  连接参与多条结果时，贡献次数自然累乘；去重排序发生在查询期；
* 选列/过滤保持血缘不变；连接合并两侧真实配对的来源，左连接未匹配
  行只有左侧来源（空侧绝不虚构）；分组只合并真正进入该组的行；
* 所有输出顺序都是确定性的：非分组节点保持上游行序，分组节点按
  分组键稳定排序（NULL 组排在最前）。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any, Optional

from .contract import TYPE_INTEGER, decimal_sum
from .expression import evaluate
from .plan import (
    JOIN_INNER,
    NODE_FILTER,
    NODE_GROUP,
    NODE_JOIN,
    NODE_SELECT,
    NODE_SOURCE,
    InputSpec,
    NodeSpec,
    Plan,
)
from .sources import ParsedRecord, ParsedTable


@dataclass(frozen=True)
class SourceKey:
    """源记录的稳定身份键（落库后可直接映射回 source_records 行）。"""

    table_name: str
    image_digest: str
    file_path: str
    record_seq: int


@dataclass
class Row:
    """引擎中的一行：列值 + 血缘多重集（SourceKey -> 贡献次数）。"""

    values: dict[str, Any]
    lineage: dict[SourceKey, int] = field(default_factory=dict)

    def ref_count(self) -> int:
        return sum(self.lineage.values())


@dataclass
class NodeResult:
    name: str
    kind: str
    schema: dict[str, str]
    rows: list[Row]


@dataclass
class RunArtifacts:
    """一次成功加工的全部内存产物（落库前）。"""

    plan: Plan
    tables: dict[str, ParsedTable]
    node_results: dict[str, NodeResult]

    def source_records(self) -> list[tuple[SourceKey, ParsedRecord]]:
        """按确定顺序枚举全部合格源记录。"""
        out: list[tuple[SourceKey, ParsedRecord]] = []
        for table_name in sorted(self.tables):
            table = self.tables[table_name]
            for record in table.records:
                loc = record.location
                key = SourceKey(table_name, loc.image_digest,
                                loc.file_path, loc.record_seq)
                out.append((key, record))
        return out


class Engine:
    """按计划拓扑序执行；输入表已由解析层读入。"""

    def __init__(self, plan: Plan, tables: dict[str, ParsedTable]):
        self.plan = plan
        self.tables = tables
        self.results: dict[str, NodeResult] = {}

    def run(self) -> RunArtifacts:
        for name in self.plan.order:
            node = self.plan.nodes[name]
            if node.kind == NODE_SOURCE:
                self.results[name] = self._exec_source(node)
            elif node.kind == NODE_SELECT:
                self.results[name] = self._exec_select(node)
            elif node.kind == NODE_FILTER:
                self.results[name] = self._exec_filter(node)
            elif node.kind == NODE_JOIN:
                self.results[name] = self._exec_join(node)
            else:
                self.results[name] = self._exec_group(node)
        return RunArtifacts(plan=self.plan, tables=self.tables,
                           node_results=self.results)

    # ------------------------------------------------------------------
    def _exec_source(self, node: NodeSpec) -> NodeResult:
        input_spec: InputSpec = self.plan.inputs[node.input]
        table = self.tables[node.input]
        rows: list[Row] = []
        for record in table.records:
            loc = record.location
            key = SourceKey(node.input, loc.image_digest,
                            loc.file_path, loc.record_seq)
            rows.append(Row(values=dict(record.values),
                            lineage={key: 1}))
        return NodeResult(node.name, node.kind,
                          dict(input_spec.schema), rows)

    def _exec_select(self, node: NodeSpec) -> NodeResult:
        upstream = self.results[node.input]
        rows: list[Row] = []
        for row in upstream.rows:
            values = {col.alias: row.values[col.source]
                      for col in node.columns}
            # 选列不改血缘：来源仍是同一批记录、同样的贡献次数
            rows.append(Row(values=values, lineage=dict(row.lineage)))
        return NodeResult(node.name, node.kind,
                          dict(node.output_schema), rows)

    def _exec_filter(self, node: NodeSpec) -> NodeResult:
        upstream = self.results[node.input]
        rows: list[Row] = []
        for row in upstream.rows:
            # 三值逻辑：只有 TRUE 保留，FALSE/UNKNOWN 都排除
            if evaluate(node.expression, row.values) is True:
                rows.append(Row(values=dict(row.values),
                                lineage=dict(row.lineage)))
        return NodeResult(node.name, node.kind,
                          dict(node.output_schema), rows)

    def _exec_join(self, node: NodeSpec) -> NodeResult:
        left = self.results[node.left]
        right = self.results[node.right]
        left_schema = self.plan.nodes[node.left].output_schema
        right_schema = self.plan.nodes[node.right].output_schema
        collisions = set(left_schema) & set(right_schema)

        index = self._build_join_index(right.rows, node.right_key)
        rows: list[Row] = []
        for left_row in left.rows:
            key_value = left_row.values[node.left_key]
            matches = index.get(self._index_key(key_value), [])
            if not matches:
                if node.join_type == JOIN_INNER:
                    continue
                rows.append(self._left_unmatched(node, left_row,
                                                 right_schema, collisions))
                continue
            for right_row in matches:
                rows.append(self._join_pair(node, left_row, right_row,
                                            right_schema, collisions))
        return NodeResult(node.name, node.kind,
                          dict(node.output_schema), rows)

    @staticmethod
    def _index_key(value: Any) -> Any:
        # None 单独成键且绝不与任何值（含 None）匹配：直接用哨兵
        return _NULL_SENTINEL if value is None else value

    def _build_join_index(self, rows: list[Row],
                          key_name: str) -> dict[Any, list[Row]]:
        index: dict[Any, list[Row]] = {}
        for row in rows:
            value = row.values[key_name]
            if value is None:
                continue  # 空键不进入索引 -> 不可能匹配任何行
            index.setdefault(value, []).append(row)
        return index

    def _join_pair(self, node: NodeSpec, left_row: Row, right_row: Row,
                   right_schema: dict[str, str],
                   collisions: set[str]) -> Row:
        values = self._project_left(node, left_row, collisions)
        for column in right_schema:
            out_name = column + node.right_suffix \
                if column in collisions else column
            values[out_name] = right_row.values[column]
        lineage = dict(left_row.lineage)
        for key, multiplicity in right_row.lineage.items():
            lineage[key] = lineage.get(key, 0) + multiplicity
        return Row(values=values, lineage=lineage)

    def _left_unmatched(self, node: NodeSpec, left_row: Row,
                        right_schema: dict[str, str],
                        collisions: set[str]) -> Row:
        values = self._project_left(node, left_row, collisions)
        for column, data_type in right_schema.items():
            out_name = column + node.right_suffix \
                if column in collisions else column
            values[out_name] = None  # 左连接空侧补 null，不虚构来源
        return Row(values=values, lineage=dict(left_row.lineage))

    def _project_left(self, node: NodeSpec, left_row: Row,
                      collisions: set[str]) -> dict[str, Any]:
        left_schema = self.plan.nodes[node.left].output_schema
        values: dict[str, Any] = {}
        for column in left_schema:
            out_name = column + node.left_suffix \
                if column in collisions else column
            values[out_name] = left_row.values[column]
        return values

    def _exec_group(self, node: NodeSpec) -> NodeResult:
        upstream = self.results[node.input]
        groups: dict[tuple, dict[str, Any]] = {}
        order: list[tuple] = []
        for row in upstream.rows:
            key = tuple(row.values[k] for k in node.keys)
            bucket = groups.get(key)
            if bucket is None:
                bucket = {"rows": [], "lineage": {}}
                groups[key] = bucket
                order.append(key)
            bucket["rows"].append(row)
            for source_key, multiplicity in row.lineage.items():
                bucket["lineage"][source_key] = \
                    bucket["lineage"].get(source_key, 0) + multiplicity

        # 稳定排序：None 键最前，其余按分组键自然序
        ordered_keys = sorted(order, key=_group_sort_key)
        rows: list[Row] = []
        for key in ordered_keys:
            bucket = groups[key]
            members: list[Row] = bucket["rows"]
            values = {column: value for column, value in
                      zip(node.keys, key)}
            values[node.count_alias] = len(members)
            values[node.sum_alias] = self._sum_members(node, members)
            rows.append(Row(values=values, lineage=dict(bucket["lineage"])))
        return NodeResult(node.name, node.kind,
                          dict(node.output_schema), rows)

    @staticmethod
    def _sum_members(node: NodeSpec, members: list[Row]) -> Any:
        raw = [row.values[node.sum_column] for row in members]
        # 空输入不会产生任何组；此处每个组至少有一行
        if node.output_schema[node.sum_alias] == TYPE_INTEGER:
            return sum(value for value in raw if value is not None)
        return decimal_sum(raw)


_NULL_SENTINEL = object()


def _group_sort_key(key: tuple) -> tuple:
    """NULL 分组键排在最前，其余按值排序；Decimal 与 int 可直接比较。"""
    return tuple((0, 0) if value is None else (1, value) for value in key)
