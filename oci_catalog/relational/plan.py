"""声明式计划的解析与全量校验（执行前完成，节点排列顺序无关）。

计划是一份纯 JSON 数据，不含任何可执行代码。校验在任何数据读取之前
全部完成，并保证：

* 输入表与节点**全局唯一命名**，重名即拒绝；
* 所有引用（source/上游节点、选列、过滤列、连接键、分组键、求和列）
  都能解析到具体对象，未知引用指出所在节点；
* 节点依赖构成 DAG：循环依赖明确指出回边上的节点；
* 拓扑序由依赖关系决定而不是声明顺序——同一份计划打乱节点顺序
  得到完全相同的执行顺序与结果。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from .contract import (
    SUPPORTED_TYPES,
    TYPE_DECIMAL,
    TYPE_INTEGER,
    TableContract,
)
from .expression import ExpressionError, compile_filter

NODE_SOURCE = "source"
NODE_SELECT = "select"
NODE_FILTER = "filter"
NODE_JOIN = "join"
NODE_GROUP = "group"
NODE_KINDS = frozenset(
    (NODE_SOURCE, NODE_SELECT, NODE_FILTER, NODE_JOIN, NODE_GROUP))

JOIN_INNER = "inner"
JOIN_LEFT = "left"

INPUT_FORMATS = frozenset(("csv", "jsonl"))


class PlanError(ValueError):
    """计划本身不合法；消息必须指出涉及的输入/节点名。"""


@dataclass(frozen=True)
class FileRef:
    image_digest: str
    path: str


@dataclass(frozen=True)
class InputSpec:
    name: str
    format: str
    files: tuple[FileRef, ...]
    contract: TableContract

    @property
    def schema(self) -> dict[str, str]:
        return {f.name: f.data_type for f in self.contract.fields}


@dataclass(frozen=True)
class SelectColumn:
    source: str
    alias: str


@dataclass(frozen=True)
class NodeSpec:
    name: str
    kind: str
    # 通用上游（source/select/filter/group 单输入；join 不用）
    input: Optional[str] = None
    # select
    columns: Optional[tuple[SelectColumn, ...]] = None
    # filter
    expression_text: Optional[str] = None
    expression: Any = field(default=None, compare=False)
    # join
    left: Optional[str] = None
    right: Optional[str] = None
    join_type: Optional[str] = None
    left_key: Optional[str] = None
    right_key: Optional[str] = None
    left_suffix: Optional[str] = None
    right_suffix: Optional[str] = None
    # group
    keys: Optional[tuple[str, ...]] = None
    count_alias: Optional[str] = None
    sum_column: Optional[str] = None
    sum_alias: Optional[str] = None
    # 校验期推导出的输出 schema（列名 -> 类型）
    output_schema: dict[str, str] = field(default_factory=dict, compare=False)
    # 校验期推导出的依赖（用于拓扑）
    dependencies: tuple[str, ...] = ()


@dataclass(frozen=True)
class Plan:
    inputs: dict[str, InputSpec]
    nodes: dict[str, NodeSpec]
    order: tuple[str, ...]          # 拓扑执行顺序（与声明顺序无关）


# ---------------------------------------------------------------------------
# 解析
# ---------------------------------------------------------------------------
def _require(obj: dict, key: str, owner: str) -> Any:
    if key not in obj:
        raise PlanError(f"{owner} 缺少必填字段 {key!r}")
    return obj[key]


def _as_name(value: Any, owner: str, key: str) -> str:
    if not isinstance(value, str) or not value:
        raise PlanError(f"{owner} 的 {key} 必须是非空字符串: {value!r}")
    return value


def _parse_inputs(raw: Any) -> dict[str, InputSpec]:
    if not isinstance(raw, list) or not raw:
        raise PlanError("计划 inputs 必须是非空数组")
    inputs: dict[str, InputSpec] = {}
    for item in raw:
        if not isinstance(item, dict):
            raise PlanError(f"输入声明必须是对象: {item!r}")
        name = _as_name(item.get("name"), "输入", "name")
        if name in inputs:
            raise PlanError(f"输入表重名: {name!r}")
        fmt = _require(item, "format", f"输入 {name!r}")
        if fmt not in INPUT_FORMATS:
            raise PlanError(
                f"输入 {name!r} 的 format {fmt!r} 不受支持，"
                f"可选 {sorted(INPUT_FORMATS)}")
        files_raw = _require(item, "files", f"输入 {name!r}")
        if not isinstance(files_raw, list) or not files_raw:
            raise PlanError(f"输入 {name!r} 的 files 必须是非空精确路径数组")
        files: list[FileRef] = []
        seen_files: set[tuple[str, str]] = set()
        for fr in files_raw:
            if not isinstance(fr, dict):
                raise PlanError(f"输入 {name!r} 的文件声明必须是对象: {fr!r}")
            image = _as_name(fr.get("image"), f"输入 {name!r}", "image")
            path = _as_name(fr.get("path"), f"输入 {name!r}", "path")
            if not path.startswith("/"):
                raise PlanError(
                    f"输入 {name!r} 的文件路径必须是视图内绝对路径: {path!r}")
            key = (image, path)
            if key in seen_files:
                raise PlanError(
                    f"输入 {name!r} 内文件重复声明: image={image} path={path}")
            seen_files.add(key)
            files.append(FileRef(image, path))
        try:
            contract = TableContract.from_dict(
                _require(item, "contract", f"输入 {name!r}"))
        except Exception as exc:
            if isinstance(exc, PlanError):
                raise
            raise PlanError(f"输入 {name!r} 契约不合法: {exc}") from exc
        inputs[name] = InputSpec(name=name, format=fmt,
                                 files=tuple(files), contract=contract)
    return inputs


def _parse_select_columns(raw: Any, owner: str) -> tuple[SelectColumn, ...]:
    if not isinstance(raw, list) or not raw:
        raise PlanError(f"节点 {owner!r} 的 columns 必须是非空数组")
    columns: list[SelectColumn] = []
    aliases: set[str] = set()
    for item in raw:
        if not isinstance(item, dict):
            raise PlanError(f"节点 {owner!r} 的选列声明必须是对象: {item!r}")
        source = _as_name(item.get("source"), f"节点 {owner!r}", "source")
        alias = item.get("alias", source)
        if not isinstance(alias, str) or not alias:
            raise PlanError(
                f"节点 {owner!r} 的选列别名必须是非空字符串: {alias!r}")
        if alias in aliases:
            raise PlanError(f"节点 {owner!r} 的输出列重名: {alias!r}")
        aliases.add(alias)
        columns.append(SelectColumn(source=source, alias=alias))
    return tuple(columns)


def _parse_node(raw: dict) -> NodeSpec:
    name = _as_name(raw.get("name"), "节点", "name")
    kind = _require(raw, "kind", f"节点 {name!r}")
    if kind not in NODE_KINDS:
        raise PlanError(
            f"节点 {name!r} 的 kind {kind!r} 不受支持，"
            f"可选 {sorted(NODE_KINDS)}")
    node = NodeSpec(name=name, kind=kind)
    if kind == NODE_SOURCE:
        node = _finish_source(node, raw)
    elif kind == NODE_SELECT:
        node = _finish_select(node, raw)
    elif kind == NODE_FILTER:
        node = _finish_filter(node, raw)
    elif kind == NODE_JOIN:
        node = _finish_join(node, raw)
    else:
        node = _finish_group(node, raw)
    return node


def _simple_input(raw: dict, node: NodeSpec) -> NodeSpec:
    upstream = _as_name(_require(raw, "input", f"节点 {node.name!r}"),
                        f"节点 {node.name!r}", "input")
    return NodeSpec(name=node.name, kind=node.kind, input=upstream)


def _finish_source(node: NodeSpec, raw: dict) -> NodeSpec:
    source_name = _as_name(_require(raw, "input", f"节点 {node.name!r}"),
                           f"节点 {node.name!r}", "input")
    return NodeSpec(name=node.name, kind=NODE_SOURCE, input=source_name,
                    dependencies=(source_name,))


def _finish_select(node: NodeSpec, raw: dict) -> NodeSpec:
    base = _simple_input(raw, node)
    columns = _parse_select_columns(
        _require(raw, "columns", f"节点 {node.name!r}"), node.name)
    return NodeSpec(name=node.name, kind=NODE_SELECT, input=base.input,
                    columns=columns, dependencies=(base.input,))


def _finish_filter(node: NodeSpec, raw: dict) -> NodeSpec:
    base = _simple_input(raw, node)
    expression_text = _require(raw, "expression", f"节点 {node.name!r}")
    if not isinstance(expression_text, str) or not expression_text.strip():
        raise PlanError(
            f"节点 {node.name!r} 的 expression 必须是非空字符串")
    return NodeSpec(name=node.name, kind=NODE_FILTER, input=base.input,
                    expression_text=expression_text,
                    dependencies=(base.input,))


def _finish_join(node: NodeSpec, raw: dict) -> NodeSpec:
    left = _as_name(_require(raw, "left", f"节点 {node.name!r}"),
                    f"节点 {node.name!r}", "left")
    right = _as_name(_require(raw, "right", f"节点 {node.name!r}"),
                     f"节点 {node.name!r}", "right")
    join_type = _require(raw, "join_type", f"节点 {node.name!r}")
    if join_type not in (JOIN_INNER, JOIN_LEFT):
        raise PlanError(
            f"节点 {node.name!r} 的 join_type 只能是 inner/left: "
            f"{join_type!r}")
    left_key = _as_name(_require(raw, "left_key", f"节点 {node.name!r}"),
                        f"节点 {node.name!r}", "left_key")
    right_key = _as_name(_require(raw, "right_key", f"节点 {node.name!r}"),
                         f"节点 {node.name!r}", "right_key")
    left_suffix = _require(raw, "left_suffix", f"节点 {node.name!r}")
    right_suffix = _require(raw, "right_suffix", f"节点 {node.name!r}")
    for label, suffix in (("left_suffix", left_suffix),
                          ("right_suffix", right_suffix)):
        if not isinstance(suffix, str) or not suffix:
            raise PlanError(
                f"节点 {node.name!r} 的 {label} 必须是非空字符串")
    if left_suffix == right_suffix:
        raise PlanError(
            f"节点 {node.name!r} 的 left_suffix 与 right_suffix 不能相同")
    return NodeSpec(name=node.name, kind=NODE_JOIN, left=left, right=right,
                    join_type=join_type, left_key=left_key,
                    right_key=right_key, left_suffix=left_suffix,
                    right_suffix=right_suffix,
                    dependencies=(left, right))


def _finish_group(node: NodeSpec, raw: dict) -> NodeSpec:
    base = _simple_input(raw, node)
    keys_raw = _require(raw, "keys", f"节点 {node.name!r}")
    if not isinstance(keys_raw, list) or not keys_raw:
        raise PlanError(f"节点 {node.name!r} 的 keys 必须是非空数组")
    keys: list[str] = []
    for key in keys_raw:
        if not isinstance(key, str) or not key:
            raise PlanError(
                f"节点 {node.name!r} 的分组键必须是非空字符串: {key!r}")
        if key in keys:
            raise PlanError(f"节点 {node.name!r} 的分组键重复: {key!r}")
        keys.append(key)
    count_alias = _as_name(_require(raw, "count_alias",
                                    f"节点 {node.name!r}"),
                           f"节点 {node.name!r}", "count_alias")
    sum_column = _require(raw, "sum_column", f"节点 {node.name!r}")
    sum_alias = _as_name(_require(raw, "sum_alias", f"节点 {node.name!r}"),
                         f"节点 {node.name!r}", "sum_alias")
    aliases = set(keys)
    for label, alias in (("count_alias", count_alias),
                         ("sum_alias", sum_alias)):
        if alias in aliases:
            raise PlanError(
                f"节点 {node.name!r} 的 {label} {alias!r} 与分组键或其他"
                f"输出列重名")
        aliases.add(alias)
    return NodeSpec(name=node.name, kind=NODE_GROUP, input=base.input,
                    keys=tuple(keys), count_alias=count_alias,
                    sum_column=sum_column, sum_alias=sum_alias,
                    dependencies=(base.input,))


# ---------------------------------------------------------------------------
# 全量校验
# ---------------------------------------------------------------------------
def _topological_order(nodes: dict[str, NodeSpec],
                       all_names: set[str]) -> tuple[str, ...]:
    """Kahn 拓扑：邻接按名字典序固定，结果只依赖依赖关系，不依赖声明顺序。

    输入表是只有入边、没有出依赖的根节点，一并纳入邻接表初始化。
    """
    indegree = {name: 0 for name in nodes}
    adjacency: dict[str, list[str]] = {name: [] for name in all_names}
    for name, node in nodes.items():
        for dep in node.dependencies:
            indegree[name] += 1
            adjacency[dep].append(name)
    # 零入度根是输入表（不在 nodes 里）；用全部名字里的零入度项播种
    indegree_full = dict(indegree)
    for name in all_names:
        indegree_full.setdefault(name, 0)
    ready = sorted(name for name, degree in indegree_full.items()
                   if degree == 0)
    order: list[str] = []
    while ready:
        current = ready.pop(0)
        order.append(current)
        for downstream in sorted(adjacency[current]):
            indegree_full[downstream] -= 1
            if indegree_full[downstream] == 0:
                ready.append(downstream)
                ready.sort()
    node_order = [name for name in order if name in nodes]
    if len(node_order) != len(nodes):
        remaining = sorted(set(nodes) - set(node_order))
        cycle_nodes = _find_cycle_nodes(nodes, remaining)
        raise PlanError(
            f"节点依赖存在循环，涉及环上节点（按发现顺序）: {cycle_nodes}")
    return tuple(node_order)


def _find_cycle_nodes(nodes: dict[str, NodeSpec],
                      candidates: list[str]) -> list[str]:
    """在剩余子图里用 DFS 找出一条具体回边，返回环上节点名。"""
    candidate_set = set(candidates)
    state: dict[str, int] = {}  # 0=未访问 1=在栈上 2=完成
    stack: list[str] = []

    def visit(name: str) -> Optional[list[str]]:
        state[name] = 1
        stack.append(name)
        node = nodes[name]
        for dep in sorted(node.dependencies):
            if dep not in candidate_set:
                continue
            if state.get(dep, 0) == 1:
                idx = stack.index(dep)
                return stack[idx:] + [dep]
            if state.get(dep, 0) == 0:
                found = visit(dep)
                if found:
                    return found
        stack.pop()
        state[name] = 2
        return None

    for name in sorted(candidate_set):
        if state.get(name, 0) == 0:
            found = visit(name)
            if found:
                return found
    return candidates  # pragma: no cover - 理论不可达


def _resolve_ref(name: str, schemas: dict[str, dict[str, str]],
                 owner: str, label: str) -> dict[str, str]:
    if name not in schemas:
        raise PlanError(
            f"节点 {owner!r} 的 {label} 引用了未知输入/节点 {name!r}")
    return schemas[name]


def _validate_node_schemas(plan_inputs: dict[str, InputSpec],
                           nodes: dict[str, NodeSpec],
                           order: tuple[str, ...]) -> dict[str, NodeSpec]:
    """按拓扑序推导每个节点的输出 schema，并做引用/类型级校验。"""
    schemas: dict[str, dict[str, str]] = {
        name: dict(input_spec.schema)
        for name, input_spec in plan_inputs.items()
    }
    validated: dict[str, NodeSpec] = {}
    for name in order:
        node = nodes[name]
        if node.kind == NODE_SOURCE:
            _resolve_ref(node.input, schemas, name, "input")
            schema = dict(schemas[node.input])
        elif node.kind == NODE_SELECT:
            upstream = _resolve_ref(node.input, schemas, name, "input")
            schema = {}
            for column in node.columns:
                if column.source not in upstream:
                    raise PlanError(
                        f"节点 {name!r} 选列引用了 {node.input!r} 上不存在"
                        f"的列 {column.source!r}")
                schema[column.alias] = upstream[column.source]
        elif node.kind == NODE_FILTER:
            upstream = _resolve_ref(node.input, schemas, name, "input")
            try:
                bound = compile_filter(node.expression_text, upstream)
            except ExpressionError as exc:
                raise PlanError(
                    f"节点 {name!r} 的过滤表达式不合法: {exc}") from exc
            node = NodeSpec(**{**node.__dict__, "expression": bound})
            schema = dict(upstream)
        elif node.kind == NODE_JOIN:
            schema = _join_schema(node, schemas)
        else:
            schema = _group_schema(node, schemas)
        schemas[name] = schema
        validated[name] = NodeSpec(**{**node.__dict__,
                                      "output_schema": schema})
    return validated


def _join_schema(node: NodeSpec,
                 schemas: dict[str, dict[str, str]]) -> dict[str, str]:
    left_schema = _resolve_ref(node.left, schemas, node.name, "left")
    right_schema = _resolve_ref(node.right, schemas, node.name, "right")
    if node.left_key not in left_schema:
        raise PlanError(
            f"连接节点 {node.name!r} 的 left_key {node.left_key!r} "
            f"在左侧 {node.left!r} 上不存在")
    if node.right_key not in right_schema:
        raise PlanError(
            f"连接节点 {node.name!r} 的 right_key {node.right_key!r} "
            f"在右侧 {node.right!r} 上不存在")
    # 键类型必须一致（null 不互相匹配是运行时规则，这里保证可比）
    if left_schema[node.left_key] != right_schema[node.right_key]:
        raise PlanError(
            f"连接节点 {node.name!r} 的键类型不一致: "
            f"{left_schema[node.left_key]} vs "
            f"{right_schema[node.right_key]}")

    schema: dict[str, str] = {}
    # 左侧列原名；与右侧重名的非键列加左后缀
    left_collisions = (set(left_schema) & set(right_schema))
    for column, data_type in left_schema.items():
        out_name = column + node.left_suffix if column in left_collisions \
            else column
        if out_name in schema:
            raise PlanError(
                f"连接节点 {node.name!r} 左列改名后仍重名: {out_name!r}")
        schema[out_name] = data_type
    for column, data_type in right_schema.items():
        out_name = column + node.right_suffix if column in left_collisions \
            else column
        if out_name in schema:
            raise PlanError(
                f"连接节点 {node.name!r} 右列改名后与左侧重名: {out_name!r}；"
                f"请调整 suffix 避免冲突")
        schema[out_name] = data_type
    return schema


def _group_schema(node: NodeSpec,
                  schemas: dict[str, dict[str, str]]) -> dict[str, str]:
    upstream = _resolve_ref(node.input, schemas, node.name, "input")
    for key in node.keys:
        if key not in upstream:
            raise PlanError(
                f"分组节点 {node.name!r} 的分组键 {key!r} 在上游 "
                f"{node.input!r} 上不存在")
    if node.sum_column not in upstream:
        raise PlanError(
            f"分组节点 {node.name!r} 的 sum_column {node.sum_column!r} "
            f"在上游 {node.input!r} 上不存在")
    sum_type = upstream[node.sum_column]
    if sum_type not in (TYPE_INTEGER, TYPE_DECIMAL):
        raise PlanError(
            f"分组节点 {node.name!r} 的 sum_column {node.sum_column!r} "
            f"类型为 {sum_type}，只能对 integer/decimal 求和")
    schema = {key: upstream[key] for key in node.keys}
    schema[node.count_alias] = TYPE_INTEGER
    schema[node.sum_alias] = sum_type
    return schema


def parse_plan(raw: dict) -> Plan:
    """解析并全量校验一份计划字典，返回带拓扑序与推导 schema 的 Plan。"""
    if not isinstance(raw, dict):
        raise PlanError("计划必须是 JSON 对象")
    inputs = _parse_inputs(raw.get("inputs"))
    nodes_raw = raw.get("nodes")
    if not isinstance(nodes_raw, list) or not nodes_raw:
        raise PlanError("计划 nodes 必须是非空数组")

    nodes: dict[str, NodeSpec] = {}
    all_names = set(inputs)
    for item in nodes_raw:
        if not isinstance(item, dict):
            raise PlanError(f"节点声明必须是对象: {item!r}")
        node = _parse_node(item)
        if node.name in all_names:
            raise PlanError(f"名字在输入表/节点间重复: {node.name!r}")
        all_names.add(node.name)
        nodes[node.name] = node

    # 依赖引用存在性（先于拓扑，错误信息更直接）
    for node in nodes.values():
        for dep in node.dependencies:
            if dep not in all_names:
                raise PlanError(
                    f"节点 {node.name!r} 依赖了不存在的输入/节点 {dep!r}")
            if dep == node.name:
                raise PlanError(f"节点 {node.name!r} 不能依赖自身")

    order = _topological_order(nodes, all_names)
    validated = _validate_node_schemas(inputs, nodes, order)
    return Plan(inputs=inputs, nodes=validated, order=order)


def load_plan(path: str) -> Plan:
    """从 UTF-8 JSON 文件加载计划。"""
    import json
    try:
        with open(path, encoding="utf-8") as fh:
            raw = json.load(fh)
    except OSError as exc:
        raise PlanError(f"无法读取计划文件 {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise PlanError(f"计划文件不是合法 JSON: {exc}") from exc
    return parse_plan(raw)
