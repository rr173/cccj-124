"""离线关系加工子系统：把镜像文件视图中的 CSV/JSONL 接成可查询数据表。

模块划分：

* :mod:`oci_catalog.relational.contract`   —— 字段契约、严格类型转换与
  定点十进制（不经过二进制浮点）、单记录校验
* :mod:`oci_catalog.relational.sources`    —— 只读文件视图取字节、
  UTF-8 CSV / 逐行 JSON 解析与物理行定位
* :mod:`oci_catalog.relational.expression` —— 受限过滤表达语言
  （手写词法/语法分析 + 三值逻辑，无 eval）
* :mod:`oci_catalog.relational.plan`       —— 声明式计划解析与全量校验
  （重名/未知引用/循环依赖，拓扑序与声明顺序无关）
* :mod:`oci_catalog.relational.engine`     —— 选列/过滤/连接/分组执行
  与逐行血缘多重集
* :mod:`oci_catalog.relational.store`      —— 独立 SQLite 结果库、
  单事务原子落库、新进程查询/追溯/CSV 导出
* :mod:`oci_catalog.relational.api`        —— 可调用 Python 接口
* :mod:`oci_catalog.relational.relational_cli` —— 命令行入口

本子系统只读访问目录库与文件视图库，不访问 registry，不把镜像路径当
宿主路径打开；计划不含任何可执行 Python/SQL，不能表达任意代码。
"""

from .contract import (
    SUPPORTED_TYPES,
    FieldSpec,
    RejectedRecord,
    TableContract,
    decimal_sum,
    parse_decimal,
    parse_integer,
)
from .engine import Engine, NodeResult, Row, RunArtifacts, SourceKey
from .expression import (
    ExpressionError,
    compile_filter,
    evaluate,
    parse_expression,
    validate_expression,
)
from .plan import (
    JOIN_INNER,
    JOIN_LEFT,
    NODE_FILTER,
    NODE_GROUP,
    NODE_JOIN,
    NODE_SELECT,
    NODE_SOURCE,
    FileRef,
    InputSpec,
    Plan,
    PlanError,
    load_plan,
    parse_plan,
)
from .sources import (
    FORMAT_CSV,
    FORMAT_JSONL,
    ParsedRecord,
    ParsedTable,
    ReadOnlyViewReader,
    Rejection,
    SourceLocation,
    SourceReadError,
    parse_csv_table,
    parse_jsonl_table,
)
from .store import (
    NodeNotFoundError,
    OutputConflictError,
    RelationalStore,
    RunHandle,
    RunNotFoundError,
)
from .api import RunOutcome, open_result_store, run_plan

__all__ = [
    # 契约与类型
    "SUPPORTED_TYPES", "FieldSpec", "TableContract", "RejectedRecord",
    "parse_integer", "parse_decimal", "decimal_sum",
    # 表达式
    "ExpressionError", "parse_expression", "validate_expression",
    "compile_filter", "evaluate",
    # 计划
    "Plan", "PlanError", "parse_plan", "load_plan", "InputSpec", "FileRef",
    "NODE_SOURCE", "NODE_SELECT", "NODE_FILTER", "NODE_JOIN", "NODE_GROUP",
    "JOIN_INNER", "JOIN_LEFT",
    # 源
    "FORMAT_CSV", "FORMAT_JSONL", "ReadOnlyViewReader", "SourceReadError",
    "ParsedTable", "ParsedRecord", "Rejection", "SourceLocation",
    "parse_csv_table", "parse_jsonl_table",
    # 引擎
    "Engine", "Row", "NodeResult", "RunArtifacts", "SourceKey",
    # 存储与 API
    "RelationalStore", "RunHandle", "RunNotFoundError", "NodeNotFoundError",
    "OutputConflictError", "run_plan", "open_result_store", "RunOutcome",
]
