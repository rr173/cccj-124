# 离线关系加工（声明式计划 → 可查询业务结果 + 逐行血缘）

把封在镜像文件视图里的离线数据（按日期分区的订单 CSV、逐行 JSON 客户
归属、一对多费用表）接成可查询的关系结果。交付人员只需提交一份
**声明式计划**，指定已有文件视图中的数据文件、字段契约与加工步骤，
即可得到订单明细、客户汇总等业务结果，并能对任意结果行追溯“它由哪几条
原始记录贡献、各贡献几次”。

* **不执行任意 Python 或 SQL**：过滤条件是受限表达语言，手写词法/语法
  分析 + 三值逻辑，没有 `eval`、没有字符串拼执行；
* **不访问 registry，不打开镜像宿主路径**：文件字节只经只读文件视图
  接口 `read_file_bytes` 取得，目录库与视图库都以 `mode=ro` 打开；
* 结果落在**独立 SQLite 库**，与目录库、SBOM 库、视图库物理隔离；
* 一次成功落库对应整份已校验计划，单事务提交，失败不留半成品。

## 模块划分

```
oci_catalog/relational/
├── contract.py          # 字段契约、严格类型/定点十进制、单记录校验
├── sources.py           # 只读视图取字节、CSV/JSONL 解析、物理行定位
├── expression.py        # 受限过滤表达（手写分析器、三值逻辑、无 eval）
├── plan.py              # 计划解析与全量校验（重名/未知引用/循环/拓扑）
├── engine.py            # 选列/过滤/连接/分组执行与血缘多重集
├── store.py             # 独立 SQLite 库、原子落库、查询/追溯/CSV 导出
├── api.py               # 可调用 Python 接口 run_plan / open_result_store
├── relational_cli.py    # 命令行入口（python3 -m ...）
├── sample_relational.py # 可完全本地重建的演示数据与计划
└── sample_plan.json     # 计划格式样板（含注释性字段）
```

## 计划格式

计划是一份 UTF-8 JSON，顶层只有 `inputs` 与 `nodes` 两段。

### 输入表（inputs）

每个输入表有唯一 `name`、`format`（`csv` / `jsonl`）、一个或多个
**精确路径**（每个文件给出视图镜像 digest 与视图内绝对路径），以及
字段契约 `contract`。

```json
{
  "name": "orders",
  "format": "csv",
  "files": [
    {"image": "sha256:....", "path": "/data/orders/dt=2026-11-01/orders.csv"},
    {"image": "sha256:....", "path": "/data/orders/dt=2026-11-02/orders.csv"}
  ],
  "contract": {
    "missing": "reject",
    "empty_string": "null",
    "extra_fields": "reject",
    "fields": [
      {"name": "order_id", "type": "string",  "nullable": false},
      {"name": "cust_id",   "type": "string",  "nullable": true},
      {"name": "amount",    "type": "decimal", "nullable": false},
      {"name": "qty",       "type": "integer", "nullable": false}
    ]
  }
}
```

#### 类型（`type`）

| 类型 | 接受 | 拒绝 |
|---|---|---|
| `string` | Unicode 字符串 | 数字标量（不隐式 `str()`）、非字符串 |
| `integer` | 整数字面量字符串 `"12"`/`"-3"`、JSON 整数 | `1.0`、`" 1 "`、科学计数法、布尔 |
| `decimal` | 定点字符串 `"0.10"`、JSON 整数 | JSON 浮点、`1e3`、`NaN`/`Infinity`、布尔 |

`decimal` 内部用 `decimal.Decimal` 精确表示，**不经过二进制浮点、不
截断**；`0.10 + 0.20 = 0.30`，存储与导出都保留定点字面量。

#### 空值策略（在契约里显式声明）

* `missing`：JSON 缺键如何处理 —— `reject`（拒绝该记录）/ `null`
  （可空字段转 null；不可空字段仍拒绝）；
* `empty_string`：空字符串如何处理 —— `reject` / `null`（可空字段转
  null）/ `keep`（仅 string 字段，空串作为普通值保留）；
* `extra_fields`：契约外字段 —— `reject`（记录级拒绝）/ `ignore`
  （丢弃额外字段）；
* 显式 JSON `null`：`nullable=true` 的字段转 null，否则记录级拒绝。

记录级不合约（坏值、缺字段、额外字段、非对象 JSON 行等）只拒绝该条，
原始值、文件、记录序号、物理行与原因写入拒绝明细，其它记录继续。
文件不存在、编码损坏、CSV 结构损坏（重复表头、缺契约列、列宽不符）与
计划本身不合法则**拒绝整次加工**。

### 加工节点（nodes）

节点全局唯一命名，靠名字连接；执行顺序由依赖拓扑决定，**与声明顺序
无关**。支持五种节点：

| kind | 关键字段 | 语义 |
|---|---|---|
| `source` | `input`（输入表名） | 把输入表接入节点图 |
| `select` | `input`、`columns:[{source, alias?}]` | 选列与改名 |
| `filter` | `input`、`expression` | 带类型检查的过滤（三值逻辑） |
| `join` | `left`/`right`、`join_type`（`inner`/`left`）、`left_key`/`right_key`、`left_suffix`/`right_suffix` | 等值连接 |
| `group` | `input`、`keys`、`count_alias`、`sum_column`、`sum_alias` | 分组计数与十进制/整数求和 |

#### 过滤表达式（受限语言，无 eval）

```
expr      := or_expr
or_expr   := and_expr ( OR and_expr )*
and_expr  := not_expr ( AND not_expr )*
not_expr  := NOT not_expr | '(' expr ')' | comparison
comparison := operand ( = | != | < | <= | > | >= ) operand
operand   := 字段引用 | 常量
字段引用   := 裸标识符 order_id  |  双引号标识符 "order-id"
常量       := NULL | '单引号字符串'（'' 转义） | 123 整数 | 1.50 定点数
```

* 列引用、常量类型在计划校验期逐一核对，未知列、跨类型比较是计划级错误；
* 三值逻辑：任一侧为 NULL 的比较结果是 UNKNOWN；只有最终为 TRUE 的行
  保留，FALSE/UNKNOWN 都过滤；`AND/OR/NOT` 遵循 SQL 真值表；
* 没有算术、函数、属性访问、可执行代码路径；`__import__('os')` 等
  形态无法通过词法。

#### 连接规则

* 仅等值内连接 / 左连接；**空键不彼此匹配**（NULL 永不等于任何值）；
* 重复键保留**全部匹配组合**（笛卡尔展开）；
* 左连接找不到右行时右侧列补 null，且**不虚构右侧来源**；
* 左右重名列分别加 `left_suffix`/`right_suffix`（两个后缀必须不同且
  非空），不重名的列保留原名。

#### 分组规则

* 按 `keys` 等值分组，NULL 键自成一组且排序在最前；
* `count` 计组成员行数；`sum` 对 integer/decimal 列求和，null 值跳过，
  decimal 精确求和；
* **空输入不产生任何分组**（不虚构零值行）。

## 血缘（逐行来源追溯）

每条源记录保存：镜像 image digest、文件路径、**记录序号**与
**物理起始/结束行**。CSV 一条记录被引号换行拆成多行时，记录序号与
物理行号分别记录、不混淆。

* 选列/过滤保持血缘不变；
* 内连接合并实际配对的两侧来源；左连接未匹配行只有左侧来源；
* 分组只合并真正进入该组的行；同一源记录经一对多连接参与多条结果时，
  其**贡献次数（contribution）**在该结果行内累加；
* 追溯返回去重、按（表、digest、文件、序号）稳定排序的源记录及原始
  字段值。

结果行 ID 是落库时生成并持久化的整数，只在该 run 内稳定，新进程按
（run_id、节点名、row_id）即可追溯，不依赖任何内存对象。

## 运行方式

```bash
# 执行计划（成功落库；计划/读取失败退出码 2）
python3 -m oci_catalog.relational.relational_cli run \
    --plan plan.json --output results.db \
    --views views.db --catalog catalog.db

# 列 run / 节点 / 结果行 / 拒绝明细
python3 -m oci_catalog.relational.relational_cli --output results.db runs
python3 -m oci_catalog.relational.relational_cli --output results.db nodes --run 1
python3 -m oci_catalog.relational.relational_cli --output results.db rows  --run 1 --node region_summary
python3 -m oci_catalog.relational.relational_cli --output results.db rejections --run 1

# 按结果行 ID 追溯源记录与贡献次数
python3 -m oci_catalog.relational.relational_cli --output results.db trace \
    --run 1 --node region_summary --row-id 32

# 导出节点为 UTF-8 CSV
python3 -m oci_catalog.relational.relational_cli --output results.db \
    export --run 1 --node region_summary > summary.csv
```

Python 接口：

```python
from oci_catalog.relational import run_plan, open_result_store

outcome = run_plan(plan_dict, "results.db", "views.db", "catalog.db")
if not outcome.ok:
    print(outcome.error_code, outcome.error_message)   # 失败不留半成品
else:
    store = open_result_store("results.db")            # 只读，新进程可用
    rid = outcome.handle.run_id
    store.fetch_rows(rid, "region_summary")
    store.trace_row(rid, "region_summary", row_id=32)
    store.export_node_csv(rid, "region_summary")
```

## 端到端演示（可完全本地重建）

```bash
python3 -I run_relational_demo.py
```

演示链：两个日期分区订单（含一个只含表头的空分区）合成一个输入表 →
过滤撤销订单 → 与客户表左连接 → 与一对多费用表内连接 → 按地区汇总
金额；随后在**独立新进程**里按 `verify_relational_demo.py` 中手写的
期待值核对每条明细、分组金额、拒绝行与每条汇总的来源集合/贡献次数。
样例内置：无客户订单、null 连接键、重复收费键、引号内逗号+换行字段、
坏金额/坏整数、非对象 JSON 行，并验证节点乱序可执行、循环/缺列执行前
拒绝、空分区聚合、读取失败与输出库路径冲突均无成功半成品。
