"""可完全本地重建的关系加工演示数据（全部由代码生成，无外部依赖）。

构造两个镜像的文件视图（经既有目录库 + 文件视图机制构建）：

* **订单镜像**：两个日期分区的订单 CSV（含一个只含表头的空分区）+
  一对多费用 CSV；
* **客户镜像**：逐行 JSON 客户归属表。

数据里刻意安排题面要求的全部边界：

* 没有客户的订单（O4 不被客户表覆盖）；
* null 连接键（O3 的 cust_id 为空，按契约转 null）；
* 重复收费键（费用表 O1 出现两条 F1/F2，连接产生全部匹配组合）；
* 含引号内逗号与换行的字段（O1 的 note）；
* 至少一个坏金额（F5 的 amount=BAD，记录级拒绝）；
* 坏整数（O6 的 qty=1.5，记录级拒绝）；
* 非对象 JSON 行（客户表第 3 行是 JSON 数组，记录级拒绝）；
* 空分区（orders-d3.csv 只有表头，验证空输入聚合）。

期待的业务结果在 :mod:`verify_relational_demo` 中以独立手写字面量列出，
本模块只负责造数，不用执行器自证。
"""

from __future__ import annotations

import io
import tarfile
from dataclasses import dataclass

from ..digest import sha256_digest
from ..fileview.sample_layers import MEDIA_TAR

# ---------------------------------------------------------------------------
# 原始文件字节（验收脚本里另有独立手写期待值，不直接复用这里的派生结果）
# ---------------------------------------------------------------------------
# 订单分区 1：O1 的 note 含引号内逗号 + 引号内换行（物理行 2-3）
ORDERS_D1_CSV = (
    "order_id,cust_id,amount,status,qty,note\n"
    'O1,C1,100.00,active,2,"加急,优先\n第二行备注"\n'
    "O2,C2,200.00,cancelled,1,普通\n"
    "O3,,300.00,active,1,无客户键\n"
).encode("utf-8")

# 订单分区 2：O4 无客户归属；O6 的 qty=1.5 不是整数字面量 -> 记录拒绝
ORDERS_D2_CSV = (
    "order_id,cust_id,amount,status,qty,note\n"
    "O4,C9,400.00,active,1,客户表没有C9\n"
    "O5,C2,500.00,active,3,南方客户\n"
    "O6,C1,600.00,cancelled,1.5,坏整数行\n"
).encode("utf-8")

# 空分区：只有表头（用于验证空输入的聚合行为）
ORDERS_D3_CSV = (
    "order_id,cust_id,amount,status,qty,note\n"
).encode("utf-8")

# 客户归属（逐行 JSON）：第 3 行是数组而非对象 -> 记录拒绝；
# C3 显式 null region（null 分组）
CUSTOMERS_JSONL = (
    '{"cust_id": "C1", "name": "甲客户", "region": "north"}\n'
    '{"cust_id": "C2", "name": "乙客户", "region": "south"}\n'
    '["not-an-object", 7]\n'
    '{"cust_id": "C3", "name": "丙客户", "region": null}\n'
).encode("utf-8")

# 费用表（一对多）：F1/F2 同属 O1（重复连接键）；F5 坏金额 -> 记录拒绝；
# F6 指向不存在的订单（连接时自然落空，不是脏数据）
FEES_CSV = (
    "fee_id,order_id,amount\n"
    "F1,O1,10.00\n"
    "F2,O1,2.80\n"
    "F3,O3,10.00\n"
    "F4,O5,5.00\n"
    "F5,O2,BAD\n"
    "F6,O99,7.00\n"
).encode("utf-8")

# 镜像内精确路径
ORDERS_IMG = "orders-image"
CUSTOMERS_IMG = "customers-image"

ORDERS_FILES = {
    "/data/orders/dt=2026-11-01/orders.csv": ORDERS_D1_CSV,
    "/data/orders/dt=2026-11-02/orders.csv": ORDERS_D2_CSV,
    "/data/orders/dt=2026-11-03/orders.csv": ORDERS_D3_CSV,
    "/data/fees/fees.csv": FEES_CSV,
}
CUSTOMERS_FILES = {
    "/data/customers/customers.jsonl": CUSTOMERS_JSONL,
}


@dataclass(frozen=True)
class DemoImage:
    key: str
    files: dict[str, bytes]
    layer_digest: str
    layer_archive: bytes

    @property
    def image_digest(self) -> str:
        # 与 tests/fileview_fixtures.add_image 完全相同的确定性 manifest
        # digest 构造：canonical = [[layer_digest, media], config_digest]
        import json as _json
        config = "sha256:" + "cf" * 32
        canonical = _json.dumps(
            [[self.layer_digest, MEDIA_TAR], config],
            separators=(",", ":")).encode("utf-8")
        return sha256_digest(b"manifest:" + canonical)


def _tar_of(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for path in sorted(files):
            data = files[path]
            info = tarfile.TarInfo(path.lstrip("/"))
            info.size = len(data)
            info.mode = 0o644
            info.mtime = 0
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def build_demo_images() -> dict[str, DemoImage]:
    """构造两个演示镜像（各单层 tar），返回 key -> DemoImage。"""
    images: dict[str, DemoImage] = {}
    for key, files in ((ORDERS_IMG, ORDERS_FILES),
                       (CUSTOMERS_IMG, CUSTOMERS_FILES)):
        archive = _tar_of(files)
        images[key] = DemoImage(
            key=key, files=dict(files),
            layer_digest=sha256_digest(archive), layer_archive=archive)
    return images


# ---------------------------------------------------------------------------
# 声明式计划（节点顺序刻意不按依赖顺序，证明执行与排列无关）
# ---------------------------------------------------------------------------
def build_plan(order_image_digest: str,
               customer_image_digest: str) -> dict:
    """构造演示计划；节点声明顺序故意打乱（group 在其上游之前）。"""
    return {
        "inputs": [
            {
                "name": "orders",
                "format": "csv",
                "files": [
                    {"image": order_image_digest,
                     "path": "/data/orders/dt=2026-11-01/orders.csv"},
                    {"image": order_image_digest,
                     "path": "/data/orders/dt=2026-11-02/orders.csv"},
                    {"image": order_image_digest,
                     "path": "/data/orders/dt=2026-11-03/orders.csv"},
                ],
                "contract": {
                    "missing": "reject",
                    "empty_string": "null",
                    "extra_fields": "reject",
                    "fields": [
                        {"name": "order_id", "type": "string",
                         "nullable": False},
                        {"name": "cust_id", "type": "string",
                         "nullable": True},
                        {"name": "amount", "type": "decimal",
                         "nullable": False},
                        {"name": "status", "type": "string",
                         "nullable": False},
                        {"name": "qty", "type": "integer",
                         "nullable": False},
                        {"name": "note", "type": "string",
                         "nullable": False},
                    ],
                },
            },
            {
                "name": "fees",
                "format": "csv",
                "files": [
                    {"image": order_image_digest,
                     "path": "/data/fees/fees.csv"},
                ],
                "contract": {
                    "missing": "reject",
                    "empty_string": "null",
                    "extra_fields": "reject",
                    "fields": [
                        {"name": "fee_id", "type": "string",
                         "nullable": False},
                        {"name": "order_id", "type": "string",
                         "nullable": False},
                        {"name": "amount", "type": "decimal",
                         "nullable": False},
                    ],
                },
            },
            {
                "name": "customers",
                "format": "jsonl",
                "files": [
                    {"image": customer_image_digest,
                     "path": "/data/customers/customers.jsonl"},
                ],
                "contract": {
                    "missing": "reject",
                    "empty_string": "null",
                    "extra_fields": "reject",
                    "fields": [
                        {"name": "cust_id", "type": "string",
                         "nullable": False},
                        {"name": "name", "type": "string",
                         "nullable": False},
                        {"name": "region", "type": "string",
                         "nullable": True},
                    ],
                },
            },
        ],
        # 故意乱序：最终节点排最前，source 排最后
        "nodes": [
            {
                "name": "region_summary",
                "kind": "group",
                "input": "detail",
                "keys": ["region"],
                "count_alias": "fee_count",
                # fee 表的 amount 与订单侧 order_amount 不重名，连接后
                # 保留原名 amount（仅重名列才加 suffix）
                "sum_column": "amount",
                "sum_alias": "fee_total",
            },
            {
                "name": "detail",
                "kind": "join",
                "left": "orders_with_customer",
                "right": "fees_src",
                "join_type": "inner",
                "left_key": "order_id",
                "right_key": "order_id",
                "left_suffix": "_o",
                "right_suffix": "_f",
            },
            {
                "name": "fees_src",
                "kind": "source",
                "input": "fees",
            },
            {
                "name": "orders_with_customer",
                "kind": "join",
                "left": "active_orders",
                "right": "customers_src",
                "join_type": "left",
                "left_key": "cust_id",
                "right_key": "cust_id",
                "left_suffix": "_o",
                "right_suffix": "_c",
            },
            {
                "name": "customers_src",
                "kind": "source",
                "input": "customers",
            },
            {
                "name": "active_orders",
                "kind": "filter",
                "input": "orders_picked",
                "expression": "status = 'active'",
            },
            {
                "name": "orders_picked",
                "kind": "select",
                "input": "orders_src",
                "columns": [
                    {"source": "order_id"},
                    {"source": "cust_id"},
                    {"source": "amount", "alias": "order_amount"},
                    {"source": "status"},
                    {"source": "qty"},
                ],
            },
            {
                "name": "orders_src",
                "kind": "source",
                "input": "orders",
            },
        ],
    }
