#!/usr/bin/env python3
"""新进程验收：按显式手写期待值核对关系加工结果与逐行血缘。

本脚本被 ``run_relational_demo.py`` 以独立子进程（``python3 -I``）启动，
模拟交付人员在另一个进程中打开结果 SQLite 库排查“客户汇总金额由哪几条
原始订单与收费记录贡献”。

**所有期待值都是本文件内独立手写的字面量**（根据样例原始数据手算），
不导入执行器、不重新计算，避免“用同一套代码自证”。
"""

import argparse
import json
import os
import sys
from decimal import Decimal

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from oci_catalog.relational.api import open_result_store
from oci_catalog.relational.store import RunNotFoundError

D1 = "/data/orders/dt=2026-11-01/orders.csv"
D2 = "/data/orders/dt=2026-11-02/orders.csv"
FEES = "/data/fees/fees.csv"
CUSTOMERS = "/data/customers/customers.jsonl"


# ---------------------------------------------------------------------------
# 手算期待：detail 节点的 4 行（连接后保留全部匹配组合，左空侧补 null）
# 列：order_id_o, order_id_f, fee_id, amount, region, name, order_amount,
#     qty, status, cust_id_o, cust_id_c
# ---------------------------------------------------------------------------
EXPECTED_DETAIL = [
    {"order_id_o": "O1", "order_id_f": "O1", "fee_id": "F1",
     "amount": "10.00", "region": "north", "name": "甲客户",
     "order_amount": "100.00", "qty": 2, "status": "active",
     "cust_id_o": "C1", "cust_id_c": "C1"},
    {"order_id_o": "O1", "order_id_f": "O1", "fee_id": "F2",
     "amount": "2.80", "region": "north", "name": "甲客户",
     "order_amount": "100.00", "qty": 2, "status": "active",
     "cust_id_o": "C1", "cust_id_c": "C1"},
    {"order_id_o": "O3", "order_id_f": "O3", "fee_id": "F3",
     "amount": "10.00", "region": None, "name": None,
     "order_amount": "300.00", "qty": 1, "status": "active",
     "cust_id_o": None, "cust_id_c": None},
    {"order_id_o": "O5", "order_id_f": "O5", "fee_id": "F4",
     "amount": "5.00", "region": "south", "name": "乙客户",
     "order_amount": "500.00", "qty": 3, "status": "active",
     "cust_id_o": "C2", "cust_id_c": "C2"},
]

# 手算期待：按地区汇总（NULL 组排在最前），金额精确十进制
EXPECTED_SUMMARY = [
    {"region": None, "fee_count": 1, "fee_total": "10.00"},
    {"region": "north", "fee_count": 2, "fee_total": "12.80"},
    {"region": "south", "fee_count": 1, "fee_total": "5.00"},
]

# 手算期待：每条汇总行的来源集合（表, 文件, 记录序号 -> 贡献次数）
EXPECTED_SUMMARY_TRACE = {
    None: {
        ("orders", D1, 3): 1,    # O3（null 客户键，左连接空侧无客户来源）
        ("fees", FEES, 3): 1,    # F3
    },
    "north": {
        ("orders", D1, 1): 2,    # O1 参与 F1/F2 两条收费组合 -> 贡献 2 次
        ("customers", CUSTOMERS, 1): 2,  # C1 同样贡献 2 次
        ("fees", FEES, 1): 1,    # F1
        ("fees", FEES, 2): 1,    # F2
    },
    "south": {
        ("orders", D2, 5): 1,    # O5（位于第二个日期分区）
        ("customers", CUSTOMERS, 2): 1,  # C2
        ("fees", FEES, 4): 1,    # F4
    },
}

# 手算期待：3 条记录级拒绝（表, 记录序号, 物理起始行, 原因码）
EXPECTED_REJECTIONS = [
    ("customers", 3, 3, "json_not_object"),
    ("fees", 5, 6, "not_convertible"),
    ("orders", 6, 4, "not_convertible"),
]


def check(cond: bool, message: str) -> None:
    if not cond:
        raise AssertionError(message)
    print(f"  ✓ {message}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--plan", required=True)
    args = parser.parse_args()
    with open(args.plan, encoding="utf-8") as fh:
        plan = json.load(fh)

    store = open_result_store(plan["results_db"])
    try:
        rid = store.latest_success_run()
        print("== A. 节点清单与拓扑序（与声明顺序无关） ==")
        nodes = store.list_nodes(rid)
        check([n["node_name"] for n in nodes] == [
            "customers_src", "fees_src", "orders_src", "orders_picked",
            "active_orders", "orders_with_customer", "detail",
            "region_summary"], "8 个节点按依赖拓扑序落库")

        print("\n== B. 订单明细 detail：手算 4 行逐行核对 ==")
        detail = store.fetch_rows(rid, "detail")
        actual_detail = [r["values"] for r in detail["rows"]]
        check(len(actual_detail) == 4, "detail 恰好 4 行")

        def norm(row):
            # decimal 读侧为 Decimal，统一转字面量字符串再与手写值比较
            return {k: (str(v) if v.__class__.__name__ == "Decimal" else v)
                    for k, v in row.items()}

        for i, expected in enumerate(EXPECTED_DETAIL):
            check(norm(actual_detail[i]) == expected,
                  f"detail 第 {i + 1} 行与手算值一致: "
                  f"{expected['order_id_o']}/{expected['fee_id']}")
        # 明细里的金额在 Python 侧是精确 Decimal
        self_amounts = {r["values"]["amount"] for r in detail["rows"]}
        check(all(isinstance(v, Decimal) for v in self_amounts),
              "明细金额列读侧均为精确 Decimal")
        # O4（无费用）被内连接剔除；F6（O99）无对应订单不产生行
        ids = {(r["order_id_o"], r["fee_id"]) for r in actual_detail}
        check(("O4", "F4") not in ids and not any(
            f == "F6" for _, f in ids),
            "无费用订单 O4 与悬空收费 F6 都不出现在明细中")

        print("\n== C. 地区汇总：精确十进制金额与 NULL 组 ==")
        summary = store.fetch_rows(rid, "region_summary")
        actual_summary = [r["values"] for r in summary["rows"]]
        # decimal 列在 Python 读侧还原为 Decimal；用字面量字符串比较
        normalized = [
            {k: (str(v) if v is not None and
                 v.__class__.__name__ == "Decimal" else v)
             for k, v in row.items()}
            for row in actual_summary]
        check(normalized == EXPECTED_SUMMARY,
              "三个汇总行（含 NULL 组）金额/计数与手算一致")
        # 读侧确实拿到精确 Decimal 类型，且定点字面量不丢
        north = next(r for r in actual_summary if r["region"] == "north")
        check(isinstance(north["fee_total"], Decimal)
              and north["fee_total"] == Decimal("12.80"),
              "读侧 fee_total 是精确 Decimal('12.80')，无二进制浮点")
        # 0.10 + 0.20 在 north 组精确得到 12.80（10.00+2.80），无尾差
        check(str(north["fee_total"]) == "12.80",
              "north 金额 12.80 保持定点字面量，无二进制浮点误差")
        csv_text = store.export_node_csv(rid, "region_summary")
        check("12.80" in csv_text and csv_text.startswith(
            "fee_count,fee_total,region\n"),
            "导出的 UTF-8 CSV 保留十进制字面量与表头")

        print("\n== D. 逐行追溯：来源集合、稳定排序与贡献次数 ==")
        for row in summary["rows"]:
            region = row["values"]["region"]
            trace = store.trace_row(rid, "region_summary", row["row_id"])
            actual_map = {
                (s["table_name"], s["file_path"], s["record_seq"]):
                    s["contribution"]
                for s in trace["sources"]}
            check(actual_map == EXPECTED_SUMMARY_TRACE[region],
                  f"region={region!r} 汇总行来源与贡献次数与手算一致")
            # 稳定排序断言
            coords = [(s["table_name"], s["image_digest"], s["file_path"],
                       s["record_seq"]) for s in trace["sources"]]
            check(coords == sorted(coords),
                  f"region={region!r} 来源按坐标稳定排序")
            # 去重断言：同一 (文件,序号) 只出现一次，次数记在 contribution
            unique = {(s["file_path"], s["record_seq"])
                      for s in trace["sources"]}
            check(len(unique) == len(trace["sources"]),
                  f"region={region!r} 源记录已去重")
        # null 组不能虚构客户来源
        null_trace = store.trace_row(
            rid, "region_summary", summary["rows"][0]["row_id"])
        check(all(s["table_name"] != "customers"
                  for s in null_trace["sources"]),
              "NULL 客户键的左连接空侧不虚构客户来源")

        print("\n== E. 拒绝明细：原始值、文件、序号、物理行与原因 ==")
        rejections = store.list_rejections(rid)
        check(len(rejections) == 3, "恰好 3 条记录级拒绝，合格记录继续")
        actual_rej = sorted(
            (r["table_name"], r["record_seq"],
             r["physical_start_line"], r["reason_code"])
            for r in rejections)
        check(actual_rej == sorted(EXPECTED_REJECTIONS),
              "拒绝行的表/序号/物理行/原因码与手算一致")
        fee_bad = next(r for r in rejections if r["table_name"] == "fees")
        check("BAD" in fee_bad["raw_text"]
              and fee_bad["file_path"] == FEES,
              "坏金额拒绝保留原始行文本与精确文件路径")
        # 记录序号 ≠ 物理行号：O1 引号换行跨物理行 2-3，但记录序号是 1
        order_rej = next(r for r in rejections
                         if r["table_name"] == "orders")
        check(order_rej["record_seq"] == 6
              and order_rej["physical_start_line"] == 4,
              "坏整数行记录序号 6 与物理行 4 不混淆（多文件连续序号）")

        print("\n== F. 引号内逗号/换行字段的来源可回看原始值 ==")
        owc = store.fetch_rows(rid, "orders_with_customer")
        o1_row = next(r for r in owc["rows"]
                      if r["values"]["order_id"] == "O1")
        trace = store.trace_row(rid, "orders_with_customer",
                                o1_row["row_id"])
        o1_source = next(s for s in trace["sources"]
                         if s["table_name"] == "orders")
        check("," in o1_source["raw_values"]["note"]
              and "\n" in o1_source["raw_values"]["note"],
              "O1 的 note 保留引号内逗号与换行的原始值")
        check(o1_source["physical_start_line"] == 2
              and o1_source["physical_end_line"] == 3
              and o1_source["record_seq"] == 1,
              "O1 跨行记录物理行 2-3、记录序号 1（两者明确区分）")

        print("\n== G. 行 ID 在新进程稳定（不依赖内存对象） ==")
        row_id_before = summary["rows"][1]["row_id"]
    finally:
        store.close()
    # 重新打开（本脚本本身就是新进程；这里再模拟一次连接关闭重开）
    store = open_result_store(plan["results_db"])
    try:
        rid = store.latest_success_run()
        again = store.fetch_rows(rid, "region_summary")
        check(again["rows"][1]["row_id"] == row_id_before
              and again["rows"][1]["values"]["fee_total"]
              == Decimal("12.80"),
              "结果行 ID 重开数据库后保持稳定且可再次追溯")
    finally:
        store.close()

    print("\n== H. 失败 run 无成功半成品 ==")
    for label, db_path in plan["failure_dbs"].items():
        fail_store = open_result_store(db_path)
        try:
            try:
                fail_store.latest_success_run()
                raise AssertionError(f"{label} 库不应存在成功 run")
            except RunNotFoundError:
                pass
            count = fail_store.conn.execute(
                "SELECT COUNT(*) AS c FROM result_nodes").fetchone()["c"]
            check(count == 0, f"{label} 库无任何结果节点（无半成品）")
        finally:
            fail_store.close()

    print("\n== I. 空分区聚合为零个分组 ==")
    empty_store = open_result_store(plan["empty_db"])
    try:
        empty_rid = empty_store.latest_success_run()
        check(empty_store.fetch_rows(empty_rid, "empty_group")["rows"]
              == [], "只有表头的空分区分组结果为空")
    finally:
        empty_store.close()

    print("\n全部验收通过")


if __name__ == "__main__":
    main()
