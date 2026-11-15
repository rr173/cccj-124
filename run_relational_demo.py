#!/usr/bin/env python3
"""离线关系加工端到端演示（含独立新进程验收）。

按交付动作组织：

1. 用既有目录库 + 文件视图机制构建两个镜像视图（订单镜像含两个日期
   分区订单 CSV + 一对多费用 CSV；客户镜像含逐行 JSON 归属表）；
2. 提交一份**节点故意乱序**的声明式计划：过滤撤销订单 → 左连接客户 →
   内连接一对多费用 → 按地区分组求记录数与十进制金额和；
3. 再提交一份节点反序的等价计划到另一个结果库，证明执行与排列无关；
4. 演示四类必须拒绝的情形：循环依赖、缺列、读取失败、输出库路径冲突，
   并确认没有留下可查询的成功半成品；
5. 演示空分区（只有表头）聚合为零个分组；
6. 在**新进程**里打开结果库，按验收脚本中手写的期待值逐项核对明细、
   分组金额、拒绝行、每条汇总结果的来源集合与贡献次数。

运行：python3 -I run_relational_demo.py（纯标准库，不访问网络/registry）
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from oci_catalog import CatalogStore
from oci_catalog.digest import sha256_digest
from oci_catalog.fileview import FileViewStore
from oci_catalog.models import Descriptor, ManifestInfo, ManifestKind
from oci_catalog.relational.api import open_result_store, run_plan
from oci_catalog.relational.relational_cli import main as cli_main
from oci_catalog.relational.sample_relational import (
    CUSTOMERS_IMG,
    ORDERS_IMG,
    build_demo_images,
    build_plan,
)

HERE = os.path.dirname(os.path.abspath(__file__))
IMAGE_MEDIA = "application/vnd.oci.image.manifest.v1+json"
LAYER_MEDIA = "application/vnd.oci.image.layer.v1.tar"


def build_views(tmp: str):
    """建目录库与两个文件视图，返回路径与镜像 digest。"""
    catalog_db = os.path.join(tmp, "catalog.db")
    views_db = os.path.join(tmp, "views.db")
    catalog = CatalogStore(catalog_db)
    views = FileViewStore(views_db, catalog_db)
    images = build_demo_images()
    layer_paths = {}
    for img in images.values():
        path = os.path.join(tmp, img.key + ".tar")
        with open(path, "wb") as fh:
            fh.write(img.layer_archive)
        layer_paths[img.layer_digest] = path
    digests = {}
    for key, img in images.items():
        catalog.upsert_manifest(ManifestInfo(
            digest=img.image_digest, media_type=IMAGE_MEDIA,
            kind=ManifestKind.IMAGE,
            layers=(Descriptor(digest=img.layer_digest,
                               media_type=LAYER_MEDIA,
                               size=len(img.layer_archive)),)))
        digests[key] = img.image_digest
    catalog.conn.commit()
    for img in images.values():
        result = views.build_view(img.image_digest, layer_paths)
        assert result.ok, result.to_dict()
    views.close()
    catalog.close()
    return catalog_db, views_db, digests


def check(cond: bool, message: str) -> None:
    if not cond:
        raise AssertionError(message)
    print(f"  ✓ {message}")


def main() -> None:
    tmp = tempfile.mkdtemp(prefix="relational-demo-")
    print(f"== 工作目录: {tmp} ==")
    catalog_db, views_db, digests = build_views(tmp)
    order_img = digests[ORDERS_IMG]
    customer_img = digests[CUSTOMERS_IMG]

    # ----------------------------------------------------------------
    print("\n== 步骤 1：CLI 执行节点乱序的声明式计划 ==")
    results_db = os.path.join(tmp, "results.db")
    plan = build_plan(order_img, customer_img)
    plan_path = os.path.join(tmp, "plan.json")
    with open(plan_path, "w", encoding="utf-8") as fh:
        json.dump(plan, fh, ensure_ascii=False, indent=2)
    rc = cli_main(["run", "--plan", plan_path, "--output", results_db,
                   "--views", views_db, "--catalog", catalog_db])
    check(rc == 0, "CLI run 成功退出（退出码 0）")

    # ----------------------------------------------------------------
    print("\n== 步骤 2：节点反序的等价计划，证明执行与排列无关 ==")
    reversed_db = os.path.join(tmp, "results_reversed.db")
    reversed_plan = json.loads(json.dumps(plan))
    reversed_plan["nodes"] = list(reversed(reversed_plan["nodes"]))
    reversed_path = os.path.join(tmp, "plan_reversed.json")
    with open(reversed_path, "w", encoding="utf-8") as fh:
        json.dump(reversed_plan, fh, ensure_ascii=False)
    outcome_rev = run_plan(reversed_plan, reversed_db, views_db,
                           catalog_db)
    check(outcome_rev.ok, "反序计划同样成功")
    s1 = open_result_store(results_db)
    s2 = open_result_store(reversed_db)
    try:
        rid1 = s1.latest_success_run()
        rid2 = s2.latest_success_run()
        for node in ("detail", "region_summary", "orders_with_customer"):
            r1 = s1.fetch_rows(rid1, node)
            r2 = s2.fetch_rows(rid2, node)
            check(
                [r["values"] for r in r1["rows"]]
                == [r["values"] for r in r2["rows"]],
                f"节点 {node} 在两种节点顺序下结果逐行一致")
    finally:
        s1.close()
        s2.close()

    # ----------------------------------------------------------------
    print("\n== 步骤 3：计划级与读取级失败均拒绝且无成功半成品 ==")
    # 3a 循环依赖
    cycle_plan = json.loads(json.dumps(plan))
    cycle_plan["nodes"][0]["input"] = "active_orders"  # region_summary 回指
    cycle_db = os.path.join(tmp, "cycle.db")
    out = run_plan(cycle_plan, cycle_db, views_db, catalog_db)
    check(not out.ok and out.error_code == "plan_invalid",
          "循环依赖在执行前拒绝（plan_invalid）")
    _assert_no_success(cycle_db, "循环依赖")

    # 3b 缺列
    missing_col_plan = json.loads(json.dumps(plan))
    missing_col_plan["nodes"][5]["expression"] = "ghost_col = 'x'"
    mc_db = os.path.join(tmp, "missing_col.db")
    out = run_plan(missing_col_plan, mc_db, views_db, catalog_db)
    check(not out.ok and out.error_code == "plan_invalid",
          "过滤引用未知列在执行前拒绝")
    _assert_no_success(mc_db, "缺列")

    # 3c 读取失败（视图中不存在的路径）
    bad_read_plan = json.loads(json.dumps(plan))
    bad_read_plan["inputs"][0]["files"][0]["path"] = "/nope/missing.csv"
    br_db = os.path.join(tmp, "bad_read.db")
    out = run_plan(bad_read_plan, br_db, views_db, catalog_db)
    check(not out.ok and out.error_code == "source_read_failed",
          "文件不存在/读取失败整次加工拒绝")
    _assert_no_success(br_db, "读取失败")

    # 3d 输出库指向输入库（写入前拒绝，且不创建该文件）
    conflict_db = views_db
    out = run_plan(plan, conflict_db, views_db, catalog_db)
    check(not out.ok and out.error_code == "output_conflict",
          "输出库路径等于视图库时写入前拒绝")
    check(os.path.abspath(conflict_db) == os.path.abspath(views_db),
          "冲突路径没有被写成新的结果库")

    # ----------------------------------------------------------------
    print("\n== 步骤 4：空分区（只有表头）聚合为零个分组 ==")
    empty_plan = {
        "inputs": [{
            "name": "empty_orders", "format": "csv",
            "files": [{"image": order_img,
                       "path": "/data/orders/dt=2026-11-03/orders.csv"}],
            "contract": plan["inputs"][0]["contract"],
        }],
        "nodes": [
            {"name": "empty_src", "kind": "source",
             "input": "empty_orders"},
            {"name": "empty_group", "kind": "group",
             "input": "empty_src", "keys": ["status"],
             "count_alias": "cnt", "sum_column": "amount",
             "sum_alias": "total"},
        ],
    }
    empty_db = os.path.join(tmp, "empty.db")
    out = run_plan(empty_plan, empty_db, views_db, catalog_db)
    check(out.ok, "空分区计划成功（空输入不是错误）")
    store = open_result_store(empty_db)
    try:
        rid = store.latest_success_run()
        rows = store.fetch_rows(rid, "empty_group")["rows"]
        check(rows == [], "空输入分组/count/sum 产出零个分组（无虚构行）")
    finally:
        store.close()

    # ----------------------------------------------------------------
    print("\n== 步骤 5：新进程按手写期待值验收 ==")
    verify_plan = {
        "results_db": results_db,
        "reversed_db": reversed_db,
        "views_db": views_db,
        "catalog_db": catalog_db,
        "order_image": order_img,
        "customer_image": customer_img,
        "failure_dbs": {"cycle": cycle_db, "missing_col": mc_db,
                        "bad_read": br_db},
        "empty_db": empty_db,
    }
    verify_plan_path = os.path.join(tmp, "verify-plan.json")
    with open(verify_plan_path, "w", encoding="utf-8") as fh:
        json.dump(verify_plan, fh)
    verifier = os.path.join(HERE, "verify_relational_demo.py")
    proc = subprocess.run(
        [sys.executable, "-I", verifier, "--plan", verify_plan_path],
        capture_output=True, text=True)
    print(proc.stdout)
    if proc.returncode != 0:
        print(proc.stderr, file=sys.stderr)
        shutil.rmtree(tmp, ignore_errors=True)
        raise SystemExit(proc.returncode)
    print(f"全部验收通过；数据库与计划位于 {tmp}")


def _assert_no_success(db_path: str, label: str) -> None:
    store = open_result_store(db_path)
    try:
        from oci_catalog.relational.store import RunNotFoundError
        try:
            store.latest_success_run()
            raise AssertionError(f"{label} 不应存在成功 run")
        except RunNotFoundError:
            pass
        node_count = store.conn.execute(
            "SELECT COUNT(*) AS c FROM result_nodes").fetchone()["c"]
        check(node_count == 0, f"{label} 库中没有任何结果节点（无半成品）")
    finally:
        store.close()


if __name__ == "__main__":
    main()
