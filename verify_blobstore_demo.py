#!/usr/bin/env python3
"""新进程验收：按手写期待值核对 OCI 原始对象仓。

本脚本被 ``run_blobstore_demo.py`` 以独立子进程（``python3 -I``）启动，
模拟交付人员在另一个进程中打开仓目录。期待的集合、role 与字节数都在
本文件手工列出，**不调用**对象仓的可达性/计划函数来生成答案；对
SQLite 与普通文件只做直接观察。
"""

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from oci_catalog.blobstore import BlobStore
from oci_catalog.blobstore.sample_data import AMD64_L2, BASE_LAYER

# ---------------------------------------------------------------------------
# 手写期待（独立于 sample_data 的派生结果）
# ---------------------------------------------------------------------------
EXPECTED_STORE_OBJECTS = {
    "main": 4,
}
EXPECTED_MAIN_BYTES = 851
EXPECTED_MAIN_NAMES = ["delivery-b"]
EXPECTED_MAIN_LAYERS = {
    "base": 120,
    "repack-l2": 81,
}
EXPECTED_C_OBJECTS = {399, 98, 50}
EXPECTED_D_OBJECTS = {399, 99, 43}
EXPECTED_A_UNIQUE_TOTAL = 3120
EXPECTED_B_TOTAL = 851
EXPECTED_ALL_UNIQUE = 4939
EXPECTED_ALL_OBJECTS = 19


def check(cond: bool, message: str) -> None:
    if not cond:
        raise AssertionError(message)
    print(f"  ✓ {message}")


def open_store(path: str) -> BlobStore:
    return BlobStore(path)


def blob_file(store: BlobStore, digest: str) -> str:
    hexpart = digest.split(":", 1)[1]
    return os.path.join(store.root, "blobs", "sha256", hexpart[:2], hexpart)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--plan", required=True)
    args = parser.parse_args()
    with open(args.plan, encoding="utf-8") as fh:
        plan = json.load(fh)
    stores = plan["stores"]
    roots = plan["roots"]
    names = plan["names"]

    print("== A. 主仓最终账目：只剩 delivery-b 闭包 ==")
    store = open_store(stores["main"])
    try:
        stats = store.stats()
        check(stats["object_count"] == EXPECTED_STORE_OBJECTS["main"],
              f"对象数 {stats['object_count']} == 手写值 "
              f"{EXPECTED_STORE_OBJECTS['main']}")
        check(stats["unique_bytes"] == EXPECTED_MAIN_BYTES,
              f"唯一字节 {stats['unique_bytes']} == {EXPECTED_MAIN_BYTES}")
        refs = store.list_refs()
        check([r.name for r in refs] == EXPECTED_MAIN_NAMES,
              f"保留名称恰为 {EXPECTED_MAIN_NAMES}")
        check(refs[0].root.digest == plan["main_root_b"] and
              refs[0].root.size == 553,
              "delivery-b 指向根 B 的 manifest（553 字节）")
        roles = {}
        with store.open_reader("delivery-b") as reader:
            for desc in reader.objects():
                roles[desc.digest] = desc.size
            check(reader.root.digest == plan["main_root_b"],
                  "新进程可打开 delivery-b 并固定根 B")
            check(reader.read_all(names["base"]) == BASE_LAYER,
                  "共享 base 层逐字节一致")
        check(roles[names["base"]] == EXPECTED_MAIN_LAYERS["base"],
              "base role/size 与手写表一致")
        check(roles[names["repack-l2"]] == EXPECTED_MAIN_LAYERS["repack-l2"],
              "repack-l2 size 与手写表一致")
        for digest in (names["garbage-l2"], names["garbage2-l2"],
                       names["amd64-l2"], names["arm64-l2"]):
            check(not os.path.exists(blob_file(store, digest)),
                  f"{digest[:19]}… 的字节文件确实不存在")
        check(os.path.exists(blob_file(store, names["base"])),
              "共享 base 的字节文件确实存在")
        # 存储布局：元数据独立 SQLite + 普通文件
        check(os.path.isfile(os.path.join(store.root, "store.db")),
              "元数据是独立 SQLite 文件 store.db")
        check(os.path.isdir(os.path.join(store.root, "blobs", "sha256")),
              "原始对象是普通文件（blobs/sha256/xx/<hex>）")
        tables = {row[0] for row in store.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        check({"objects", "closures", "refs", "readers",
               "gc_plans"} <= tables,
              "元数据表齐全（objects/closures/refs/readers/gc_plans）")
    finally:
        store.close()

    print("\n== B. 屏障仓：keep-c 完整，D 被删 ==")
    store = open_store(stores["barrier"])
    try:
        check([r.name for r in store.list_refs()] == ["delivery-a", "keep-c"],
              "屏障仓保留 delivery-a 与 keep-c")
        c = store.get_ref("keep-c")
        check(c.root.digest == roots["C"], "keep-c 指向根 C")
        with store.open_reader("keep-c") as reader:
            sizes = {d.size for d in reader.objects()}
            check(sizes == EXPECTED_C_OBJECTS, "keep-c 闭包对象 size 集合正确")
            check(len(reader.object_digests()) == 3, "keep-c 恰有 3 个对象")
        check(not os.path.exists(blob_file(store, names["garbage2-l2"])),
              "D 的独有层已删除")
        check(os.path.exists(blob_file(store, names["garbage-l2"])),
              "C 的独有层保留")
    finally:
        store.close()

    print("\n== C. 旧计划范围：计划后新导入对象未受影响 ==")
    store = open_store(stores["late"])
    try:
        names_now = [r.name for r in store.list_refs()]
        check(sorted(names_now) == ["delivery-a", "delivery-late"],
              "late 仓保留 delivery-a 与 delivery-late")
        with store.open_reader("delivery-late") as reader:
            check(reader.root.digest == roots["D"], "delivery-late 指向根 D")
            check(len(reader.object_digests()) == 3,
                  "delivery-late 闭包完整（3 个对象）")
            check(reader.read_all(names["garbage2-l2"]) ==
                  b"GARBAGE2-UNIQUE-L2\n" + b"h" * 24,
                  "计划后导入的 D 层字节可逐字节读出")
        check(not os.path.exists(blob_file(store, names["garbage-l2"])),
              "旧计划里的 C 层已删除")
    finally:
        store.close()

    print("\n== D. 并发回收仓：清单内对象各删一次 ==")
    store = open_store(stores["conc"])
    try:
        check(store.stats()["object_count"] == 10,
              "并发仓只剩 delivery-a 闭包 10 个对象")
        runs = [run for run in store.list_gc_runs()
                if run["run_id"] in plan["conc_run_ids"]]
        check(len(runs) == 2, "两个回收者都留下了运行记录")
        deleted = [item["digest"] for run in runs
                   for item in run["items"]
                   if item["outcome"] == "deleted"]
        expected = sorted(names[key] for key in (
            "manifest-garbage", "config-garbage", "garbage-l2",
            "manifest-garbage2", "config-garbage2", "garbage2-l2"))
        check(sorted(deleted) == expected,
              "6 个候选恰好各被删除一次（无重复、无遗漏）")
    finally:
        store.close()

    print("\n== E. 崩溃恢复仓：原名称完整、暂存已回收 ==")
    store = open_store(stores["crash"])
    try:
        check([r.name for r in store.list_refs()] == ["delivery-a"],
              "导入发布前崩溃没有产生半份名称")
        check(store.stats()["unique_bytes"] == EXPECTED_A_UNIQUE_TOTAL,
              "原 delivery-a 闭包仍为 3120 字节")
        staging = os.path.join(store.root, "staging")
        leftover = [entry for entry in os.listdir(staging)
                    if not entry.endswith(".lock")]
        check(leftover == [], "无主的未发布暂存目录已清理")
        check(store.check_health()["status"] == "ok", "仓库状态一致")
    finally:
        store.close()

    print("\n== F. 回收中途退出仓：两次运行如实区分 ==")
    store = open_store(stores["mid"])
    try:
        runs = store.list_gc_runs()
        check(len(runs) == 2, "中断运行与重跑运行都有记录")
        mid = [run for run in runs if run["run_id"] == plan["mid_run_id"]]
        check(len(mid) == 1, "重跑运行可按 run_id 找到")
        outcomes = {item["digest"]: item["outcome"]
                    for item in mid[0]["items"]}
        check(outcomes[plan["mid_crashed_digest"]] == "already_deleted",
              "中断前已删除的候选记为 already_deleted")
        check(sum(1 for value in outcomes.values() if value == "deleted") == 5,
              "其余 5 个候选记为 deleted")
        check(mid[0]["items"] and all(
            item["outcome"] in ("deleted", "already_deleted", "skipped")
            for item in mid[0]["items"]), "结果集合只含三种定义明确的取值")
        check(store.stats()["unique_bytes"] == EXPECTED_A_UNIQUE_TOTAL,
              "最终只剩 delivery-a 的 3120 字节")
    finally:
        store.close()

    print("\n== G. 失败导入仓：原名称与账目未变，缺损仓报异常 ==")
    store = open_store(stores["fail"])
    try:
        refs = store.list_refs()
        check([r.name for r in refs] == ["delivery-a"],
              "三次失败导入没有新增名称")
        check(refs[0].root.digest == roots["A"], "delivery-a 仍指向根 A")
        check(store.stats()["unique_bytes"] == EXPECTED_A_UNIQUE_TOTAL,
              "对象账目仍为 3120 字节")
        with store.open_reader("delivery-a") as reader:
            check(reader.read_all(names["amd64-l2"]) == AMD64_L2,
                  "失败导入后原闭包的含非 UTF-8 层仍逐字节正确")
        failures = store.conn.execute(
            "SELECT COUNT(*) AS c FROM import_failures").fetchone()["c"]
        check(failures == 3, "三次失败各留一条诊断，不产生可见内容")
    finally:
        store.close()

    store = open_store(stores["missing"])
    try:
        check(store.check_health()["status"] == "corrupt",
              "缺损仓被报告为 corrupt")
        try:
            store.plan_gc()
            raise AssertionError("缺损仓不应能生成计划")
        except Exception as exc:
            check("仓库状态异常" in str(exc),
                  "缺损仓生成计划被拒绝并说明状态异常")
        check(os.path.exists(blob_file(store, names["garbage-l2"])),
              "缺损仓的无引用垃圾未被顺带清理")
    finally:
        store.close()

    print("\n全部验收通过")


if __name__ == "__main__":
    main()
