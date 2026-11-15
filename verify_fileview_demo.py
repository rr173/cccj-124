#!/usr/bin/env python3
"""新进程验收：按显式期待值核对镜像层文件视图。

本脚本被 ``run_fileview_demo.py`` 以独立子进程（``python3 -I``）启动，
模拟交付人员在另一个进程中打开已落库的视图 SQLite 库做查询。
期待的文件树、内容字节、来源层与类型都在本文件中手写列出，
而不是用导出再导入自证。
"""

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from oci_catalog.fileview import (
    FileViewStore,
    ViewPathError,
    list_tree,
    read_file_bytes,
    stat_path,
)

# ---------------------------------------------------------------------------
# 手写期待内容（与 sample_layers 无关的独立字面量）
# ---------------------------------------------------------------------------
APP_CONF_V3 = b"[server]\nport=9090\nmode=v3-final\n"
APP_CONF_ARM = b"[server]\nport=7070\narch=arm64\n"
BLOB_BIN = b"\xff\xfe\x00\x01BINARY\x89PNG\r\n\x00end"
README_V2 = b"readme-v2\n"
LEGACY_NEW = b"fresh-legacy\n"
LOG_CURRENT = b"log-data-v1\n"
LOG_LATER = b"later-log-content\n"
DB_NOTES = b"db-notes\n"
MOTD_PATCHED = b"patched motd\n"
ARM_TARGET_V1 = b"arm-target-v1\n"
ARM_TARGET_V2 = b"arm-target-v2\n"

# amd64 镜像 /data 前缀下的完整期待树：
# (路径, 类型, 内容字节, 来源层键, tar 成员名)
EXPECTED_AMD64_DATA = [
    ("/data", "dir", None, "amd64-l1", "data"),
    ("/data/app.conf", "file", APP_CONF_V3, "amd64-l3", "data/app.conf"),
    ("/data/bin", "dir", None, "amd64-l1", "data/bin/blob.bin"),
    ("/data/bin/blob.bin", "file", BLOB_BIN, "amd64-l1",
     "data/bin/blob.bin"),
    ("/data/docs", "dir", None, "amd64-l2", "data/docs"),
    ("/data/docs/readme-copy.txt", "hardlink", README_V2, "amd64-l3",
     "data/docs/readme-copy.txt"),
    ("/data/docs/readme.txt", "file", README_V2, "amd64-l2",
     "data/docs/readme.txt"),
    ("/data/latest", "symlink", None, "amd64-l3", "data/latest"),
    ("/data/legacy", "dir", None, "amd64-l1", "data/legacy"),
    ("/data/legacy/new.txt", "file", LEGACY_NEW, "amd64-l2",
     "data/legacy/new.txt"),
    ("/data/logs", "dir", None, "amd64-l3", "data/logs/current.log"),
    ("/data/logs/alias.log", "hardlink", LOG_CURRENT, "amd64-l3",
     "data/logs/alias.log"),
    ("/data/logs/current.log", "file", LOG_CURRENT, "amd64-l3",
     "data/logs/current.log"),
    ("/data/logs/forward.log", "hardlink", LOG_LATER, "amd64-l3",
     "data/logs/forward.log"),
    ("/data/logs/later.log", "file", LOG_LATER, "amd64-l3",
     "data/logs/later.log"),
]

# 被删除/遮蔽后必须不存在的路径
ABSENT_PATHS = ["/data/registry.dat", "/data/legacy/old.txt",
                "/data/arm-only.txt"]


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

    images = plan["images"]
    layer_digest = plan["layers"]
    store = FileViewStore(plan["views_db"], plan["catalog_db"])
    try:
        print("== A. amd64 /data 文件树：路径、类型、大小、来源层、成员名 ==")
        listing = list_tree(store, images["amd64"], "/data")
        actual = {e["path"]: e for e in listing["entries"]}
        check(set(actual) == {row[0] for row in EXPECTED_AMD64_DATA},
              f"/data 下恰好 {len(EXPECTED_AMD64_DATA)} 个条目，"
              f"删除与不透明遮蔽的路径不存在")
        for path, etype, content, layer_key, member in EXPECTED_AMD64_DATA:
            entry = actual[path]
            ok = (entry["entry_type"] == etype
                  and entry["layer_digest"] == layer_digest[layer_key]
                  and entry["member_name"] == member)
            if content is not None:
                ok = ok and entry["size"] == len(content)
            check(ok, f"{path}: type={etype} layer={layer_key} "
                      f"member={member!r}")
        for path in ABSENT_PATHS[:2]:
            check(path not in actual, f"{path} 已被上层删除/遮蔽")
        whole = list_tree(store, images["amd64"], "/")
        check(all(".wh." not in e["path"] for e in whole["entries"]),
              "整棵视图树中没有任何白标记被当成业务文件导出")

        print("\n== B. 文件字节与来源层溯源 ==")
        check(read_file_bytes(store, images["amd64"], "/data/app.conf")
              == APP_CONF_V3, "/data/app.conf 是 L3 最终生效内容")
        check(read_file_bytes(store, images["amd64"], "/data/bin/blob.bin")
              == BLOB_BIN, "非 UTF-8 字节文件逐字节一致（未按文本重编码）")
        origin = stat_path(store, images["amd64"], "/data/app.conf")["entry"]
        check(origin["layer_digest"] == layer_digest["amd64-l3"],
              "app.conf 来源层是第三层（覆盖链 v1->v2->v3 的终点）")
        motd = stat_path(store, images["amd64"], "/etc/motd")["entry"]
        check(motd["layer_digest"] == layer_digest["amd64-l3"]
              and read_file_bytes(store, images["amd64"], "/etc/motd")
              == MOTD_PATCHED, "/etc/motd 被第三层补丁覆盖")

        print("\n== C. 符号链接：只查链接信息，绝不跟随 ==")
        link = stat_path(store, images["amd64"], "/data/latest")["entry"]
        check(link["entry_type"] == "symlink"
              and link["link_target"] == "docs/readme.txt",
              "/data/latest 是符号链接，链接目标作为信息保留")
        try:
            read_file_bytes(store, images["amd64"], "/data/latest")
            raise AssertionError("读取符号链接应被拒绝")
        except ViewPathError:
            check(True, "对符号链接取文件字节被拒绝（不跟随）")
        try:
            read_file_bytes(store, images["amd64"], "/data/latest/x")
            raise AssertionError("穿越符号链接应被拒绝")
        except ViewPathError as exc:
            check("符号链接" in str(exc),
                  "穿越符号链接的路径被拒绝且诊断指明链接位置")

        print("\n== D. 硬链接：前向、复用低层、内容快照 ==")
        check(read_file_bytes(store, images["amd64"], "/data/logs/alias.log")
              == LOG_CURRENT, "同层硬链接 alias.log 解析到目标内容")
        check(read_file_bytes(store, images["amd64"],
                              "/data/logs/forward.log") == LOG_LATER,
              "前向硬链接（目标在同层靠后成员）解析正确")
        check(read_file_bytes(store, images["amd64"],
                              "/data/docs/readme-copy.txt") == README_V2,
              "复用低层（L2）文件的硬链接解析正确")
        hl = stat_path(store, images["amd64"],
                       "/data/docs/readme-copy.txt")["entry"]
        check(hl["entry_type"] == "hardlink"
              and hl["link_target"] == "/data/docs/readme.txt",
              "硬链接条目保留归一后的链接目标")

        print("\n== E. 前缀边界：/data 不混入 /database ==")
        check(all(not p.startswith("/database") for p in actual),
              "list /data 不含 /database 条目")
        db_listing = list_tree(store, images["amd64"], "/database")
        check([e["path"] for e in db_listing["entries"]]
              == ["/database", "/database/notes.txt"],
              "list /database 只含自身子树")
        check(read_file_bytes(store, images["amd64"], "/database/notes.txt")
              == DB_NOTES, "/database/notes.txt 内容正确")

        print("\n== F. arm64：不同生效内容 + 链接目标被下一层替换 ==")
        check(read_file_bytes(store, images["arm64"], "/data/app.conf")
              == APP_CONF_ARM, "arm64 的 app.conf 是平台专属内容")
        check(read_file_bytes(store, images["arm64"], "/data/target.txt")
              == ARM_TARGET_V2, "链接目标在第二层被替换为新内容")
        pinned = stat_path(store, images["arm64"], "/data/pinned.txt")["entry"]
        check(pinned["entry_type"] == "hardlink"
              and pinned["layer_digest"] == layer_digest["arm64-l1"],
              "pinned.txt 是第一层建立的硬链接")
        check(read_file_bytes(store, images["arm64"], "/data/pinned.txt")
              == ARM_TARGET_V1,
              "已建立的硬链接保持旧内容（不受目标路径覆盖影响）")
        arm_tree = list_tree(store, images["arm64"], "/data")
        check("/data/arm-only.txt" not in
              {e["path"] for e in arm_tree["entries"]},
              "arm64 第二层白标记删除了 arm-only.txt")

        print("\n== G. 白标记位置无关：重打包镜像归并结果一致 ==")
        repacked = list_tree(store, images["repacked"], "/")["entries"]
        original = list_tree(store, images["amd64"], "/")["entries"]
        l2, l2r = layer_digest["amd64-l2"], layer_digest["amd64-l2-repacked"]

        def normalized(entries):
            result = {}
            for e in entries:
                layer = e["layer_digest"]
                result[e["path"]] = (
                    e["entry_type"], e["size"], e["mode"],
                    l2 if layer == l2r else layer,
                    e["member_name"], e["link_target"])
            return result
        check(normalized(repacked) == normalized(original),
              "白标记移到归档末尾后，文件树（路径/类型/大小/模式/来源层/"
              "成员名）逐条一致")
        for path, etype, content, _, _ in EXPECTED_AMD64_DATA:
            if content is None:
                continue
            check(read_file_bytes(store, images["repacked"], path)
                  == read_file_bytes(store, images["amd64"], path),
                  f"重打包镜像 {path} 字节一致")

        print("\n== H. 层序逐镜像记录：共享层不互相跳过 ==")
        amd_view = store.get_view(images["amd64"])
        rep_view = store.get_view(images["repacked"])
        amd_layers = [r["layer_digest"] for r in
                      store.list_view_layers(amd_view["view_id"])]
        rep_layers = [r["layer_digest"] for r in
                      store.list_view_layers(rep_view["view_id"])]
        check(amd_layers == [layer_digest["amd64-l1"], layer_digest["amd64-l2"],
                             layer_digest["amd64-l3"]],
              "amd64 视图按 manifest 层序记录三层")
        check(rep_layers == [layer_digest["amd64-l1"], l2r,
                             layer_digest["amd64-l3"]],
              "重打包镜像复用同一批层但按自己的层序独立构建")
        check(amd_view["view_id"] != rep_view["view_id"],
              "同一层被多个镜像引用时各自构建视图，未因已有结果被跳过")

        print("\n== I. 失败诊断与无半份视图 ==")
        failures = store.list_failures()
        check(len(failures) == len(plan["expected_failure_codes"]),
              f"{len(plan['expected_failure_codes'])} 次失败构建全部留诊断")
        actual_codes = []
        for row in failures:
            for diag in json.loads(row["diagnostics_json"]):
                actual_codes.append(diag["code"])
                if diag["layer_digest"]:
                    check(diag["image_digest"] and diag["layer_digest"],
                          f"诊断 {diag['code']} 同时指出镜像与层")
        for code in plan["expected_failure_codes"]:
            check(code in actual_codes, f"诊断包含 {code}")
        check(len(store.list_views()) == 3,
              "只有 3 个成功视图（amd64/arm64/repacked）")
        for key in ("hostile", "corrupt", "zstd", "hardlink"):
            check(store.get_view(images[key]) is None,
                  f"失败镜像 {key} 没有留下可查询的半份视图")
            try:
                list_tree(store, images[key], "/")
                raise AssertionError(f"{key} 不应可查询")
            except KeyError:
                check(True, f"查询失败镜像 {key} 报无视图")

        print("\n== J. 存储隔离：视图库、目录库互不混写 ==")
        views_tables = {r[0] for r in store.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        catalog = store._catalog_conn
        catalog_tables = {r[0] for r in catalog.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        check("entries" in views_tables and "tag_events" not in views_tables,
              "视图库只含视图表，不含目录库表")
        check("image_views" not in catalog_tables
              and "entries" not in catalog_tables,
              "目录库不含视图表，两套库物理隔离")
        check(catalog.execute(
            "SELECT COUNT(*) AS c FROM tag_events").fetchone()["c"] == 8,
            "tag 事件数与目录采集结束时一致（8 个 tag），视图构建零污染")
    finally:
        store.close()
    print("\n全部验收通过")


if __name__ == "__main__":
    main()
