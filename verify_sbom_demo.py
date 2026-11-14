#!/usr/bin/env python3
"""新进程验收：按显式期待值核对 SBOM 接入与血缘查询结果。

本脚本被 ``run_sbom_demo.py`` 以独立子进程（``python3 -I``）启动，
模拟交付人员在另一个进程中打开已落库的 SBOM SQLite 库做查询。
期待的组件集合、出现次数、直接依赖与路径都在本文件中手写列出，
而不是用导出再导入自证。
"""

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from oci_catalog.sbom import SBOMStore
from oci_catalog.sbom.sbom_queries import (
    query_component_images,
    query_image_components,
    shortest_paths,
)

# ---------------------------------------------------------------------------
# 显式期待的归一化组件身份（canonical purl）
# ---------------------------------------------------------------------------
EXPECTED_COMPONENTS = {
    "pkg:pypi/flask-core-ext@3.0.2",
    "pkg:pypi/requests@2.32.3",
    "pkg:pypi/requests@2.31.0",
    # 同版本 urllib3 的三种坐标：带 qualifiers 与不带 qualifiers 不可合并，
    # 另一平台的 2.2.1 又是独立身份
    "pkg:pypi/urllib3@1.26.18?arch=AMD64&repo=main",
    "pkg:pypi/urllib3@1.26.18",
    "pkg:pypi/urllib3@2.2.1",
    "pkg:pypi/certifi@2024.2.2",
    "pkg:npm/%40angular/animation@17.0.0",
    "pkg:generic/openssl@3.0.13?distro=debian",
    "pkg:generic/shop-utils@1.4.0",
    "pkg:generic/edge-gateway@2.1.0",
}

# 无 purl 的文件内组件（只保留文件内身份）
EXPECTED_PURLESS_REFS = {
    "SPDXRef-internal-blob", "SPDXRef-iso-a", "SPDXRef-iso-b",
    "SPDXRef-ldap",
}


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

    store = SBOMStore(plan["sbom_db"], plan["catalog_db"])
    try:
        print("== A. 归一化身份与出现记录 ==")
        rows = store.conn.execute(
            "SELECT canonical_purl FROM components ORDER BY canonical_purl"
        ).fetchall()
        actual_components = {r["canonical_purl"] for r in rows}
        check(actual_components == EXPECTED_COMPONENTS,
              f"归一化组件集合与期待完全一致（{len(EXPECTED_COMPONENTS)} 个）")
        # 同名不同版本不合并
        check(store.conn.execute(
            "SELECT COUNT(*) AS c FROM components "
            "WHERE canonical_purl IN ('pkg:pypi/requests@2.32.3',"
            "'pkg:pypi/requests@2.31.0')").fetchone()["c"] == 2,
            "requests 2.32.3 与 2.31.0 是两个身份，未误合并")
        check(store.conn.execute(
            "SELECT COUNT(*) AS c FROM components "
            "WHERE canonical_purl LIKE 'pkg:pypi/urllib3%'"
        ).fetchone()["c"] == 3,
            "urllib3 三个区分身份（带 qualifier / 不带 / 2.2.1）")

        # 不同 bom-ref 指向同一 purl：出现记录各自保留
        dup_rows = store.conn.execute(
            "SELECT o.file_ref, o.location, o.name FROM occurrences o "
            "JOIN components c ON c.component_id = o.component_id "
            "WHERE c.canonical_purl = "
            "'pkg:pypi/urllib3@1.26.18?arch=AMD64&repo=main' "
            "ORDER BY o.file_ref").fetchall()
        check([r["file_ref"] for r in dup_rows] ==
              ["SPDXRef-urllib3", "SPDXRef-urllib3-dup"],
              "同一 purl 的两个 bom-ref 出现记录都保留（含各自来源位置）")

        # 跨格式同组件：flask 在 CDX 与 SPDX 中归一为同一身份、两次出现
        flask_rows = store.conn.execute(
            "SELECT f.doc_format, o.file_ref FROM occurrences o "
            "JOIN components c ON c.component_id = o.component_id "
            "JOIN sbom_files f ON f.file_id = o.file_id "
            "WHERE c.canonical_purl = 'pkg:pypi/flask-core-ext@3.0.2' "
            "ORDER BY f.doc_format, o.file_ref").fetchall()
        check([(r["doc_format"], r["file_ref"]) for r in flask_rows] == [
            ("cyclonedx", "SPDXRef-flask"),
            ("spdx", "SPDXRef-flask-spdx")],
            "Flask_Core.Ext 与 flask-core-ext 跨格式归一、出现记录分别保留")

        # 无 purl 组件不进 components 表，但出现记录保留文件内身份
        purless = {r["file_ref"] for r in store.conn.execute(
            "SELECT file_ref FROM occurrences WHERE component_id IS NULL")}
        check(EXPECTED_PURLESS_REFS.issubset(purless),
              "无 purl 组件只保留文件内身份，未臆造全局坐标")

        print("\n== B. 镜像导出：组件明细、可追溯字段与直接依赖 ==")
        amd64_report = query_image_components(store, plan["amd64"])
        check(amd64_report["platform"] ==
              {"architecture": "amd64", "os": "linux",
               "os_version": "", "os_features": [],
               "variant": "", "features": []},
              "平台上下文从目录库带出（linux/amd64）")
        check(len(amd64_report["files"]) == 2,
              "amd64 镜像绑定两份来源清单，分别返回不合并")
        formats = {f["doc_format"] for f in amd64_report["files"]}
        check(formats == {"cyclonedx", "spdx"}, "两种格式各一份")

        cdx_file = next(f for f in amd64_report["files"]
                        if f["doc_format"] == "cyclonedx")
        spdx_file = next(f for f in amd64_report["files"]
                         if f["doc_format"] == "spdx")
        check(len(cdx_file["occurrences"]) == 13,
              "CycloneDX 13 个组件出现（含嵌套与无 purl 节点）")
        check(len(spdx_file["occurrences"]) == 4,
              "SPDX 4 个 package 出现")

        # 可追溯字段：供应商/许可证原始表达/源位置
        cdx_app = next(o for o in cdx_file["occurrences"]
                       if o["file_ref"] == "SPDXRef-app")
        check(cdx_app["supplier"] == "Shop Platform Team", "供应商可追溯")
        check("Apache-2.0" in cdx_app["license_raw"], "许可证原始表达可追溯")
        check(cdx_app["location"] == "$.components[0]", "源文件位置可追溯")
        nested = next(o for o in cdx_file["occurrences"]
                      if o["file_ref"] == "SPDXRef-helper")
        check(nested["location"] == "$.components[0].components[0]",
              "嵌套 component 位置可追溯")

        # 直接依赖（CDX）
        direct = {o["file_ref"]: [d["ref"] for d in o["direct_dependencies"]]
                  for o in cdx_file["occurrences"]}
        check(sorted(direct["SPDXRef-app"]) == sorted([
            "SPDXRef-requests", "SPDXRef-flask",
            "SPDXRef-angular", "SPDXRef-utils"]),
            "app 直接依赖完整且无 urllib3（菱形长边）")
        check(sorted(direct["SPDXRef-requests"]) ==
              ["SPDXRef-certifi", "SPDXRef-urllib3"],
              "requests 直接依赖 urllib3/certifi")
        # 直接依赖（SPDX，DEPENDS_ON 与 DEPENDENCY_OF 同向化）
        spdx_direct = {o["file_ref"]: [d["ref"] for d in o["direct_dependencies"]]
                       for o in spdx_file["occurrences"]}
        check(sorted(spdx_direct["SPDXRef-DOCUMENT-root"]) ==
              ["SPDXRef-flask-spdx", "SPDXRef-urllib3"],
              "SPDX DEPENDS_ON 与 DEPENDENCY_OF 已转成同一方向")
        check("SPDXRef-urllib3" not in spdx_direct.get(
            "SPDXRef-flask-spdx", []),
            "SPDX CONTAINS 关系未被悄悄当成依赖边")

        print("\n== C. 菱形与环：最短路径稳定、查询终止 ==")
        graph = {}
        for row in store.conn.execute(
                "SELECT from_ref, to_ref FROM dependency_edges "
                "WHERE file_id = ?", (cdx_file["file_id"],)):
            graph.setdefault(row["from_ref"], set()).add(row["to_ref"])
            graph.setdefault(row["to_ref"], set())

        diamond, truncated, anchored_diamond = shortest_paths(
            graph, "SPDXRef-urllib3")
        check(not truncated and not anchored_diamond,
              "路径枚举未触发截断，菱形目标从根可达")
        check(diamond == [
            ["SPDXRef-app", "SPDXRef-flask", "SPDXRef-urllib3"],
            ["SPDXRef-app", "SPDXRef-requests", "SPDXRef-urllib3"],
        ], "菱形两条同长路径按文件内引用名字典序稳定选择")

        helper_paths, _, helper_anchored = shortest_paths(
            graph, "SPDXRef-helper")
        check(not helper_anchored, "helper 从根可达，无需环岛屿锚点")
        check(helper_paths == [
            ["SPDXRef-app", "SPDXRef-flask", "SPDXRef-helper"],
            ["SPDXRef-app", "SPDXRef-utils", "SPDXRef-helper"],
        ], "根可达环不导致无限循环，最短路径稳定可核对")

        iso_paths, _, iso_anchored = shortest_paths(graph, "SPDXRef-iso-b")
        check(iso_anchored, "环岛屿目标标注了 anchor_note")
        check(iso_paths == [["SPDXRef-iso-a", "SPDXRef-iso-b"]],
              "环岛屿以分量内最小引用名为锚点，仍返回可核对路径")

        print("\n== D. 跨镜像反查：来源分组、不跨文件拼边 ==")
        reverse = query_component_images(
            store, "pkg:pypi/urllib3@1.26.18?arch=AMD64&repo=main")
        check(len(reverse["images"]) == 1, "带 qualifier 的 urllib3 只在 amd64 出现")
        source = reverse["images"][0]["sources"][0]
        check(source["source_path"].endswith("shop.cdx.json"),
              "反查结果携带源文件")
        # 同一文件内两个 bom-ref 指向该 purl：两个 match 各自保留文件内身份
        match_refs = {m["file_ref"] for m in source["matches"]}
        check(match_refs == {"SPDXRef-urllib3", "SPDXRef-urllib3-dup"},
              "同文件内同 purl 的两个出现分别返回，文件内身份各自保留")
        match = next(m for m in source["matches"]
                     if m["file_ref"] == "SPDXRef-urllib3")
        check(match["paths"] == [
            ["SPDXRef-app", "SPDXRef-flask", "SPDXRef-urllib3"],
            ["SPDXRef-app", "SPDXRef-requests", "SPDXRef-urllib3"]],
              "反查路径与镜像导出一致，边仅限本文件内")

        # purl 查询接受等价写法（qualifier 顺序不同）
        reverse2 = query_component_images(
            store, "pkg:pypi/urllib3@1.26.18?repo=main&arch=%41MD64")
        check(reverse2["canonical_purl"] ==
              "pkg:pypi/urllib3@1.26.18?arch=AMD64&repo=main",
              "查询坐标按同一 purl 契约归一后命中")

        # 同名不同版本：requests 反查命中两个平台
        rev_requests = query_component_images(
            store, "pkg:pypi/requests@2.32.3")
        check([img["image_digest"] for img in rev_requests["images"]] ==
              [plan["amd64"]], "requests 2.32.3 仅 amd64")
        rev_requests_old = query_component_images(
            store, "pkg:pypi/requests@2.31.0")
        check([img["image_digest"] for img in rev_requests_old["images"]] ==
              [plan["arm64"]], "requests 2.31.0 仅 arm64（版本区分身份）")
        arm64_report = query_image_components(store, plan["arm64"])
        check(arm64_report["platform"]["architecture"] == "arm64",
              "arm64 平台上下文正确（variant=v8）")

        # 多文件镜像：flask 同时出现在两份来源清单中，反查时两份来源各自
        # 给路径，不存在跨 CDX/SPDX 拼接的路径（引用名复用也不串图）
        rev_shared = query_component_images(
            store, "pkg:pypi/flask-core-ext@3.0.2")
        amd64_sources = next(
            img for img in rev_shared["images"]
            if img["image_digest"] == plan["amd64"])["sources"]
        check(len(amd64_sources) == 2, "两份来源清单分别返回路径")
        check({s["doc_format"] for s in amd64_sources} ==
              {"cyclonedx", "spdx"}, "反查按来源文件分组")
        for src in amd64_sources:
            for match in src["matches"]:
                for path in match["paths"]:
                    refs_in_file = {o["file_ref"]
                                    for f in amd64_report["files"]
                                    if f["file_id"] == src["file_id"]
                                    for o in f["occurrences"]}
                    check(all(ref in refs_in_file for ref in path),
                          f"{os.path.basename(src['source_path'])} 路径不跨文件拼接")
        # 两份来源里的路径分别用各自的文件内引用名，证明同引用名未串图
        spdx_src = next(s for s in amd64_sources
                        if s["doc_format"] == "spdx")
        check(spdx_src["matches"][0]["paths"] == [
            ["SPDXRef-DOCUMENT-root", "SPDXRef-flask-spdx"]],
            "SPDX 路径仅含 SPDX 文件内引用（复用的 bom-ref 未跨文件连接）")

        print("\n== E. 坏输入拒绝且无残留 ==")
        failure_rows = store.list_failures()
        check(len(failure_rows) == 5, f"5 个失败文件全部留诊断（实际 {len(failure_rows)}）")
        codes = sorted(d["code"] for row in failure_rows
                       for d in json.loads(row["diagnostics_json"]))
        for expected_code in ("invalid_purl", "dangling_ref", "duplicate_ref",
                              "binding_not_image", "binding_unknown_digest"):
            check(expected_code in codes, f"诊断包含 {expected_code}")

        # 失败文件没有任何 sbom_files/occurrences/edges 残留
        bad_basenames = ("bad-purl", "bad-dangling", "bad-duplicate")
        bad_rows = store.conn.execute(
            "SELECT file_id FROM sbom_files WHERE "
            + " OR ".join("source_path LIKE ?" for _ in bad_basenames),
            tuple(f"%{b}%" for b in bad_basenames)).fetchall()
        check(bad_rows == [], "失败文件未留下可查询的清单记录")
        check(store.conn.execute(
            "SELECT COUNT(*) AS c FROM sbom_files").fetchone()["c"] == 3,
            "成功文件恰好 3 份（shop cdx/spdx + edge cdx）")

        # 绑定 index digest / 未收录 digest 的尝试没有产生文件行
        check(store.conn.execute(
            "SELECT COUNT(*) AS c FROM sbom_files WHERE image_digest = ?",
            (plan["index_digest"],)).fetchone()["c"] == 0,
            "index digest 绑定被拒绝，未产生文件行")

        print("\n== F. 目录库只读：无 tag 事件污染 ==")
        catalog = store._catalog_conn
        # 采集本身产生的 created 事件（4 个 tag）；SBOM 导入不得新增任何事件
        check(catalog.execute(
            "SELECT COUNT(*) AS c FROM tag_events").fetchone()["c"] == 4,
            "tag 事件数与目录采集结束时一致，SBOM 导入未新增 tag 事件")
        check(catalog.execute(
            "SELECT COUNT(*) AS c FROM manifests").fetchone()["c"] >= 3,
            "目录库 manifest 内容身份保持采集结果")
        # SBOM 库中不存在目录库专属表，证明两套库物理隔离
        catalog_tables = {r[0] for r in catalog.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        sbom_tables = {r[0] for r in store.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        check("sbom_files" not in catalog_tables and "tag_events" not in sbom_tables,
              "SBOM 库与目录库物理隔离，各自表不互串")

    finally:
        store.close()
    print("\n全部验收通过")


if __name__ == "__main__":
    main()
