#!/usr/bin/env python3
"""新进程验收：按手写期待表核对公告关联报告与按编号查询结果。

本脚本被 ``run_vuln_demo.py`` 以独立子进程（``python3 -I``）启动。
期待的组件状态、公告组、安装版本与来源位置全部手写为常量表，
**不调用正式区间判定器再算一遍充当答案**。
"""

import argparse
import json
import os
import sys

# ---------------------------------------------------------------------------
# 手写期待表：(文件内引用, 状态, 安装版本, 命中组, 无法判断原因码)
# 安装版本 None 表示报告不应给出；命中组/原因码 None 表示不适用。
# ---------------------------------------------------------------------------
EXPECTED_AMD64 = [
    # shop.cdx.json
    ("SPDXRef-app", "unknown", None, None, "missing_purl"),
    ("SPDXRef-requests", "affected", "2.31.0", "PYSEC-FAKE-0001", None),
    ("SPDXRef-shoplib", "affected", "1.0rc1", "PYSEC-FAKE-0002", None),
    ("SPDXRef-certifi", "affected", "2024.2.2", "GHSA-GHOST-0000", None),
    ("SPDXRef-widget", "affected", "2.0.0-rc.2", "NPM-WIDGET", None),
    ("SPDXRef-gadget", "not_affected_in_feed", "1.4.0+build.7", None, None),
    ("SPDXRef-utils", "not_affected_in_feed", "1.5.0", None, None),
    ("SPDXRef-helper", "affected", "0.9.7", "PYSEC-FAKE-0011", None),
    # attribution.spdx.json（同一镜像的第二份清单）
    ("SPDXRef-requests-spdx", "affected", "2.31.0", "PYSEC-FAKE-0001", None),
    ("SPDXRef-legacylib", "unknown", None, None, "missing_version"),
    ("SPDXRef-openssl", "unknown", "3.0.13", None, "unsupported_ecosystem"),
    ("SPDXRef-internal-blob", "unknown", None, None, "missing_purl"),
    ("SPDXRef-qualpkg", "not_affected_in_feed", "3.1.0", None, None),
]

EXPECTED_ARM64 = [
    ("SPDXRef-edge-app", "unknown", None, None, "missing_purl"),
    ("SPDXRef-requests", "not_affected_in_feed", "2.32.3", None, None),
    ("SPDXRef-shoplib", "not_affected_in_feed", "1.0.post1", None, None),
    ("SPDXRef-widget", "not_affected_in_feed", "2.0.0-rc.10", None, None),
    ("SPDXRef-ghostpkg", "uncovered", "5.0", None, None),
    ("SPDXRef-alphalib", "affected", "1.5", "PACK-AAAA", None),
    ("SPDXRef-betalib", "not_affected_in_feed", "1.5", None, None),
    ("SPDXRef-oddpkg", "unknown", "1.0", None, "unsupported_range_type"),
    ("SPDXRef-mystery", "unknown", "3.0.0", None, "unsupported_range_type"),
    ("SPDXRef-emptyset", "unknown", "9.9", None, "no_version_set"),
    ("SPDXRef-mixedpkg", "unknown", "3.0", None, "unsupported_range_type"),
    ("SPDXRef-toolkit", "uncovered", "7.7.7", None, None),
    ("SPDXRef-helper", "not_affected_in_feed", "0.9.4", None, None),
]

EXPECTED_SUMMARIES = {
    "amd64": {"occurrences": 13, "affected": 6, "unknown": 4,
              "not_affected_in_feed": 3, "uncovered": 0},
    "arm64": {"occurrences": 13, "affected": 1, "unknown": 5,
              "not_affected_in_feed": 5, "uncovered": 2},
}

# 公告等价组（展示名 = 组内字典序最小编号）
EXPECTED_GROUPS = {
    "GHSA-GHOST-0000": ["GHSA-GHOST-0000", "VULN-AAAA", "VULN-BBBB",
                        "VULN-CCCC"],
    "PACK-AAAA": ["PACK-AAAA", "PACK-BBBB"],
    "CVE-GHOST-0001": ["CVE-GHOST-0001", "GHOST-0001"],
    "VULN-DDDD": ["VULN-DDDD"],
}


def check(cond: bool, message: str) -> None:
    if not cond:
        raise AssertionError(message)
    print(f"  ✓ {message}")


def load_json(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def check_report(label: str, report: dict, expected_rows: list,
                 digest: str) -> None:
    print(f"== 报告[{label}]：逐出现项状态 ==")
    check(report["image_digest"] == digest, "镜像 digest 与选定镜像一致")
    check(report["sbom_present"] is True, "报告标记 sbom_present")
    check(report["platform"] is not None and
          report["platform"]["architecture"] in ("amd64", "arm64"),
          f"平台上下文带出（{report['platform']}）")

    occurrences = {o["file_ref"]: o for o in report["occurrences"]}
    check(len(report["occurrences"]) == len(expected_rows),
          f"出现项数量 {len(report['occurrences'])} 与期待一致；"
          f"同一组件在两份清单的出现没有合并成一条库存记录")
    for file_ref, status, version, hit_group, reason in expected_rows:
        occ = occurrences.get(file_ref)
        check(occ is not None, f"{file_ref} 出现在报告中")
        check(occ["status"] == status,
              f"{file_ref} 状态 {status}（实际 {occ['status']}）")
        check(occ["installed_version"] == version,
              f"{file_ref} 安装版本 {version}（实际 "
              f"{occ['installed_version']}）")
        hit_groups = [g["group_id"] for g in occ["groups"]
                      if g["verdict"] == "hit"]
        if hit_group is None:
            check(hit_groups == [], f"{file_ref} 无命中组")
        else:
            check(hit_groups == [hit_group],
                  f"{file_ref} 命中组 {hit_group}（实际 {hit_groups}）")
        if reason is not None:
            codes = [r["code"] for r in occ["reasons"]]
            group_reasons = [r["code"] for g in occ["groups"]
                             for r in g["reasons"]]
            check(reason in codes or reason in group_reasons,
                  f"{file_ref} 无法判断原因 {reason}")

    expected_summary = EXPECTED_SUMMARIES[label]
    check(report["summary"] == expected_summary,
          f"汇总 {expected_summary} 与期待一致")
    check(any("没有漏洞" in line for line in report["limitations"]),
          "报告保留限制声明：没有找到命中不代表镜像没有漏洞")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--plan", required=True)
    args = parser.parse_args()
    plan = load_json(args.plan)

    amd64_report = load_json(plan["reports"]["amd64"])
    arm64_report = load_json(plan["reports"]["arm64"])

    check_report("amd64", amd64_report, EXPECTED_AMD64, plan["amd64"])
    check_report("arm64", arm64_report, EXPECTED_ARM64, plan["arm64"])

    print("\n== 逐条核对的代表性判定依据 ==")
    occ = {o["file_ref"]: o for o in amd64_report["occurrences"]}
    # requests 2.31.0 命中 [2.31.0, 2.32.3)：证据指出公告 id 与 affected 下标
    evidence = next(g for g in occ["SPDXRef-requests"]["groups"]
                    if g["verdict"] == "hit")["evidence"][0]
    check(evidence["advisory_id"] == "PYSEC-FAKE-0001" and
          evidence["affected_index"] == 0 and evidence["kind"] == "range",
          "requests 命中依据指出公告 id、affected 下标与区间位置")
    # certifi 命中来自 versions 精确列表（与区间的并集）
    cert_groups = {g["group_id"]: g for g in occ["SPDXRef-certifi"]["groups"]}
    check(set(cert_groups) == {"GHSA-GHOST-0000", "VULN-DDDD", "CERTIFI-GIT"},
          "certifi 相关组：别名环一组 + related 独立组 + GIT 未知组")
    check(cert_groups["GHSA-GHOST-0000"]["verdict"] == "hit" and
          cert_groups["VULN-DDDD"]["verdict"] == "miss" and
          cert_groups["CERTIFI-GIT"]["verdict"] == "unknown",
          "certifi：别名环命中、related 不命中、GIT 未知，命中不被未知抹掉")
    cert_evidence = cert_groups["GHSA-GHOST-0000"]["evidence"][0]
    check(cert_evidence["kind"] == "versions" and
          cert_evidence["advisory_id"] == "VULN-AAAA",
          "certifi 命中依据来自 VULN-AAAA 的 versions 精确列表")
    # helper 0.9.7 命中“引入—修复—再次引入”的 last_affected 包含端点
    helper_ev = next(g for g in occ["SPDXRef-helper"]["groups"]
                     if g["verdict"] == "hit")["evidence"][0]
    check(helper_ev["interval"]["close_kind"] == "last_affected" and
          helper_ev["interval"]["close"] == "0.9.7",
          "helper 0.9.7 命中 last_affected 包含端点（再次引入段）")
    # gadget：构建元数据不改变区间先后，精确列表按文本不匹配
    gadget = occ["SPDXRef-gadget"]
    check(gadget["installed_version"] == "1.4.0+build.7" and
          gadget["status"] == "not_affected_in_feed",
          "gadget 1.4.0+build.7：fixed 1.4.0 排除端点且 versions 文本不同")
    # qualpkg：qualifiers 原样带回
    qualpkg = occ["SPDXRef-qualpkg"]
    check(qualpkg["canonical_purl"] ==
          "pkg:pypi/qualpkg@3.1.0?arch=AMD64&repo=main" and
          qualpkg["purl_raw"] ==
          "pkg:pypi/qualpkg@3.1.0?repo=main&arch=%41MD64",
          "qualpkg qualifiers 原样带回（canonical 与原 purl 都保留）")
    # 同坐标重复出现：requests 2.31.0 在两份清单各一条记录
    req_refs = [o for o in amd64_report["occurrences"]
                if o["canonical_purl"] == "pkg:pypi/requests@2.31.0"]
    check(len(req_refs) == 2 and
          {o["file_ref"] for o in req_refs} ==
          {"SPDXRef-requests", "SPDXRef-requests-spdx"} and
          len({o["source_path"] for o in req_refs}) == 2,
          "requests 2.31.0 在两份清单中的重复出现各自保留")

    print("\n== arm64 代表性判定 ==")
    occ64 = {o["file_ref"]: o for o in arm64_report["occurrences"]}
    check(occ64["SPDXRef-requests"]["status"] == "not_affected_in_feed",
          "requests 2.32.3 恰为 fixed 排除端点，不命中")
    check(occ64["SPDXRef-shoplib"]["status"] == "not_affected_in_feed",
          "shoplib 1.0.post1 高于 fixed 1.0（dev/rc/post 次序）")
    check(occ64["SPDXRef-widget"]["status"] == "not_affected_in_feed",
          "widget 2.0.0-rc.10 恰为 fixed 排除端点（rc.2 < rc.10）")
    check(occ64["SPDXRef-helper"]["status"] == "not_affected_in_feed",
          "helper 0.9.4 落在修复—再次引入之间的间隙，不命中")
    check(occ64["SPDXRef-ghostpkg"]["status"] == "uncovered",
          "ghostpkg 只有已撤回公告：uncovered 而非受影响")
    check(occ64["SPDXRef-betalib"]["status"] == "not_affected_in_feed" and
          occ64["SPDXRef-alphalib"]["status"] == "affected",
          "同组不同包不串范围：alphalib 命中、betalib 不命中")

    print("\n== 公告等价组 ==")
    groups = {g["group_id"]: g for g in amd64_report["advisory_groups"]}
    for display, members in EXPECTED_GROUPS.items():
        check(display in groups and groups[display]["member_ids"] == members,
              f"等价组 {display} 成员 {members}")
    check(groups["CVE-GHOST-0001"]["withdrawn_ids"] == ["GHOST-0001"],
          "撤回公告保留在组内作编号解释但不贡献范围")
    check(groups["GHSA-GHOST-0000"]["valid_advisories"] ==
          ["VULN-AAAA", "VULN-BBBB", "VULN-CCCC"],
          "别名传递环三份公告同组（GHSA-GHOST-0000 无独立文件）")
    check(groups["VULN-DDDD"]["related_ids"] == ["VULN-AAAA"],
          "related 只作关联记录，不并组")

    print("\n== 另一进程按公告编号查询 ==")
    alias_cycle = load_json(plan["queries"]["alias-cycle"])
    check(alias_cycle["group"]["group_id"] == "GHSA-GHOST-0000",
          "用 VULN-CCCC 查询解析到等价组 GHSA-GHOST-0000")
    check(len(alias_cycle["hits"]) == 1, "别名环查询命中 1 个安装项")
    hit = alias_cycle["hits"][0]
    check(hit["installed_version"] == "2024.2.2" and
          hit["file_ref"] == "SPDXRef-certifi" and
          hit["location"] == "$.components[3]" and
          hit["image_digest"] == plan["amd64"],
          "命中安装项给出安装版本、文件内引用、源位置与镜像")
    check(hit["evidence"][0]["advisory_id"] == "VULN-AAAA",
          "命中依据指出实际贡献的公告 id")

    alias_nofile = load_json(plan["queries"]["alias-nofile"])
    check(alias_nofile["group"]["group_id"] == "GHSA-GHOST-0000" and
          len(alias_nofile["hits"]) == 1,
          "无独立文件的别名 GHSA-GHOST-0000 同样解析到该组")

    withdrawn = load_json(plan["queries"]["withdrawn"])
    check(withdrawn["group"]["group_id"] == "CVE-GHOST-0001" and
          withdrawn["hits"] == [] and
          any("撤回" in note for note in withdrawn["notes"]),
          "已撤回公告的别名可查询，但组内无有效公告、无命中")

    related = load_json(plan["queries"]["related-only"])
    check(related["group"]["group_id"] == "VULN-DDDD" and
          related["hits"] == [],
          "仅 related 的编号是独立组，不共享别名环的命中")

    all_loc = load_json(plan["queries"]["all-locations"])
    check(all_loc["group"]["group_id"] == "PYSEC-FAKE-0001" and
          len(all_loc["hits"]) == 2,
          "同一坐标在两份清单中的命中：全部来源位置都列出")
    check({h["file_ref"] for h in all_loc["hits"]} ==
          {"SPDXRef-requests", "SPDXRef-requests-spdx"} and
          all(h["installed_version"] == "2.31.0"
              for h in all_loc["hits"]) and
          len({h["location"] for h in all_loc["hits"]}) == 2,
          "两个命中各自保留文件内引用、安装版本与源位置")

    print("\n== 失败语义 ==")
    quiet = plan["quiet_result"]
    check(quiet["exit_code"] == 3 and "no_sbom" in quiet["stderr"],
          "无 SBOM 镜像：退出码 3 单独说明，不输出零漏洞成功结论")
    expected_bad = {
        "regress": ("range_regressed",
                    "bad-regress.json:$.affected[0].ranges[0].events[1]"),
        "overlap": ("range_overlap",
                    "bad-overlap.json:$.affected[0].ranges[0].events[2]"),
        "duplicate-id": ("duplicate_advisory_id",
                         "bad-duplicate-id.json:$.id"),
        "duplicate-json-key": ("duplicate_json_key", "bad-dup-key.json:$"),
    }
    for label, (code, location) in expected_bad.items():
        result = plan["bad_results"][label]
        check(result["exit_code"] == 2, f"坏公告 {label} 退出码 2")
        diagnostics = json.loads(result["stderr"])["diagnostics"]
        check(any(d["code"] == code and d["location"] == location
                  for d in diagnostics),
              f"坏公告 {label} 诊断定位 {location}")

    print("\n全部验收通过")


if __name__ == "__main__":
    main()
