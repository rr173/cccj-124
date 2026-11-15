#!/usr/bin/env python3
"""新进程验收：换策略重评价已保存的原始证据，按独立列出的期待值核对。

本脚本被 ``run_provenance_demo.py`` 以独立子进程（``python3 -I``）启动，
模拟交付人员在另一个进程中打开已落库的证明证据库做评价与查询——此时
供应商信封原始文件已被移走，所有结论只能来自库中保存的原始证据。

期待的镜像绑定位置、材料出现项、有效指纹集合与结论都在本文件中**手写
列出**（指纹与材料摘要为字面量），不是用导出再导入自证。
"""

import argparse
import contextlib
import io
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from oci_catalog.provenance.policy import load_policy
from oci_catalog.provenance.provenance_cli import main as cli_main
from oci_catalog.provenance.queries import (
    query_image_provenance,
    query_material_images,
)
from oci_catalog.provenance.store import ProvenanceStore

# ---------------------------------------------------------------------------
# 独立列出的期待值（字面量；与夹具输入分开维护）
# ---------------------------------------------------------------------------
EXPECTED_FINGERPRINTS = {
    "key-a": "sha256:d6f021da6db21e8b3533f9b447211180744d3e28cfcd7a3f836f0c75c8698fa4",
    "key-b": "sha256:a4840f17322098d4e4d07d434c1e14281aa706c219ae01c6e98217c2a5137041",
    "key-c": "sha256:7dabf92b3c9fd2d99a4c36f741892b88322332ac8e000f78de628cf76bcd2495",
}

BUILDER_ID = "https://builder.example.com/offline-etl"
BUILD_TYPE = "https://buildtypes.example.com/offline-etl/v1"
INVOCATION_AMD64 = "etl-task-amd64-2026-11-01"
INVOCATION_ARM64 = "etl-task-arm64-2026-11-01"

SHARED_URI = "https://mirror.example.com/datasets/etl-input-2026.11.tar.gz"
SHARED_SHA256 = "7b69af3d47193f0c87d042e9e6fbaf9bb581cc4346a6549cbe5f674d7caf136a"
REF_URI = "https://mirror.example.com/datasets/reference-dict.csv"
REF_AMD64_SHA256 = "6f4ba24405807c3958823354468063db64a6ab2fc90a1a0570c5e341635e3fae"
REF_ARM64_SHA256 = "917078f0c236a90fe679bc594bf9cae783af13b841642d05d4c5dab224cef63a"
TOOLCHAIN_URI = "https://mirror.example.com/toolchains/etl-builder-4.2.0.tar.gz"
TOOLCHAIN_SHA256 = "e4c1b4eeafe69d125715da0878f23ac243663121fd49f9fed226d7455b4db492"


def check(cond: bool, message: str) -> None:
    if not cond:
        raise AssertionError(message)
    print(f"  ✓ {message}")


def run_cli(argv: list) -> tuple[int, dict]:
    stdout = io.StringIO()
    with contextlib.redirect_stdout(stdout):
        rc = cli_main(argv)
    return rc, json.loads(stdout.getvalue())


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--plan", required=True)
    args = parser.parse_args()
    with open(args.plan, encoding="utf-8") as fh:
        plan = json.load(fh)

    prov_db, catalog_db = plan["prov_db"], plan["catalog_db"]
    amd64, arm64 = plan["amd64"], plan["arm64"]
    policies = {}
    for name, path in plan["policies"].items():
        with open(path, "rb") as fh:
            policies[name] = load_policy(fh.read())
    p1 = policies["policy-p1.json"]
    p2 = policies["policy-p2.json"]
    p3 = policies["policy-p3.json"]

    store = ProvenanceStore(prov_db, catalog_db)
    try:
        print("== A. 原始证据在库（供应商文件已移走，仍可评价） ==")
        evidences = store.list_all_evidence()
        check(len(evidences) == 2, "两份证据（amd64/arm64 各一）")
        by_image = {e["image_digest"]: e for e in evidences}
        check(set(by_image) == {amd64, arm64}, "证据绑定到两个平台镜像")
        check(bytes(by_image[amd64]["payload_bytes"]).startswith(b"{"),
              "payload 原始字节保存在库中，无需供应商文件")

        print("\n== B. 换策略重评价：不沿用旧策略的通过标志 ==")
        # P1（key-a+key-b 门槛 2）：amd64 可信、arm64 一票不足
        rc, out = run_cli(["--catalog", catalog_db, "--prov", prov_db,
                           "verify", "--policy",
                           plan["policies"]["policy-p1.json"]])
        check(rc == 0, "新进程中命令行 verify 正常运行")
        verdicts = {e["evidence_id"]: e for e in out["evaluations"]}
        amd_id = by_image[amd64]["evidence_id"]
        arm_id = by_image[arm64]["evidence_id"]
        check(verdicts[amd_id]["verdict"] == "trusted",
              "P1 下 amd64 可信（key-a+key-b 达到门槛 2）")
        check(verdicts[arm_id]["verdict"] == "untrusted" and
              verdicts[arm_id]["reason"] == "threshold_not_met",
              "P1 下 arm64 只有 key-b 一票，未达门槛")
        check(sorted(verdicts[amd_id]["counted_fingerprints"]) ==
              sorted([EXPECTED_FINGERPRINTS["key-a"],
                      EXPECTED_FINGERPRINTS["key-b"]]),
              "amd64 计入门槛的指纹集合 = {key-a, key-b}（字面量核对）")

        # P2（撤掉 key-a，授权 key-b+key-c）：amd64 不再通过，arm64 转为可信
        rc, out = run_cli(["--catalog", catalog_db, "--prov", prov_db,
                           "verify", "--policy",
                           plan["policies"]["policy-p2.json"]])
        verdicts = {e["evidence_id"]: e for e in out["evaluations"]}
        check(verdicts[amd_id]["verdict"] == "untrusted" and
              verdicts[amd_id]["reason"] == "threshold_not_met",
              "P2 撤掉 key-a 授权后，amd64 旧证据不再通过")
        check(verdicts[amd_id]["counted_fingerprints"] ==
              [EXPECTED_FINGERPRINTS["key-b"]],
              "P2 下 amd64 只剩 key-b 一票")
        check(verdicts[arm_id]["verdict"] == "trusted",
              "P2 下 arm64 转为可信（key-b+key-c 达到门槛）")
        check(sorted(verdicts[arm_id]["counted_fingerprints"]) ==
              sorted([EXPECTED_FINGERPRINTS["key-b"],
                      EXPECTED_FINGERPRINTS["key-c"]]),
              "arm64 计入门槛的指纹集合 = {key-b, key-c}")

        # P3（另一组足够的授权 key-a+key-b+key-c）：两者都恢复可信
        rc, out = run_cli(["--catalog", catalog_db, "--prov", prov_db,
                           "verify", "--policy",
                           plan["policies"]["policy-p3.json"]])
        verdicts = {e["evidence_id"]: e for e in out["evaluations"]}
        check(verdicts[amd_id]["verdict"] == "trusted" and
              verdicts[arm_id]["verdict"] == "trusted",
              "P3 另一组足够的授权，两个镜像都恢复可信")

        print("\n== C. 镜像来源查询（P3，命令行在新进程运行） ==")
        rc, report = run_cli(["--catalog", catalog_db, "--prov", prov_db,
                              "image", "--policy",
                              plan["policies"]["policy-p3.json"],
                              "--digest", amd64])
        check(rc == 0, "image 查询命令正常")
        entry = report["evidence"][0]
        check(entry["builder_id"] == BUILDER_ID, "构建者按原值返回")
        check(entry["build_type"] == BUILD_TYPE, "构建类型按原值返回")
        check(entry["invocation_id"] == INVOCATION_AMD64, "任务标识返回")
        check(entry["bound_subject_indices"] == [1],
              "绑定命中 subject 非首项（位置 1，首项是源码包）")
        check([m["material_index"] for m in entry["materials"]] == [0, 1, 2, 3],
              "amd64 四个材料出现位置全部保留")
        shared_positions = [m["material_index"] for m in entry["materials"]
                            if m["uri"] == SHARED_URI]
        check(shared_positions == [0, 3],
              "完全重复的共享材料两处出现（位置 0 与 3）都可查回")
        check(report["platform"]["architecture"] == "amd64",
              "平台上下文从目录库带出")

        print("\n== D. 材料反查（P3；只含可信证明） ==")
        shared = query_material_images(store, SHARED_URI, SHARED_SHA256, p3)
        check(sorted(m["image_digest"] for m in shared["matches"]) ==
              sorted([amd64, arm64]),
              "共享材料反查命中两个平台镜像")
        amd_match = next(m for m in shared["matches"]
                         if m["image_digest"] == amd64)
        check(amd_match["material_positions"] == [0, 3],
              "amd64 的共享材料两处出现位置都带回")
        check(amd_match["invocation_id"] == INVOCATION_AMD64,
              "反查带回构建任务标识")

        ref_amd = query_material_images(store, REF_URI, REF_AMD64_SHA256, p3)
        check([m["image_digest"] for m in ref_amd["matches"]] == [amd64],
              "同 URI 的 amd64 版参考字典只命中 amd64")
        ref_arm = query_material_images(store, REF_URI, REF_ARM64_SHA256, p3)
        check([m["image_digest"] for m in ref_arm["matches"]] == [arm64],
              "同 URI 的 arm64 版参考字典只命中 arm64（不串结果）")
        toolchain = query_material_images(
            store, TOOLCHAIN_URI, TOOLCHAIN_SHA256, p3)
        check([m["image_digest"] for m in toolchain["matches"]] == [amd64],
              "工具链材料只命中 amd64")

        # P2 策略下反查共享材料：amd64 不可信 -> 只剩 arm64
        shared_p2 = query_material_images(store, SHARED_URI, SHARED_SHA256, p2)
        check([m["image_digest"] for m in shared_p2["matches"]] == [arm64],
              "P2 下共享材料反查只剩 arm64（未通过证明的材料不混入）")

        print("\n== E. 评价历史：每次结论依据哪套规则可查 ==")
        history = store.list_evaluations()
        used_policies = {row["policy_sha256"] for row in history}
        check(p1.policy_sha256 in used_policies and
              p2.policy_sha256 in used_policies and
              p3.policy_sha256 in used_policies,
              "评价历史记录了三份策略各自的内容摘要")
        amd_history = [row for row in store.list_evaluations(amd_id)]
        check(any(row["verdict"] == "trusted" for row in amd_history) and
              any(row["verdict"] == "untrusted" for row in amd_history),
              "同一证据在不同策略下的结论分别留痕（trusted/untrusted 都有）")

        print("\n== F. 库隔离：目录库只读、证据库独立 ==")
        catalog = store._catalog_conn
        check(catalog.execute(
            "SELECT COUNT(*) AS c FROM tag_events").fetchone()["c"] ==
            plan["baseline_events"],
            "tag 事件数与采集结束时一致，证明接入未污染目录库")
        catalog_tables = {r[0] for r in catalog.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        prov_tables = {r[0] for r in store.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        check("evidence" not in catalog_tables and
              "tag_events" not in prov_tables,
              "证据库与目录库物理隔离")
    finally:
        store.close()
    print("\n全部验收通过")


if __name__ == "__main__":
    main()
