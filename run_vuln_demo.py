#!/usr/bin/env python3
"""离线公告关联端到端演示（含独立进程验收）。

流程：

1. 用内置假 registry 采集三个单平台镜像（amd64 / arm64 / 无 SBOM 的
   quiet）与一个多平台索引；
2. 用既有 SBOM 子系统把三份清单绑定到两个平台镜像（同一坐标
   ``pkg:pypi/requests@2.31.0`` 故意出现在 amd64 的两份清单中）；
3. 生成人工 OSV 风格公告目录（样例覆盖见
   ``oci_catalog/vuln/sample_data.py`` 模块 docstring）；
4. 在**命令行子进程**中为两个平台镜像生成版本判定报告（JSON）；
5. 在**另一批子进程**中按别名查询命中安装项（含无独立文件的别名与
   已撤回公告的别名）；
6. 演示失败语义：无 SBOM 镜像单独说明（退出码 3），倒退/重叠/重复 id/
   重复 JSON 键的公告目录整次作业失败（退出码 2）；
7. 启动 ``verify_vuln_demo.py`` 新进程，按手写期待表逐项核对。

运行：.venv/bin/python -I run_vuln_demo.py
（需要 packaging 与 semantic_version；纯离线，不访问在线漏洞库）
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from oci_catalog import (
    CatalogStore,
    Collector,
    FakeRegistry,
    RegistryClient,
    make_image_manifest,
    make_index_manifest,
)
from oci_catalog.sbom.sbom_cli import main as sbom_cli_main
from oci_catalog.vuln.sample_data import (
    BAD_DUP_KEY_TEXT,
    IMAGE_AMD64_DIGEST,
    IMAGE_ARM64_DIGEST,
    IMAGE_QUIET_DIGEST,
    REGISTRY_IMAGES,
    advisories,
    bad_duplicate_id,
    bad_overlap,
    bad_regress,
    edge_cdx,
    shop_cdx,
    shop_spdx,
)

HERE = os.path.dirname(os.path.abspath(__file__))
IMAGE_MEDIA = "application/vnd.oci.image.manifest.v1+json"
INDEX_MEDIA = "application/vnd.oci.image.index.v1+json"


def build_catalog(tmp: str):
    """采集目录，返回 (store, registry, {样例 digest: 实际 digest})。"""
    registry = FakeRegistry(auth_enabled=False, default_page_size=5)
    base_url = registry.start()
    digests: dict[str, str] = {}
    children = []
    for repo, image_digest, layers, platform in REGISTRY_IMAGES:
        registry.put_manifest(
            repo, make_image_manifest(
                "sha256:" + "c0" * 32, layers), IMAGE_MEDIA, tag="current")
        actual = next(iter(registry.repos[repo].manifests.keys()))
        digests[image_digest] = actual
        children.append((actual, IMAGE_MEDIA, platform))
    index_digest = registry.put_manifest(
        "vendor/shop", make_index_manifest(children), INDEX_MEDIA,
        tag="latest")

    store = CatalogStore(os.path.join(tmp, "catalog.db"))
    collector = Collector(RegistryClient(base_url), store,
                          registry_name=base_url, page_size=5)
    report = collector.run()
    assert report.status == "completed", report.to_dict()
    return store, registry, digests, index_digest


def write_json(path: str, payload) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=2)


def run_cli(args: list[str]) -> subprocess.CompletedProcess:
    """以真实命令行子进程运行 vuln_cli（继承当前解释器/虚拟环境）。"""
    return subprocess.run(
        [sys.executable, "-m", "oci_catalog.vuln.vuln_cli"] + args,
        cwd=HERE, capture_output=True, text=True)


def main() -> None:
    tmp = tempfile.mkdtemp(prefix="vuln-demo-")
    print(f"== 工作目录: {tmp} ==")
    store, registry, digests, index_digest = build_catalog(tmp)
    catalog_db = os.path.join(tmp, "catalog.db")
    sbom_db = os.path.join(tmp, "sbom.db")
    amd64 = digests[IMAGE_AMD64_DIGEST]
    arm64 = digests[IMAGE_ARM64_DIGEST]
    quiet = digests[IMAGE_QUIET_DIGEST]

    print("\n== 步骤 1：导入三份 SBOM（既有子系统，目录库只读） ==")
    sbom_files = {
        "shop.cdx.json": (shop_cdx(), amd64),
        "attribution.spdx.json": (shop_spdx(), amd64),
        "edge.cdx.json": (edge_cdx(), arm64),
    }
    bind_args = []
    for name, (doc, digest) in sbom_files.items():
        path = os.path.join(tmp, name)
        write_json(path, doc)
        bind_args += ["--bind", f"{path}={digest}"]
    rc = sbom_cli_main(["--catalog", catalog_db, "--sbom", sbom_db,
                        "import"] + bind_args)
    assert rc == 0, "SBOM 导入应全部成功"
    # 目录库基线：SBOM 导入不产生 tag 事件
    events = store.conn.execute(
        "SELECT COUNT(*) AS c FROM tag_events").fetchone()["c"]
    print(f"目录库 tag_events={events}（SBOM 导入未新增事件）")
    registry.stop()
    store.close()

    print("\n== 步骤 2：生成人工公告目录 ==")
    adv_dir = os.path.join(tmp, "advisories")
    os.makedirs(adv_dir)
    for name, doc in advisories().items():
        write_json(os.path.join(adv_dir, name), doc)
    print(f"公告 {len(os.listdir(adv_dir))} 份，目录 {adv_dir}")

    print("\n== 步骤 3：命令行子进程生成两个平台镜像的判定报告 ==")
    reports = {}
    for label, digest in (("amd64", amd64), ("arm64", arm64)):
        output = os.path.join(tmp, f"report-{label}.json")
        proc = run_cli(["--catalog", catalog_db, "--sbom", sbom_db,
                        "--advisories", adv_dir,
                        "report", "--digest", digest, "--output", output])
        print(f"  report[{label}] 退出码={proc.returncode} -> {output}")
        if proc.returncode != 0:
            print(proc.stderr, file=sys.stderr)
            raise SystemExit(proc.returncode)
        reports[label] = output
        with open(output, encoding="utf-8") as fh:
            summary = json.load(fh)["summary"]
        print(f"  {label} 汇总: {json.dumps(summary, ensure_ascii=False)}")

    print("\n== 步骤 4：另一批子进程按公告编号（含别名）查询命中 ==")
    queries = {}
    for label, query_id, digest in (
            ("alias-cycle", "VULN-CCCC", amd64),      # 别名传递环成员
            ("alias-nofile", "GHSA-GHOST-0000", amd64),  # 无独立文件的别名
            ("withdrawn", "CVE-GHOST-0001", arm64),   # 已撤回公告的别名
            ("related-only", "VULN-DDDD", amd64),     # 仅 related，独立组
            ("all-locations", "PYSEC-FAKE-0001", amd64)):  # 同坐标两份清单
        proc = run_cli(["--catalog", catalog_db, "--sbom", sbom_db,
                        "--advisories", adv_dir,
                        "advisory", "--digest", digest, "--id", query_id])
        out_path = os.path.join(tmp, f"query-{label}.json")
        with open(out_path, "w", encoding="utf-8") as fh:
            fh.write(proc.stdout)
        print(f"  query[{label}] id={query_id} 退出码={proc.returncode}")
        if proc.returncode != 0:
            print(proc.stderr, file=sys.stderr)
            raise SystemExit(proc.returncode)
        queries[label] = out_path

    print("\n== 步骤 5：无 SBOM 镜像单独说明（退出码 3，不是零漏洞） ==")
    proc = run_cli(["--catalog", catalog_db, "--sbom", sbom_db,
                    "--advisories", adv_dir, "report", "--digest", quiet])
    print(f"  quiet 镜像退出码={proc.returncode}")
    print(f"  stderr: {proc.stderr.strip()}")
    quiet_result = {"exit_code": proc.returncode, "stderr": proc.stderr}
    if proc.returncode != 3:
        raise SystemExit("无 SBOM 镜像必须以退出码 3 单独说明")

    print("\n== 步骤 6：坏公告目录整次作业失败（退出码 2，定位文件与字段） ==")
    bad_cases = {
        "regress": ("bad-regress.json", bad_regress()),
        "overlap": ("bad-overlap.json", bad_overlap()),
        "duplicate-id": ("bad-duplicate-id.json", bad_duplicate_id()),
        "duplicate-json-key": ("bad-dup-key.json", BAD_DUP_KEY_TEXT),
    }
    bad_results = {}
    for label, (name, payload) in bad_cases.items():
        bad_dir = os.path.join(tmp, f"advisories-{label}")
        shutil.copytree(adv_dir, bad_dir)
        target = os.path.join(bad_dir, name)
        if isinstance(payload, str):
            with open(target, "w", encoding="utf-8") as fh:
                fh.write(payload)
        else:
            write_json(target, payload)
        proc = run_cli(["--catalog", catalog_db, "--sbom", sbom_db,
                        "--advisories", bad_dir,
                        "report", "--digest", amd64])
        first_diag = ""
        try:
            first_diag = json.loads(proc.stderr)["diagnostics"][0]
            first_diag = (f"{first_diag['code']} @ {first_diag['location']}")
        except (json.JSONDecodeError, KeyError, IndexError):
            pass
        print(f"  {label}: 退出码={proc.returncode} 首个诊断 {first_diag}")
        if proc.returncode != 2:
            raise SystemExit(f"坏公告目录 {label} 应以退出码 2 失败")
        bad_results[label] = {"exit_code": proc.returncode,
                              "stderr": proc.stderr}

    print("\n== 步骤 7：新进程按手写期待表验收 ==")
    plan = {
        "catalog_db": catalog_db, "sbom_db": sbom_db,
        "amd64": amd64, "arm64": arm64, "quiet": quiet,
        "reports": reports, "queries": queries,
        "quiet_result": quiet_result, "bad_results": bad_results,
    }
    plan_path = os.path.join(tmp, "verify-plan.json")
    write_json(plan_path, plan)
    verifier = os.path.join(HERE, "verify_vuln_demo.py")
    proc = subprocess.run([sys.executable, "-I", verifier,
                           "--plan", plan_path],
                          capture_output=True, text=True)
    print(proc.stdout)
    if proc.returncode != 0:
        print(proc.stderr, file=sys.stderr)
        raise SystemExit(proc.returncode)
    print(f"全部验收通过；数据库与报告位于 {tmp}")


if __name__ == "__main__":
    main()
