#!/usr/bin/env python3
"""离线 SBOM 接入与依赖血缘查询端到端演示（含独立进程验收）。

流程：

1. 用内置假 registry 采集一个多平台目录（保留现有目录采集能力）；
2. 把相互关联的 CycloneDX/SPDX 供应商清单绑定到**已收录的单平台
   image manifest digest**，写入独立 SBOM SQLite 库（目录库只读）；
3. 导入坏坐标/悬空引用/重复 bom-ref/非法绑定，验证逐文件拒绝且无残留；
4. 在**新进程**中打开 SBOM 库，按本文件内显式列出的期待组件集合、
   出现次数、直接依赖、菱形/环路径与跨镜像反查逐项核对。

运行：python3 -I run_sbom_demo.py（纯标准库，不访问网络）
"""

import json
import os
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
from oci_catalog.sbom.sample_data import (
    CONFIG_DIGEST,
    IMAGE_AMD64_DIGEST,
    IMAGE_ARM64_DIGEST,
    REGISTRY_IMAGES,
    bad_dangling_ref,
    bad_duplicate_bomref,
    bad_invalid_purl,
    cyclonedx_edge,
    cyclonedx_shop,
    spdx_shop,
)
from oci_catalog.sbom.sbom_cli import main as cli_main

IMAGE_MEDIA = "application/vnd.oci.image.manifest.v1+json"
INDEX_MEDIA = "application/vnd.oci.image.index.v1+json"


def build_catalog(tmp: str) -> tuple[CatalogStore, FakeRegistry, str, dict]:
    """采集目录，返回 store、registry 与平台 image digest 映射。"""
    registry = FakeRegistry(auth_enabled=False, default_page_size=5)
    base_url = registry.start()
    image_digests: dict[str, str] = {}
    children = []
    for repo, image_digest, layers, platform in REGISTRY_IMAGES:
        registry.put_manifest(
            repo, make_image_manifest(CONFIG_DIGEST, layers),
            IMAGE_MEDIA, tag="current")
        actual_digest = next(iter(registry.repos[repo].manifests.keys()))
        image_digests[image_digest] = actual_digest
        children.append((actual_digest, IMAGE_MEDIA, platform))
    # 两个仓库各自挂一个多平台索引，保证两个平台 image 都被采集收录
    index_digest = registry.put_manifest(
        "vendor/shop", make_index_manifest(children), INDEX_MEDIA, tag="latest")
    registry.put_manifest(
        "vendor/edge", make_index_manifest(children), INDEX_MEDIA, tag="latest")

    catalog_db = os.path.join(tmp, "catalog.db")
    store = CatalogStore(catalog_db)
    collector = Collector(RegistryClient(base_url), store,
                          registry_name=base_url, page_size=5)
    report = collector.run()
    assert report.status == "completed", report.to_dict()
    return store, registry, index_digest, image_digests


def write_samples(tmp: str) -> dict[str, str]:
    files = {
        "shop.cdx.json": cyclonedx_shop(),
        "shop.spdx.json": spdx_shop(),
        "edge.cdx.json": cyclonedx_edge(),
        "bad-purl.cdx.json": bad_invalid_purl(),
        "bad-dangling.cdx.json": bad_dangling_ref(),
        "bad-duplicate.cdx.json": bad_duplicate_bomref(),
    }
    paths: dict[str, str] = {}
    for name, payload in files.items():
        path = os.path.join(tmp, name)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False, indent=2)
        paths[name] = path
    return paths


def run_import(sbom_db: str, catalog_db: str, paths: dict[str, str],
               digests: dict[str, str], index_digest: str) -> dict:
    amd64 = digests[IMAGE_AMD64_DIGEST]
    arm64 = digests[IMAGE_ARM64_DIGEST]
    argv = [
        "--catalog", catalog_db, "--sbom", sbom_db, "import",
        "--bind", f"{paths['shop.cdx.json']}={amd64}",
        "--bind", f"{paths['shop.spdx.json']}={amd64}",
        "--bind", f"{paths['edge.cdx.json']}={arm64}",
        # 坏输入：三种解析错误 + 两种非法绑定
        "--bind", f"{paths['bad-purl.cdx.json']}={amd64}",
        "--bind", f"{paths['bad-dangling.cdx.json']}={amd64}",
        "--bind", f"{paths['bad-duplicate.cdx.json']}={amd64}",
        "--bind", f"{paths['shop.cdx.json']}={index_digest}",   # index 不可绑定
        "--bind", f"{paths['shop.cdx.json']}=sha256:" + "9f" * 32,  # 未收录摘要
    ]
    rc = cli_main(argv)
    assert rc == 2, f"存在失败文件时导入退出码应为 2，实际 {rc}"
    # 重新打开库读取结构化结果（cli 已关闭连接）
    from oci_catalog.sbom import SBOMStore
    store = SBOMStore(sbom_db, catalog_db)
    try:
        failures = [dict(r) for r in store.list_failures()]
        files = [dict(r) for r in store.conn.execute(
            "SELECT source_path, image_digest, doc_format FROM sbom_files")]
    finally:
        store.close()
    return {"exit_code": rc, "failures": failures, "imported_files": files}


def main() -> None:
    tmp = tempfile.mkdtemp(prefix="sbom-demo-")
    print(f"== 工作目录: {tmp} ==")
    store, registry, index_digest, digests = build_catalog(tmp)
    catalog_db_path = os.path.join(tmp, "catalog.db")
    sbom_db = os.path.join(tmp, "sbom.db")
    paths = write_samples(tmp)

    # SBOM 导入前记录目录库基线，导入后核对完全不变（无 tag 事件污染）
    baseline_events = store.conn.execute(
        "SELECT COUNT(*) AS c FROM tag_events").fetchone()["c"]
    baseline_manifests = store.conn.execute(
        "SELECT COUNT(*) AS c FROM manifests").fetchone()["c"]

    print("\n== 步骤 1：批量导入（含坏输入与非法绑定） ==")
    import_outcome = run_import(sbom_db, catalog_db_path, paths,
                                digests, index_digest)
    print(json.dumps({
        "exit_code": import_outcome["exit_code"],
        "imported_files": [
            {"source_path": os.path.basename(r["source_path"]),
             "image_digest": r["image_digest"][:19] + "...",
             "doc_format": r["doc_format"]}
            for r in import_outcome["imported_files"]],
        "failure_count": len(import_outcome["failures"]),
        "failure_codes": [
            d["code"] for r in import_outcome["failures"]
            for d in json.loads(r["diagnostics_json"])],
    }, indent=2, ensure_ascii=False))

    # 幂等演示：再次整批导入，同路径文件应 replaced、同内容同绑定应 skipped
    print("\n== 步骤 2：重复导入幂等性 ==")
    amd64 = digests[IMAGE_AMD64_DIGEST]
    arm64 = digests[IMAGE_ARM64_DIGEST]
    second = SBOMStore_cli_import(sbom_db, catalog_db_path, [
        (paths["shop.cdx.json"], amd64),
        (paths["shop.spdx.json"], amd64),
        (paths["edge.cdx.json"], arm64),
    ])
    print(json.dumps([{"file": os.path.basename(r["source_path"]),
                       "status": r["status"]} for r in second],
                     indent=2, ensure_ascii=False))

    # 同内容换路径 + 同绑定：必须 duplicate_skipped（内容 sha256+绑定相同）
    import shutil
    copied = os.path.join(tmp, "shop-copy.cdx.json")
    shutil.copyfile(paths["shop.cdx.json"], copied)
    third = SBOMStore_cli_import(sbom_db, catalog_db_path, [(copied, amd64)])
    print(json.dumps([{"file": os.path.basename(r["source_path"]),
                       "status": r["status"]} for r in third],
                     indent=2, ensure_ascii=False))
    assert [r["status"] for r in third] == ["duplicate_skipped"]

    # 目录库未被 SBOM 写入：tag 事件数与 manifest 数与导入前基线完全一致
    after_events = store.conn.execute(
        "SELECT COUNT(*) AS c FROM tag_events").fetchone()["c"]
    after_manifests = store.conn.execute(
        "SELECT COUNT(*) AS c FROM manifests").fetchone()["c"]
    assert after_events == baseline_events, "SBOM 导入新增了 tag 事件"
    assert after_manifests == baseline_manifests, "SBOM 导入改动了 manifest 身份"
    print(f"\n== 目录库无污染：tag_events={after_events}（导入前后一致），"
          f"manifests={after_manifests}（导入前后一致） ==")
    registry.stop()
    store.close()

    # ---- 独立进程验收 ----
    plan = {
        "sbom_db": sbom_db,
        "catalog_db": catalog_db_path,
        "amd64": amd64,
        "arm64": arm64,
        "index_digest": index_digest,
        "paths": paths,
    }
    plan_path = os.path.join(tmp, "verify-plan.json")
    with open(plan_path, "w", encoding="utf-8") as fh:
        json.dump(plan, fh)
    verifier = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "verify_sbom_demo.py")
    print("\n== 步骤 3：新进程验收 ==")
    proc = subprocess.run(
        [sys.executable, "-I", verifier, "--plan", plan_path],
        capture_output=True, text=True)
    print(proc.stdout)
    if proc.returncode != 0:
        print(proc.stderr, file=sys.stderr)
        raise SystemExit(proc.returncode)
    print(f"全部验收通过；数据库位于 {tmp}")


def SBOMStore_cli_import(sbom_db: str, catalog_db: str,
                         items: list[tuple[str, str]]) -> list:
    from oci_catalog.sbom import SBOMStore
    store = SBOMStore(sbom_db, catalog_db)
    try:
        results = store.import_paths(items)
    finally:
        store.close()
    return [r.to_dict() for r in results]


if __name__ == "__main__":
    main()
