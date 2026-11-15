#!/usr/bin/env python3
"""离线构建证明接入端到端演示（含独立进程验收）。

流程：

1. 用内置假 registry 采集一个含两个平台 image 的目录（复用真实目录接口）；
2. 由固定种子重建三对测试密钥（私钥仅本地夹具使用），生成供应商 DSSE
   信封（夹具用自己的 PAE 构造 + cryptography 直接签名）与三份信任策略；
3. 命令行导入信封并绑定到**已收录的单平台 image manifest digest**；
4. 命令行按策略 P1 核验：amd64 两把授权密钥达到门槛可信，arm64 只有
   一票不可信；查询镜像来源、反查共享材料（同 URI 的另一摘要不串结果）；
5. 核对目录库零污染，然后把供应商原始文件移走；
6. 在**新进程**中打开证据库：换策略 P2（撤掉 key-a 授权）旧证据不再
   通过，再换 P3（另一组足够的授权）恢复可信；全部期待值在验收脚本中
   独立列出。

运行：.venv/bin/python -I run_provenance_demo.py
（需要 cryptography；全程本地，不连接透明日志、证书服务或 registry）
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
from oci_catalog.provenance import sample_data
from oci_catalog.provenance.provenance_cli import main as cli_main

IMAGE_MEDIA = "application/vnd.oci.image.manifest.v1+json"
INDEX_MEDIA = "application/vnd.oci.image.index.v1+json"

CONFIG_DIGEST = "sha256:" + "c0" * 32
LAYER_AMD64 = "sha256:" + "d1" * 32
LAYER_ARM64 = "sha256:" + "d2" * 32


def build_catalog(tmp: str) -> tuple[CatalogStore, FakeRegistry, dict]:
    """采集目录，返回 store、registry 与平台 image digest。"""
    registry = FakeRegistry(auth_enabled=False, default_page_size=5)
    base_url = registry.start()
    registry.put_manifest(
        "vendor/offline-etl",
        make_image_manifest(CONFIG_DIGEST, [LAYER_AMD64]),
        IMAGE_MEDIA, tag="current-amd64")
    amd64 = next(iter(registry.repos["vendor/offline-etl"].manifests.keys()))
    registry.put_manifest(
        "vendor/offline-etl-arm",
        make_image_manifest(CONFIG_DIGEST, [LAYER_ARM64]),
        IMAGE_MEDIA, tag="current-arm64")
    arm64 = next(iter(registry.repos["vendor/offline-etl-arm"].manifests.keys()))
    registry.put_manifest(
        "vendor/offline-etl",
        make_index_manifest([
            (amd64, IMAGE_MEDIA, {"architecture": "amd64", "os": "linux"}),
            (arm64, IMAGE_MEDIA,
             {"architecture": "arm64", "os": "linux", "variant": "v8"}),
        ]), INDEX_MEDIA, tag="latest")

    store = CatalogStore(os.path.join(tmp, "catalog.db"))
    collector = Collector(RegistryClient(base_url), store,
                          registry_name=base_url, page_size=5)
    report = collector.run()
    assert report.status == "completed", report.to_dict()
    return store, registry, {"amd64": amd64, "arm64": arm64}


def write_vendor_files(tmp: str, digests: dict) -> dict:
    """写供应商信封（vendor/）与本地策略（policy/），返回路径表。"""
    vendor_dir = os.path.join(tmp, "vendor")
    policy_dir = os.path.join(tmp, "policy")
    os.makedirs(vendor_dir)
    os.makedirs(policy_dir)
    paths = {}
    for name, payload in (
            ("image-amd64.intoto.json", sample_data.envelope_amd64(digests["amd64"])),
            ("image-arm64.intoto.json", sample_data.envelope_arm64(digests["arm64"]))):
        path = os.path.join(vendor_dir, name)
        with open(path, "wb") as fh:
            fh.write(payload)
        paths[name] = path
    for name, policy in (("policy-p1.json", sample_data.policy_p1()),
                         ("policy-p2.json", sample_data.policy_p2()),
                         ("policy-p3.json", sample_data.policy_p3())):
        path = os.path.join(policy_dir, name)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(policy, fh, indent=2)
        paths[name] = path
    return paths


def run_cli(argv: list[str]) -> tuple[int, dict]:
    """以命令行入口运行并捕获标准输出（保留实际输出打印）。"""
    import contextlib
    import io
    stdout = io.StringIO()
    with contextlib.redirect_stdout(stdout):
        rc = cli_main(argv)
    text = stdout.getvalue()
    print(text)
    return rc, json.loads(text)


def main() -> None:
    tmp = tempfile.mkdtemp(prefix="provenance-demo-")
    print(f"== 工作目录: {tmp} ==")
    store, registry, digests = build_catalog(tmp)
    catalog_db = os.path.join(tmp, "catalog.db")
    prov_db = os.path.join(tmp, "provenance.db")
    paths = write_vendor_files(tmp, digests)
    amd64, arm64 = digests["amd64"], digests["arm64"]
    print(f"amd64 image: {amd64}")
    print(f"arm64 image: {arm64}")
    print("测试公钥指纹（三对夹具密钥，私钥仅本地使用）:")
    for name, fingerprint in sample_data.key_fingerprints().items():
        print(f"  {name}: {fingerprint}")

    baseline_events = store.conn.execute(
        "SELECT COUNT(*) AS c FROM tag_events").fetchone()["c"]
    baseline_manifests = store.conn.execute(
        "SELECT COUNT(*) AS c FROM manifests").fetchone()["c"]

    print("\n== 步骤 1：命令行导入供应商信封（绑定单平台 image digest） ==")
    rc, imported = run_cli([
        "--catalog", catalog_db, "--prov", prov_db, "import",
        "--bind", f"{paths['image-amd64.intoto.json']}={amd64}",
        "--bind", f"{paths['image-arm64.intoto.json']}={arm64}",
    ])
    assert rc == 0, imported

    print("== 步骤 2：策略 P1 首次核验（授权 key-a+key-b，门槛 2） ==")
    rc, verified = run_cli([
        "--catalog", catalog_db, "--prov", prov_db, "verify",
        "--policy", paths["policy-p1.json"]])
    assert rc == 0
    verdicts = {e["evidence_id"]: e["verdict"]
                for e in verified["evaluations"]}
    assert verdicts == {1: "trusted", 2: "untrusted"}, verdicts

    print("== 步骤 3：查询 amd64 镜像的构建证明（P1） ==")
    rc, image_report = run_cli([
        "--catalog", catalog_db, "--prov", prov_db, "image",
        "--policy", paths["policy-p1.json"], "--digest", amd64])
    assert rc == 0
    entry = image_report["evidence"][0]
    assert entry["evaluation"]["verdict"] == "trusted"
    assert entry["bound_subject_indices"] == [1]  # 镜像摘要在非首项

    print("== 步骤 4：反查共享材料（P1 下只有 amd64 可信） ==")
    rc, shared = run_cli([
        "--catalog", catalog_db, "--prov", prov_db, "material",
        "--policy", paths["policy-p1.json"],
        "--uri", sample_data.SHARED_URI, "--sha256", sample_data.SHARED_SHA256])
    assert rc == 0
    assert [m["image_digest"] for m in shared["matches"]] == [amd64]

    print("== 步骤 5：同 URI 的另一摘要（amd64 版参考字典）反查 ==")
    rc, ref_amd = run_cli([
        "--catalog", catalog_db, "--prov", prov_db, "material",
        "--policy", paths["policy-p1.json"],
        "--uri", sample_data.REF_URI, "--sha256", sample_data.REF_AMD64_SHA256])
    assert rc == 0
    assert [m["image_digest"] for m in ref_amd["matches"]] == [amd64]
    # arm64 版参考字典：arm64 在 P1 下不可信 -> 反查为空
    rc, ref_arm = run_cli([
        "--catalog", catalog_db, "--prov", prov_db, "material",
        "--policy", paths["policy-p1.json"],
        "--uri", sample_data.REF_URI, "--sha256", sample_data.REF_ARM64_SHA256])
    assert rc == 0
    assert ref_arm["matches"] == [], ref_arm

    after_events = store.conn.execute(
        "SELECT COUNT(*) AS c FROM tag_events").fetchone()["c"]
    after_manifests = store.conn.execute(
        "SELECT COUNT(*) AS c FROM manifests").fetchone()["c"]
    assert after_events == baseline_events, "证明导入新增了 tag 事件"
    assert after_manifests == baseline_manifests, "证明导入改动了 manifest"
    print(f"== 目录库无污染：tag_events={after_events}、"
          f"manifests={after_manifests}（导入前后一致） ==")
    registry.stop()
    store.close()

    # 供应商原始文件移走：后续新进程操作只依赖证据库中的原始字节
    moved = os.path.join(tmp, "vendor.moved-away")
    shutil.move(os.path.join(tmp, "vendor"), moved)
    assert not os.path.exists(paths["image-amd64.intoto.json"])
    print(f"\n== 供应商信封原始文件已移走（{os.path.basename(moved)}/），"
          f"后续操作不再提供供应商文件 ==")

    plan = {
        "prov_db": prov_db,
        "catalog_db": catalog_db,
        "amd64": amd64,
        "arm64": arm64,
        "baseline_events": baseline_events,
        "baseline_manifests": baseline_manifests,
        "policies": {name: paths[name] for name in
                     ("policy-p1.json", "policy-p2.json", "policy-p3.json")},
    }
    plan_path = os.path.join(tmp, "verify-plan.json")
    with open(plan_path, "w", encoding="utf-8") as fh:
        json.dump(plan, fh)
    verifier = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "verify_provenance_demo.py")
    print("\n== 步骤 6：新进程验收（换策略重评价 + 材料反查） ==")
    proc = subprocess.run(
        [sys.executable, "-I", verifier, "--plan", plan_path],
        capture_output=True, text=True)
    print(proc.stdout)
    if proc.returncode != 0:
        print(proc.stderr, file=sys.stderr)
        raise SystemExit(proc.returncode)
    print(f"全部验收通过；数据库位于 {tmp}")


if __name__ == "__main__":
    main()
