#!/usr/bin/env python3
"""镜像层文件视图端到端演示（含独立进程验收）。

按实际交付动作组织：

1. 用内置假 registry 采集一个带两个平台（linux/amd64、linux/arm64）的
   目录，另含重打包镜像与若干“坏”镜像（目录采集能力保持不变）；
2. 为 amd64 平台提供三层本地归档（gzip+gzip+未压缩 tar），按 manifest
   层序合成最终文件树，落独立视图库；arm64 与重打包镜像同样构建；
3. 演示缺层映射、错误摘要、不合法路径、损坏归档、不支持的压缩、
   不可解析硬链接、tag/index 绑定的失败诊断，并确认没有留下
   可查询的半份视图；
4. 通过 CLI 把含非 UTF-8 字节的文件原始字节写到标准输出并核对；
5. 在**新进程**中打开视图库，按验收脚本中手写的期待值逐项核对
   /data 下仍存在的文件、来源层、类型与字节内容。

运行：python3 -I run_fileview_demo.py（纯标准库，不访问网络）
"""

import json
import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from oci_catalog import CatalogStore, Collector, FakeRegistry, RegistryClient
from oci_catalog.fileview.fileview_cli import main as cli_main
from oci_catalog.fileview.sample_layers import (
    BLOB_BIN,
    IMAGE_LAYER_KEYS,
    IMAGE_MEDIA,
    INDEX_MEDIA,
    REPO_LAYOUT,
    build_demo_layers,
    image_manifest_dict,
    index_manifest_dict,
)

HERE = os.path.dirname(os.path.abspath(__file__))


def build_catalog(tmp: str, layers: dict):
    """采集目录，返回 (store, registry, 镜像键->digest, index_digest)。"""
    registry = FakeRegistry(auth_enabled=False, default_page_size=3)
    base_url = registry.start()
    image_digests: dict[str, str] = {}
    # 先放各平台 image manifest，再用真实 digest 组索引
    for repo, tags in REPO_LAYOUT.items():
        for tag, key in tags.items():
            if key == "index":
                continue
            manifest = image_manifest_dict(
                [layers[k] for k in IMAGE_LAYER_KEYS[key]])
            stored = registry.put_manifest(repo, manifest, IMAGE_MEDIA,
                                           tag=tag)
            image_digests[key] = stored
    index_digest = None
    for repo, tags in REPO_LAYOUT.items():
        for tag, key in tags.items():
            if key != "index":
                continue
            children = [(k, image_digests[k]) for k in ("amd64", "arm64")]
            stored = registry.put_manifest(
                repo, index_manifest_dict(children), INDEX_MEDIA, tag=tag)
            index_digest = stored

    store = CatalogStore(os.path.join(tmp, "catalog.db"))
    collector = Collector(RegistryClient(base_url), store,
                          registry_name=base_url, page_size=3)
    report = collector.run()
    assert report.status == "completed", report.to_dict()
    return store, registry, image_digests, index_digest


def write_layer_files(tmp: str, layers: dict) -> dict[str, str]:
    """把演示层写到本地归档文件，返回 层键 -> 文件路径。"""
    layer_dir = os.path.join(tmp, "layers")
    os.makedirs(layer_dir)
    paths: dict[str, str] = {}
    for key, layer in layers.items():
        path = os.path.join(layer_dir, layer.filename)
        with open(path, "wb") as fh:
            fh.write(layer.data)
        paths[key] = path
    return paths


def run_cli(catalog_db: str, views_db: str, argv: list[str]) -> int:
    return cli_main(["--catalog", catalog_db, "--views", views_db] + argv)


def layer_args(keys: list[str], layers: dict, paths: dict) -> list[str]:
    return [f"{layers[key].digest}={paths[key]}" for key in keys]


def main() -> None:
    tmp = tempfile.mkdtemp(prefix="fileview-demo-")
    print(f"== 工作目录: {tmp} ==")
    layers = build_demo_layers()
    paths = write_layer_files(tmp, layers)
    store, registry, image_digests, index_digest = build_catalog(tmp, layers)
    catalog_db = os.path.join(tmp, "catalog.db")
    views_db = os.path.join(tmp, "views.db")

    # 目录库基线：构建视图后必须完全不变
    baseline_events = store.conn.execute(
        "SELECT COUNT(*) AS c FROM tag_events").fetchone()["c"]
    baseline_manifests = store.conn.execute(
        "SELECT COUNT(*) AS c FROM manifests").fetchone()["c"]

    print("\n== 步骤 1：为两个平台与重打包镜像构建文件视图 ==")
    for key in ("amd64", "arm64", "repacked"):
        argv = ["build", "--image", image_digests[key]]
        for mapping in layer_args(IMAGE_LAYER_KEYS[key], layers, paths):
            argv += ["--layer", mapping]
        rc = run_cli(catalog_db, views_db, argv)
        assert rc == 0, f"{key} 构建应成功，退出码 {rc}"
        print(f"-- {key} 视图构建成功（{len(IMAGE_LAYER_KEYS[key])} 层）")

    print("\n== 步骤 2：失败诊断（每种坏输入都必须拒绝且不留半份视图） ==")
    dig = {key: layer.digest for key, layer in layers.items()}
    failures = [
        # (说明, --image 值, --layer 映射列表, 期待诊断码)
        ("tag 不能作为构建目标", "amd64", [], "binding_not_digest"),
        ("index digest 不能构建视图", index_digest, [], "binding_not_image"),
        ("缺少层映射（只给前两层）", image_digests["amd64"],
         [f"{dig['amd64-l1']}={paths['amd64-l1']}",
          f"{dig['amd64-l2']}={paths['amd64-l2']}"],
         "missing_layer_archive"),
        ("归档字节与层摘要不符（第二层映射到第一层文件）",
         image_digests["amd64"],
         [f"{dig['amd64-l1']}={paths['amd64-l1']}",
          f"{dig['amd64-l2']}={paths['amd64-l1']}",
          f"{dig['amd64-l3']}={paths['amd64-l3']}"],
         "digest_mismatch"),
        ("成员路径含 '..' 段", image_digests["hostile"],
         [f"{dig['hostile-l1']}={paths['hostile-l1']}"],
         "unsafe_member_path"),
        ("损坏归档（字节不是 tar）", image_digests["corrupt"],
         [f"{dig['broken-corrupt-l1']}={paths['broken-corrupt-l1']}"],
         "corrupt_layer_archive"),
        ("不支持的压缩格式（zstd）", image_digests["zstd"],
         [f"{dig['broken-zstd-l1']}={paths['broken-zstd-l1']}"],
         "unsupported_layer_media"),
        ("硬链接目标不存在", image_digests["hardlink"],
         [f"{dig['broken-hardlink-l1']}={paths['broken-hardlink-l1']}"],
         "unresolvable_hardlink"),
    ]
    for label, image, layer_maps, expect_code in failures:
        argv = ["build", "--image", image]
        for mapping in layer_maps:
            argv += ["--layer", mapping]
        rc = run_cli(catalog_db, views_db, argv)
        assert rc == 2, f"{label}: 期望退出码 2，实际 {rc}"
        print(f"-- {label} -> 拒绝（诊断码 {expect_code}）")

    # 目录库未被视图构建写入
    after_events = store.conn.execute(
        "SELECT COUNT(*) AS c FROM tag_events").fetchone()["c"]
    after_manifests = store.conn.execute(
        "SELECT COUNT(*) AS c FROM manifests").fetchone()["c"]
    assert after_events == baseline_events, "视图构建新增了 tag 事件"
    assert after_manifests == baseline_manifests, "视图构建改动了 manifest 身份"
    print(f"\n== 目录库无污染：tag_events={after_events}、"
          f"manifests={after_manifests}（构建前后一致） ==")
    registry.stop()
    store.close()

    print("\n== 步骤 3：CLI 取非 UTF-8 文件原始字节（独立进程） ==")
    proc = subprocess.run(
        [sys.executable, "-I", "-c",
         "import sys; sys.path.insert(0, %r); "
         "from oci_catalog.fileview.fileview_cli import main; "
         "raise SystemExit(main())" % HERE,
         "--catalog", catalog_db, "--views", views_db,
         "cat", "--image", image_digests["amd64"],
         "--path", "/data/bin/blob.bin"],
        capture_output=True)
    assert proc.returncode == 0, proc.stderr.decode("utf-8", "replace")
    assert proc.stdout == BLOB_BIN, \
        f"stdout 字节与原始内容不符: {proc.stdout!r}"
    print(f"  ✓ /data/bin/blob.bin 原始字节 {len(BLOB_BIN)} 字节"
          f"（含非 UTF-8 字节）经 stdout 逐字节核对一致")

    # ---- 新进程验收 ----
    plan = {
        "views_db": views_db,
        "catalog_db": catalog_db,
        "images": image_digests,
        "index_digest": index_digest,
        "layers": dig,
        "expected_failure_codes": [code for _, _, _, code in failures],
    }
    plan_path = os.path.join(tmp, "verify-plan.json")
    with open(plan_path, "w", encoding="utf-8") as fh:
        json.dump(plan, fh)
    verifier = os.path.join(HERE, "verify_fileview_demo.py")
    print("\n== 步骤 4：新进程按手写期待值验收 ==")
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
