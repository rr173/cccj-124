#!/usr/bin/env python3
"""端到端冒烟：用假 registry 跑完整治理流程并演示三类查询。

运行：python3 -I smoke_demo.py（不依赖 pytest）
"""

import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from oci_catalog import (
    CatalogStore,
    Collector,
    FakeRegistry,
    RegistryClient,
    diff_namespace_scans,
    make_image_manifest,
    make_index_manifest,
    query_platform_references,
    query_tag_history,
)

IMAGE_MEDIA = "application/vnd.oci.image.manifest.v1+json"
INDEX_MEDIA = "application/vnd.oci.image.index.v1+json"


def main() -> None:
    registry = FakeRegistry(auth_enabled=True, default_page_size=2,
                            duplicate_injection=True)
    base_url = registry.start()
    tmp = tempfile.mkdtemp(prefix="oci-smoke-")
    store = CatalogStore(os.path.join(tmp, "catalog.db"))
    client = RegistryClient(base_url, username="user", password="pass")
    collector = Collector(client, store, registry_name=base_url, page_size=2)

    # ---- 搭建多平台内容 ----
    amd64 = registry.put_manifest(
        "team-a/app",
        make_image_manifest("sha256:" + "a1" * 32, ["sha256:" + "l1" * 32]),
        IMAGE_MEDIA)
    arm64 = registry.put_manifest(
        "team-a/app",
        make_image_manifest("sha256:" + "a2" * 32, ["sha256:" + "l2" * 32]),
        IMAGE_MEDIA)
    index = registry.put_manifest(
        "team-a/app",
        make_index_manifest([
            (amd64, IMAGE_MEDIA, {"architecture": "amd64", "os": "linux"}),
            (arm64, IMAGE_MEDIA, {"architecture": "arm64", "os": "linux"}),
        ]), INDEX_MEDIA, tag="latest")
    registry.retag("team-a/app", "v1.0", index)  # 同 digest 多 tag

    # ---- 第一次扫描 ----
    report1 = collector.run()
    scan_a = report1.scan_id
    print("== scan 1 ==", json.dumps(report1.to_dict(), ensure_ascii=False))
    assert report1.status == "completed"
    assert registry.blob_requests == [], "采集器不得下载 layer"

    # ---- 查询 1：digest -> 完整平台引用 ----
    refs = query_platform_references(store, index)
    print("\n== digest 平台引用 ==")
    print(json.dumps({
        "digest": refs["digest"],
        "kind": refs["kind"],
        "platforms": [
            {"digest": r["manifest_digest"], "platform": r["platform"],
             "config": r["config_digest"], "layers": r["layer_digests"],
             "path_len": len(r["path"])}
            for r in refs["references"]
        ],
        "referenced_by_tags": refs["referenced_by_tags"],
    }, indent=2, ensure_ascii=False))

    # ---- tag 改指向 + 删除，然后第二次扫描 ----
    new_image = registry.put_manifest(
        "team-a/app",
        make_image_manifest("sha256:" + "b1" * 32, ["sha256:" + "l9" * 32]),
        IMAGE_MEDIA, tag="v2.0")
    registry.retag("team-a/app", "latest", new_image)  # latest 移动
    registry.delete_tag("team-a/app", "v1.0")           # v1.0 删除
    report2 = Collector(client, store, registry_name=base_url,
                        page_size=2).run()
    scan_b = report2.scan_id
    print("\n== scan 2 ==", json.dumps(report2.to_dict(), ensure_ascii=False))

    # ---- 查询 2：tag 当前与历史指向 ----
    history = query_tag_history(store, base_url, "team-a/app", "latest")
    print("\n== latest 的历史指向 ==")
    print(json.dumps({
        "current_digest": history["current"]["digest"],
        "events": [(e["event_type"], e["old_digest"], e["new_digest"])
                   for e in history["history"]],
    }, indent=2, ensure_ascii=False))

    # ---- 查询 3：namespace 两次扫描对比 ----
    diff = diff_namespace_scans(store, base_url, "team-a", scan_a, scan_b)
    print("\n== namespace team-a 扫描差异 ==")
    print(json.dumps(diff, indent=2, ensure_ascii=False))

    # ---- 内容身份去重断言 ----
    identity_count = store.conn.execute(
        "SELECT COUNT(*) AS c FROM manifests WHERE digest = ?",
        (index,)).fetchone()["c"]
    assert identity_count == 1
    print("\n全部断言通过；DB 位于", os.path.join(tmp, "catalog.db"))
    registry.stop()
    store.close()


if __name__ == "__main__":
    main()
