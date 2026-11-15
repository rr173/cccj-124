"""可完全本地重建的发布演示数据：真实字节的 OCI Image Layout。

内容全部由代码产生，覆盖发布验收需要的全部结构：

* **根 A**：两层嵌套 index（outer → inner → linux/amd64 与
  linux/arm64 两个 image manifest）；
* 两个平台共享 base 层，amd64 独有层含 ``0x00-0xff`` 全字节
  （非 UTF-8，用于逐字节核对）；
* **零字节对象**：amd64 镜像引用的 empty 层（size 0）；
* **旧根 OLD**：一个旧的单平台 image manifest，用于在远端预置
  旧交付标签（验证最终发布前旧指向不被改动）。

验收脚本 ``verify_pusher_demo.py`` 直接引用本模块的字节常量自算
摘要，不调用被测发布器计算答案。
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass

OCI_IMAGE_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
OCI_IMAGE_INDEX = "application/vnd.oci.image.index.v1+json"
MEDIA_LAYER = "application/vnd.oci.image.layer.v1.tar+gzip"
MEDIA_CONFIG = "application/vnd.oci.image.config.v1+json"

# ---------------------------------------------------------------------------
# 原始字节常量（验收脚本直接引用）
# ---------------------------------------------------------------------------
# 共享 base 层：amd64/arm64 两个平台都引用（远端预置一份，验证复用）
BASE_LAYER = b"SHARED-BASE-LAYER\n" + b"s" * 100 + b"\x00\xff"
# amd64 独有层：0x00-0xff 全字节（非 UTF-8）
AMD64_LAYER = b"AMD64-UNIQUE-LAYER\n" + bytes(range(256))
# arm64 独有层
ARM64_LAYER = b"ARM64-UNIQUE-LAYER\n" + b"a" * 250
# 零字节对象（empty 层）
EMPTY_LAYER = b""

AMD64_CONFIG = (b'{"architecture":"amd64","os":"linux",'
                b'"rootfs":{"type":"layers","diff_ids":[]}}')
ARM64_CONFIG = (b'{"architecture":"arm64","os":"linux",'
                b'"rootfs":{"type":"layers","diff_ids":[]}}')
OLD_CONFIG = (b'{"architecture":"amd64","os":"linux","variant":"old",'
              b'"rootfs":{"type":"layers","diff_ids":[]}}')
OLD_LAYER = b"OLD-DELIVERY-LAYER\n" + b"o" * 64


def sha256_digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _descriptor(media_type: str, data: bytes,
                platform: dict | None = None) -> dict:
    desc = {"mediaType": media_type, "digest": sha256_digest(data),
            "size": len(data)}
    if platform:
        desc["platform"] = platform
    return desc


def _canonical(document: dict) -> bytes:
    return json.dumps(document, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


# ---------------------------------------------------------------------------
# 各清单文档（字节在 build_layout 时确定；验收脚本可用 fixture_bytes() 取）
# ---------------------------------------------------------------------------
def amd64_manifest_doc() -> dict:
    return {
        "schemaVersion": 2,
        "mediaType": OCI_IMAGE_MANIFEST,
        "config": _descriptor(MEDIA_CONFIG, AMD64_CONFIG),
        "layers": [
            _descriptor(MEDIA_LAYER, BASE_LAYER),
            _descriptor(MEDIA_LAYER, AMD64_LAYER),
            _descriptor(MEDIA_LAYER, EMPTY_LAYER),
        ],
    }


def arm64_manifest_doc() -> dict:
    return {
        "schemaVersion": 2,
        "mediaType": OCI_IMAGE_MANIFEST,
        "config": _descriptor(MEDIA_CONFIG, ARM64_CONFIG),
        "layers": [
            _descriptor(MEDIA_LAYER, BASE_LAYER),
            _descriptor(MEDIA_LAYER, ARM64_LAYER),
        ],
    }


def inner_index_doc() -> dict:
    return {
        "schemaVersion": 2,
        "mediaType": OCI_IMAGE_INDEX,
        "manifests": [
            _descriptor(OCI_IMAGE_MANIFEST, _canonical(amd64_manifest_doc()),
                        {"architecture": "amd64", "os": "linux"}),
            _descriptor(OCI_IMAGE_MANIFEST, _canonical(arm64_manifest_doc()),
                        {"architecture": "arm64", "os": "linux"}),
        ],
    }


def outer_index_doc() -> dict:
    return {
        "schemaVersion": 2,
        "mediaType": OCI_IMAGE_INDEX,
        "manifests": [
            _descriptor(OCI_IMAGE_INDEX, _canonical(inner_index_doc())),
        ],
    }


def old_manifest_doc() -> dict:
    return {
        "schemaVersion": 2,
        "mediaType": OCI_IMAGE_MANIFEST,
        "config": _descriptor(MEDIA_CONFIG, OLD_CONFIG),
        "layers": [_descriptor(MEDIA_LAYER, OLD_LAYER)],
    }


def fixture_bytes() -> dict:
    """全部演示对象的字节表：逻辑名 -> (字节, media_type)。"""
    amd64_raw = _canonical(amd64_manifest_doc())
    arm64_raw = _canonical(arm64_manifest_doc())
    inner_raw = _canonical(inner_index_doc())
    outer_raw = _canonical(outer_index_doc())
    old_raw = _canonical(old_manifest_doc())
    return {
        "base-layer": (BASE_LAYER, MEDIA_LAYER),
        "amd64-layer": (AMD64_LAYER, MEDIA_LAYER),
        "arm64-layer": (ARM64_LAYER, MEDIA_LAYER),
        "empty-layer": (EMPTY_LAYER, MEDIA_LAYER),
        "amd64-config": (AMD64_CONFIG, MEDIA_CONFIG),
        "arm64-config": (ARM64_CONFIG, MEDIA_CONFIG),
        "amd64-manifest": (amd64_raw, OCI_IMAGE_MANIFEST),
        "arm64-manifest": (arm64_raw, OCI_IMAGE_MANIFEST),
        "inner-index": (inner_raw, OCI_IMAGE_INDEX),
        "outer-index": (outer_raw, OCI_IMAGE_INDEX),
        "old-config": (OLD_CONFIG, MEDIA_CONFIG),
        "old-layer": (OLD_LAYER, MEDIA_LAYER),
        "old-manifest": (old_raw, OCI_IMAGE_MANIFEST),
    }


def fixture_digests() -> dict:
    """逻辑名 -> digest（由字节常量自算，不经被测发布器）。"""
    return {name: sha256_digest(data)
            for name, (data, _mt) in fixture_bytes().items()}


@dataclass(frozen=True)
class LayoutInfo:
    layout_dir: str
    root_a: str            # 嵌套索引根（outer index）的 digest
    old_root: str          # 旧根 manifest 的 digest
    digests: dict          # 逻辑名 -> digest


def build_layout(layout_dir: str) -> LayoutInfo:
    """在 ``layout_dir`` 生成完整 OCI Image Layout（根 A + 旧根 OLD）。"""
    os.makedirs(layout_dir, exist_ok=True)
    blobs_dir = os.path.join(layout_dir, "blobs", "sha256")
    os.makedirs(blobs_dir, exist_ok=True)
    table = fixture_bytes()
    digests = fixture_digests()
    for name, (data, _mt) in table.items():
        digest = digests[name]
        with open(os.path.join(blobs_dir, digest.split(":", 1)[1]),
                  "wb") as fh:
            fh.write(data)
    index_json = {
        "schemaVersion": 2,
        "mediaType": OCI_IMAGE_INDEX,
        "manifests": [
            {"mediaType": OCI_IMAGE_INDEX,
             "digest": digests["outer-index"],
             "size": len(table["outer-index"][0])},
            {"mediaType": OCI_IMAGE_MANIFEST,
             "digest": digests["old-manifest"],
             "size": len(table["old-manifest"][0])},
            {"mediaType": OCI_IMAGE_MANIFEST,
             "digest": digests["amd64-manifest"],
             "size": len(table["amd64-manifest"][0])},
        ],
    }
    with open(os.path.join(layout_dir, "index.json"), "wb") as fh:
        fh.write(json.dumps(index_json, sort_keys=True,
                            separators=(",", ":")).encode("utf-8"))
    with open(os.path.join(layout_dir, "oci-layout"), "wb") as fh:
        fh.write(b'{"imageLayoutVersion":"1.0.0"}')
    return LayoutInfo(layout_dir=os.path.abspath(layout_dir),
                      root_a=digests["outer-index"],
                      old_root=digests["old-manifest"],
                      digests=digests)
