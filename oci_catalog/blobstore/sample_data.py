"""可完全本地重建的演示数据：一份真实字节的 OCI Image Layout。

生成的 layout 覆盖对象仓验收需要的全部结构（内容全部由代码产生）：

* **根 A**：两层嵌套的 image index（外层 index -> 内层 index ->
  linux/amd64 与 linux/arm64 两个 image manifest）；
* **两个平台**各自有独立 config 与独有层，并**共享**一个 base 层；
* **根 B**：另一个 image manifest，复用同一个 base 层；
* **根 C**：从未绑定名称的“垃圾闭包”，用于演示回收；
* ``index.json`` 同时登记 A/B/C 三个根。

所有 manifest 的原始 JSON 与 blob 都是真实字节，写入标准
``oci-layout`` + ``blobs/sha256/<hex>`` 目录结构。期待的可达集合与字节数
在 ``verify_blobstore_demo.py`` 中以独立手写字面量列出，本模块只负责造数，
不调用对象仓的可达性函数。
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
# 原始字节（验收脚本中另有独立手写字面量）
# ---------------------------------------------------------------------------
# base 层被 amd64/arm64 两个平台镜像与根 B 共同引用
BASE_LAYER = b"SHARED-BASE-LAYER\n" + b"s" * 100 + b"\x00\xff"
# amd64 独有层：含非 UTF-8 字节（0x00-0xff 全字节），用于逐字节核对
AMD64_L2 = b"AMD64-UNIQUE-L2\n" + bytes(range(256))
AMD64_L3 = b"AMD64-UNIQUE-L3\n" + b"3" * 300
ARM64_L2 = b"ARM64-UNIQUE-L2\n" + b"a" * 250
REPACK_L2 = b"REPACK-UNIQUE-L2\n" + b"r" * 64
GARBAGE_L2 = b"GARBAGE-UNIQUE-L2\n" + b"g" * 32
GARBAGE2_L2 = b"GARBAGE2-UNIQUE-L2\n" + b"h" * 24

AMD64_CONFIG = (b'{"architecture":"amd64","os":"linux",'
                b'"rootfs":{"type":"layers","diff_ids":[]}}')
ARM64_CONFIG = (b'{"architecture":"arm64","os":"linux",'
                b'"rootfs":{"type":"layers","diff_ids":[]}}')
REPACK_CONFIG = (b'{"architecture":"amd64","os":"linux",'
                 b'"variant":"repack","rootfs":{"type":"layers",'
                 b'"diff_ids":[]}}')
GARBAGE_CONFIG = (b'{"architecture":"amd64","os":"linux",'
                  b'"variant":"garbage","rootfs":{"type":"layers",'
                  b'"diff_ids":[]}}')
GARBAGE2_CONFIG = (b'{"architecture":"amd64","os":"linux",'
                   b'"variant":"garbage2","rootfs":{"type":"layers",'
                   b'"diff_ids":[]}}')


def sha256_digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _descriptor(media_type: str, data: bytes, platform: dict | None = None
                ) -> dict:
    desc = {"mediaType": media_type, "digest": sha256_digest(data),
            "size": len(data)}
    if platform:
        desc["platform"] = platform
    return desc


def _canonical(document: dict) -> bytes:
    return json.dumps(document, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


@dataclass(frozen=True)
class LayoutInfo:
    """一次造数的结果：layout 目录、三个根 digest 与各对象字节。"""

    layout_dir: str
    roots: dict[str, str]          # "A"/"inner"/"B"/"C" -> digest
    blobs: dict[str, bytes]        # digest -> bytes
    names: dict[str, str]          # 逻辑层名 -> digest
    manifest_docs: dict[str, dict] # digest -> 解析后的 JSON 文档

    def blob_path(self, digest: str) -> str:
        return os.path.join(self.layout_dir, "blobs", "sha256",
                            digest.split(":", 1)[1])


def build_layout(layout_dir: str) -> LayoutInfo:
    """在 ``layout_dir`` 生成完整 OCI Image Layout，返回造数信息。"""
    os.makedirs(layout_dir, exist_ok=True)
    blobs_dir = os.path.join(layout_dir, "blobs", "sha256")
    os.makedirs(blobs_dir, exist_ok=True)
    blobs: dict[str, bytes] = {}
    docs: dict[str, dict] = {}

    def put(data: bytes) -> str:
        digest = sha256_digest(data)
        if digest not in blobs:
            with open(os.path.join(blobs_dir, digest.split(":", 1)[1]),
                      "wb") as fh:
                fh.write(data)
            blobs[digest] = data
        return digest

    def put_manifest(document: dict) -> str:
        raw = _canonical(document)
        digest = put(raw)
        docs[digest] = document
        return digest

    layer_bytes = {
        "base": BASE_LAYER,
        "amd64-l2": AMD64_L2,
        "amd64-l3": AMD64_L3,
        "arm64-l2": ARM64_L2,
        "repack-l2": REPACK_L2,
        "garbage-l2": GARBAGE_L2,
        "garbage2-l2": GARBAGE2_L2,
    }
    layer_digests = {name: put(data) for name, data in layer_bytes.items()}
    config_digests = {
        "amd64": put(AMD64_CONFIG),
        "arm64": put(ARM64_CONFIG),
        "repack": put(REPACK_CONFIG),
        "garbage": put(GARBAGE_CONFIG),
        "garbage2": put(GARBAGE2_CONFIG),
    }

    amd64_manifest = {
        "schemaVersion": 2,
        "mediaType": OCI_IMAGE_MANIFEST,
        "config": _descriptor(MEDIA_CONFIG, AMD64_CONFIG),
        "layers": [
            _descriptor(MEDIA_LAYER, BASE_LAYER),
            _descriptor(MEDIA_LAYER, AMD64_L2),
            _descriptor(MEDIA_LAYER, AMD64_L3),
        ],
    }
    arm64_manifest = {
        "schemaVersion": 2,
        "mediaType": OCI_IMAGE_MANIFEST,
        "config": _descriptor(MEDIA_CONFIG, ARM64_CONFIG),
        "layers": [
            _descriptor(MEDIA_LAYER, BASE_LAYER),
            _descriptor(MEDIA_LAYER, ARM64_L2),
        ],
    }
    repack_manifest = {
        "schemaVersion": 2,
        "mediaType": OCI_IMAGE_MANIFEST,
        "config": _descriptor(MEDIA_CONFIG, REPACK_CONFIG),
        "layers": [
            _descriptor(MEDIA_LAYER, BASE_LAYER),
            _descriptor(MEDIA_LAYER, REPACK_L2),
        ],
    }
    garbage_manifest = {
        "schemaVersion": 2,
        "mediaType": OCI_IMAGE_MANIFEST,
        "config": _descriptor(MEDIA_CONFIG, GARBAGE_CONFIG),
        "layers": [_descriptor(MEDIA_LAYER, GARBAGE_L2)],
    }
    garbage2_manifest = {
        "schemaVersion": 2,
        "mediaType": OCI_IMAGE_MANIFEST,
        "config": _descriptor(MEDIA_CONFIG, GARBAGE2_CONFIG),
        "layers": [_descriptor(MEDIA_LAYER, GARBAGE2_L2)],
    }
    amd64_digest = put_manifest(amd64_manifest)
    arm64_digest = put_manifest(arm64_manifest)
    repack_digest = put_manifest(repack_manifest)
    garbage_digest = put_manifest(garbage_manifest)
    garbage2_digest = put_manifest(garbage2_manifest)

    inner_index = {
        "schemaVersion": 2,
        "mediaType": OCI_IMAGE_INDEX,
        "manifests": [
            _descriptor(OCI_IMAGE_MANIFEST, _canonical(amd64_manifest),
                        {"architecture": "amd64", "os": "linux"}),
            _descriptor(OCI_IMAGE_MANIFEST, _canonical(arm64_manifest),
                        {"architecture": "arm64", "os": "linux"}),
        ],
    }
    inner_digest = put_manifest(inner_index)
    outer_index = {
        "schemaVersion": 2,
        "mediaType": OCI_IMAGE_INDEX,
        "manifests": [
            _descriptor(OCI_IMAGE_INDEX, _canonical(inner_index)),
        ],
    }
    outer_digest = put_manifest(outer_index)

    index_json = {
        "schemaVersion": 2,
        "mediaType": OCI_IMAGE_INDEX,
        "manifests": [
            _descriptor(OCI_IMAGE_INDEX, _canonical(outer_index)),
            _descriptor(OCI_IMAGE_MANIFEST, _canonical(repack_manifest)),
            _descriptor(OCI_IMAGE_MANIFEST, _canonical(garbage_manifest)),
            _descriptor(OCI_IMAGE_MANIFEST, _canonical(garbage2_manifest)),
        ],
    }
    with open(os.path.join(layout_dir, "index.json"), "wb") as fh:
        fh.write(json.dumps(index_json, sort_keys=True,
                            separators=(",", ":")).encode("utf-8"))
    with open(os.path.join(layout_dir, "oci-layout"), "wb") as fh:
        fh.write(b'{"imageLayoutVersion":"1.0.0"}')

    names = {
        "base": layer_digests["base"],
        "amd64-l2": layer_digests["amd64-l2"],
        "amd64-l3": layer_digests["amd64-l3"],
        "arm64-l2": layer_digests["arm64-l2"],
        "repack-l2": layer_digests["repack-l2"],
        "garbage-l2": layer_digests["garbage-l2"],
        "garbage2-l2": layer_digests["garbage2-l2"],
        "config-amd64": config_digests["amd64"],
        "config-arm64": config_digests["arm64"],
        "config-repack": config_digests["repack"],
        "config-garbage": config_digests["garbage"],
        "config-garbage2": config_digests["garbage2"],
        "manifest-amd64": amd64_digest,
        "manifest-arm64": arm64_digest,
        "manifest-repack": repack_digest,
        "manifest-garbage": garbage_digest,
        "manifest-garbage2": garbage2_digest,
        "index-inner": inner_digest,
        "index-outer": outer_digest,
    }
    return LayoutInfo(layout_dir=os.path.abspath(layout_dir),
                      roots={"A": outer_digest, "inner": inner_digest,
                             "B": repack_digest, "C": garbage_digest,
                             "D": garbage2_digest},
                      blobs=blobs, names=names, manifest_docs=docs)
