"""文件视图测试共享 fixture：内存目录库 + 本地层归档文件。

不经过 HTTP/registry：直接向 CatalogStore 登记 manifest 内容身份与层序
（collector 的端到端集成由演示脚本覆盖），层归档写成临时文件。
"""

import json
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from oci_catalog import CatalogStore
from oci_catalog.digest import sha256_digest
from oci_catalog.models import Descriptor, ManifestInfo, ManifestKind
from oci_catalog.fileview import FileViewStore
from oci_catalog.fileview.sample_layers import (  # noqa: F401  （便于测试复用）
    MEDIA_TAR,
    MEDIA_TAR_GZ,
    d,
    f,
    hard,
    opq,
    sym,
    tar_bytes,
    wh,
)

IMAGE_MEDIA = "application/vnd.oci.image.manifest.v1+json"
INDEX_MEDIA = "application/vnd.oci.image.index.v1+json"


class FileViewFixture(unittest.TestCase):
    """空目录库 + 空视图库；按需在目录库登记 image/index manifest。"""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="fileview-test-")
        self.catalog_db = os.path.join(self.tmpdir, "catalog.db")
        self.views_db = os.path.join(self.tmpdir, "views.db")
        self.catalog = CatalogStore(self.catalog_db)
        self.store = FileViewStore(self.views_db, self.catalog_db)

    def tearDown(self):
        self.store.close()
        self.catalog.close()
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    # -- 目录库登记 ---------------------------------------------------------
    def add_image(self, layers: list[tuple[bytes, str]],
                  config_digest: str = "sha256:" + "cf" * 32) -> str:
        """登记单平台 image manifest，返回其 digest。

        ``layers`` 为 [(归档字节, media_type), ...]，层序即 manifest 层序。
        """
        descriptors = tuple(
            Descriptor(digest=sha256_digest(data), media_type=media,
                       size=len(data))
            for data, media in layers)
        canonical = json.dumps(
            [[d.digest, d.media_type] for d in descriptors] + [config_digest],
            separators=(",", ":")).encode("utf-8")
        digest = sha256_digest(b"manifest:" + canonical)
        info = ManifestInfo(digest=digest, media_type=IMAGE_MEDIA,
                            kind=ManifestKind.IMAGE, layers=descriptors)
        self.catalog.upsert_manifest(info)
        # upsert 不自动提交；提交后视图库的只读目录连接才能看到
        self.catalog.conn.commit()
        return digest

    def add_index(self, child_digest: str) -> str:
        """登记一个 index manifest（用于绑定拒绝用例），返回 digest。"""
        digest = sha256_digest(b"index:" + child_digest.encode("utf-8"))
        info = ManifestInfo(
            digest=digest, media_type=INDEX_MEDIA, kind=ManifestKind.INDEX,
            manifests=(Descriptor(digest=child_digest,
                                  media_type=IMAGE_MEDIA, size=1),))
        self.catalog.upsert_manifest(info)
        self.catalog.conn.commit()
        return digest

    # -- 层归档文件 ---------------------------------------------------------
    def write_layer(self, name: str, data: bytes) -> str:
        path = os.path.join(self.tmpdir, name)
        with open(path, "wb") as fh:
            fh.write(data)
        return path

    def layer_mapping(self, layers: list[tuple[bytes, str]],
                      prefix: str = "layer") -> dict[str, str]:
        """把层字节写成文件并返回 digest -> 路径 映射。"""
        mapping: dict[str, str] = {}
        for i, (data, _media) in enumerate(layers):
            mapping[sha256_digest(data)] = self.write_layer(
                f"{prefix}-{i}.tar", data)
        return mapping

    def add_image_with_files(self, layers: list[tuple[bytes, str]],
                             prefix: str = "layer"):
        """登记镜像并把层写成文件，返回 (image_digest, mapping)。"""
        image_digest = self.add_image(layers)
        return image_digest, self.layer_mapping(layers, prefix)
