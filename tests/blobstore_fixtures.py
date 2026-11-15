"""对象仓测试共享 fixture：临时 layout + 临时仓目录。

不经过网络：直接用 :mod:`oci_catalog.blobstore.sample_data` 生成真实
OCI Image Layout（嵌套索引、两个平台、共享层、独有层），仓目录也在
临时目录中。测试不读取、不改写任何既有目录库/SBOM/视图库。
"""

import json
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from oci_catalog.blobstore import BlobStore
from oci_catalog.blobstore.sample_data import build_layout


class BlobStoreFixture(unittest.TestCase):
    """每个用例一份独立 layout 与空对象仓。"""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="blobstore-test-")
        self.layout = build_layout(os.path.join(self.tmpdir, "layout"))
        self.store_path = os.path.join(self.tmpdir, "store")
        self.store = BlobStore(self.store_path)

    def tearDown(self):
        self.store.close()
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    # -- 便捷操作 ---------------------------------------------------------
    def import_root(self, key: str, name: str | None = None):
        return self.store.import_layout(self.layout.layout_dir,
                                        self.layout.roots[key], name)

    def object_count(self) -> int:
        return self.store.conn.execute(
            "SELECT COUNT(*) AS c FROM objects").fetchone()["c"]

    def blob_exists(self, digest: str) -> bool:
        return os.path.exists(self.store.blob_path(digest))

    def copy_layout(self, target: str) -> str:
        path = os.path.join(self.tmpdir, target)
        shutil.copytree(self.layout.layout_dir, path)
        return path

    def rewrite_blob(self, layout_dir: str, digest: str, data: bytes) -> None:
        path = os.path.join(layout_dir, "blobs", "sha256",
                            digest.split(":", 1)[1])
        with open(path, "wb") as fh:
            fh.write(data)

    def remove_blob(self, layout_dir: str, digest: str) -> None:
        os.unlink(os.path.join(layout_dir, "blobs", "sha256",
                               digest.split(":", 1)[1]))

    def add_layout_manifest(self, layout_dir: str, raw: bytes,
                            media_type: str) -> str:
        """把一份自造 manifest 原始字节作为新根写进已有 layout。

        返回 digest；调用者自行把根加入 index.json。
        """
        import hashlib
        digest = "sha256:" + hashlib.sha256(raw).hexdigest()
        path = os.path.join(layout_dir, "blobs", "sha256",
                            digest.split(":", 1)[1])
        with open(path, "wb") as fh:
            fh.write(raw)
        index_path = os.path.join(layout_dir, "index.json")
        with open(index_path, "rb") as fh:
            index = json.loads(fh.read())
        index["manifests"].append({
            "mediaType": media_type, "digest": digest, "size": len(raw)})
        with open(index_path, "w", encoding="utf-8") as fh:
            json.dump(index, fh)
        return digest
