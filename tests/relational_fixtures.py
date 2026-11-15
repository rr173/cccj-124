"""关系加工测试共享 fixture：内存目录库 + 含业务文件的文件视图。

不经过 HTTP/registry：直接向 CatalogStore 登记 image manifest，
用单层 tar 构建文件视图（复用既有 fileview 机制），关系子系统随后
以只读方式消费这些视图。
"""

import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from oci_catalog import CatalogStore
from oci_catalog.digest import sha256_digest
from oci_catalog.fileview import FileViewStore
from oci_catalog.models import Descriptor, ManifestInfo, ManifestKind
from oci_catalog.relational.sample_relational import build_demo_images

IMAGE_MEDIA = "application/vnd.oci.image.manifest.v1+json"
LAYER_MEDIA = "application/vnd.oci.image.layer.v1.tar"


class RelationalFixture(unittest.TestCase):
    """建好目录库、文件视图库与两个演示镜像视图的基类。"""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="relational-test-")
        self.catalog_db = os.path.join(self.tmpdir, "catalog.db")
        self.views_db = os.path.join(self.tmpdir, "views.db")
        self.results_db = os.path.join(self.tmpdir, "results.db")
        self.catalog = CatalogStore(self.catalog_db)
        self.views = FileViewStore(self.views_db, self.catalog_db)
        self.images = build_demo_images()
        self.layer_paths = {}
        for img in self.images.values():
            path = os.path.join(self.tmpdir, img.key + ".tar")
            with open(path, "wb") as fh:
                fh.write(img.layer_archive)
            self.layer_paths[img.layer_digest] = path
        self.image_digests = {}
        for key, img in self.images.items():
            descriptor = Descriptor(digest=img.layer_digest,
                                    media_type=LAYER_MEDIA,
                                    size=len(img.layer_archive))
            info = ManifestInfo(digest=img.image_digest,
                                media_type=IMAGE_MEDIA,
                                kind=ManifestKind.IMAGE,
                                layers=(descriptor,))
            self.catalog.upsert_manifest(info)
            self.image_digests[key] = img.image_digest
        self.catalog.conn.commit()
        for img in self.images.values():
            result = self.views.build_view(
                img.image_digest, self.layer_paths)
            assert result.ok, result.to_dict()

    def tearDown(self):
        self.views.close()
        self.catalog.close()
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def demo_plan(self):
        from oci_catalog.relational.sample_relational import build_plan
        return build_plan(self.image_digests["orders-image"],
                          self.image_digests["customers-image"])
