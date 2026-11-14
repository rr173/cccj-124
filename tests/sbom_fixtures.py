"""SBOM 测试共享 fixture：内存目录库 + 已采集的单平台 image manifest。"""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from oci_catalog import (
    CatalogStore,
    FakeRegistry,
    RegistryClient,
    Collector,
    make_image_manifest,
    make_index_manifest,
)
from oci_catalog.sbom import SBOMStore

IMAGE_MEDIA = "application/vnd.oci.image.manifest.v1+json"
INDEX_MEDIA = "application/vnd.oci.image.index.v1+json"


class SBOMFixture(unittest.TestCase):
    """构建一个含两个平台 image + 一个 index 的目录库，以及空 SBOM 库。"""

    def setUp(self):
        self.registry = FakeRegistry(auth_enabled=False, default_page_size=10)
        self.base_url = self.registry.start()
        self.tmpdir = tempfile.mkdtemp(prefix="sbom-test-")
        self.catalog_db = os.path.join(self.tmpdir, "catalog.db")
        self.sbom_db = os.path.join(self.tmpdir, "sbom.db")

        # 两个单平台 image，分别属于不同仓库
        self.registry.put_manifest(
            "img/amd64",
            make_image_manifest("sha256:" + "c1" * 32,
                                ["sha256:" + "l1" * 32]),
            IMAGE_MEDIA, tag="v1")
        self.image_amd64 = next(
            iter(self.registry.repos["img/amd64"].manifests.keys()))
        self.registry.put_manifest(
            "img/arm64",
            make_image_manifest("sha256:" + "c2" * 32,
                                ["sha256:" + "l2" * 32]),
            IMAGE_MEDIA, tag="v1")
        self.image_arm64 = next(
            iter(self.registry.repos["img/arm64"].manifests.keys()))
        self.index_digest = self.registry.put_manifest(
            "img/amd64",
            make_index_manifest([
                (self.image_amd64, IMAGE_MEDIA,
                 {"architecture": "amd64", "os": "linux"}),
                (self.image_arm64, IMAGE_MEDIA,
                 {"architecture": "arm64", "os": "linux", "variant": "v8"}),
            ]), INDEX_MEDIA, tag="multi")

        self.catalog = CatalogStore(self.catalog_db)
        collector = Collector(RegistryClient(self.base_url), self.catalog,
                              registry_name=self.base_url)
        report = collector.run()
        assert report.status == "completed"
        self.catalog.close()

        self.store = SBOMStore(self.sbom_db, self.catalog_db)

    def tearDown(self):
        self.store.close()
        self.registry.stop()
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    # -- 辅助 ---------------------------------------------------------------
    def write_sbom(self, name: str, payload: dict) -> str:
        path = os.path.join(self.tmpdir, name)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh)
        return path

    def import_dict(self, name: str, payload: dict, digest: str):
        path = self.write_sbom(name, payload)
        with open(path, "rb") as fh:
            return self.store.import_file(path, digest, fh.read())
