"""公告关联测试共享 fixture：目录库 + 已导入 SBOM + 临时公告目录。"""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from oci_catalog import (
    CatalogStore,
    Collector,
    FakeRegistry,
    RegistryClient,
    make_image_manifest,
    make_index_manifest,
)
from oci_catalog.sbom import SBOMStore
from oci_catalog.vuln.versions import versions_available

VERSIONS_AVAILABLE = versions_available()

IMAGE_MEDIA = "application/vnd.oci.image.manifest.v1+json"
INDEX_MEDIA = "application/vnd.oci.image.index.v1+json"


def cdx_component(ref, name, version, purl=None):
    comp = {"bom-ref": ref, "type": "library",
            "name": name, "version": version}
    if purl is not None:
        comp["purl"] = purl
    return comp


def cdx_doc(components, serial="urn:uuid:test"):
    return {"bomFormat": "CycloneDX", "specVersion": "1.5",
            "serialNumber": serial, "version": 1,
            "components": components}


class VulnFixture(unittest.TestCase):
    """两个平台 image（amd64/arm64）+ 一个无 SBOM 镜像 + 空公告目录。"""

    def setUp(self):
        self.registry = FakeRegistry(auth_enabled=False, default_page_size=10)
        self.base_url = self.registry.start()
        self.tmpdir = tempfile.mkdtemp(prefix="vuln-test-")
        self.catalog_db = os.path.join(self.tmpdir, "catalog.db")
        self.sbom_db = os.path.join(self.tmpdir, "sbom.db")
        self.advisory_dir = os.path.join(self.tmpdir, "advisories")
        os.makedirs(self.advisory_dir)

        self.registry.put_manifest(
            "img/amd64", make_image_manifest("sha256:" + "c1" * 32,
                                             ["sha256:" + "l1" * 32]),
            IMAGE_MEDIA, tag="v1")
        self.image_amd64 = next(
            iter(self.registry.repos["img/amd64"].manifests.keys()))
        self.registry.put_manifest(
            "img/arm64", make_image_manifest("sha256:" + "c2" * 32,
                                             ["sha256:" + "l2" * 32]),
            IMAGE_MEDIA, tag="v1")
        self.image_arm64 = next(
            iter(self.registry.repos["img/arm64"].manifests.keys()))
        self.registry.put_manifest(
            "img/quiet", make_image_manifest("sha256:" + "c3" * 32,
                                             ["sha256:" + "l3" * 32]),
            IMAGE_MEDIA, tag="v1")
        self.image_quiet = next(
            iter(self.registry.repos["img/quiet"].manifests.keys()))
        self.index_digest = self.registry.put_manifest(
            "img/amd64",
            make_index_manifest([
                (self.image_amd64, IMAGE_MEDIA,
                 {"architecture": "amd64", "os": "linux"}),
                (self.image_arm64, IMAGE_MEDIA,
                 {"architecture": "arm64", "os": "linux"}),
            ]),
            INDEX_MEDIA, tag="latest")

        store = CatalogStore(self.catalog_db)
        collector = Collector(RegistryClient(self.base_url), store,
                              registry_name=self.base_url, page_size=10)
        report = collector.run()
        assert report.status == "completed"
        store.close()

    def tearDown(self):
        self.registry.stop()

    # ------------------------------------------------------------------
    def import_sbom(self, doc: dict, digest: str, name: str) -> None:
        """把一份清单导入 SBOM 库（断言成功，供测试准备数据）。"""
        path = os.path.join(self.tmpdir, name)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(doc, fh)
        store = SBOMStore(self.sbom_db, self.catalog_db)
        try:
            result = store.import_file(path, digest,
                                       json.dumps(doc).encode("utf-8"))
        finally:
            store.close()
        assert result.ok, [d.to_dict() for d in result.diagnostics]

    def write_advisories(self, mapping: dict, subdir: str = "") -> str:
        """把 {文件名: 公告对象或原始字符串} 写入公告目录，返回目录路径。"""
        target = self.advisory_dir if not subdir else os.path.join(
            self.tmpdir, subdir)
        os.makedirs(target, exist_ok=True)
        for name, payload in mapping.items():
            with open(os.path.join(target, name), "w", encoding="utf-8") as fh:
                if isinstance(payload, str):
                    fh.write(payload)
                else:
                    json.dump(payload, fh)
        return target


def advisory(advisory_id, affected, **extra):
    doc = {"id": advisory_id, "affected": affected}
    doc.update(extra)
    return doc


def pypi_claim(name, versions=None, events=None, range_type="ECOSYSTEM"):
    claim = {"package": {"ecosystem": "PyPI", "name": name}}
    if versions is not None:
        claim["versions"] = versions
    if events is not None:
        claim["ranges"] = [{"type": range_type, "events": events}]
    return claim


def npm_claim(name, versions=None, events=None, range_type="SEMVER"):
    claim = {"package": {"ecosystem": "npm", "name": name}}
    if versions is not None:
        claim["versions"] = versions
    if events is not None:
        claim["ranges"] = [{"type": range_type, "events": events}]
    return claim


def ev(*pairs):
    """事件列表简写：ev(("introduced", "1.0"), ("fixed", "2.0"))。"""
    return [{key: value} for key, value in pairs]
