"""测试共享 fixture：构造一个多平台、多 namespace 的假 registry。"""

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

INDEX_MEDIA = "application/vnd.oci.image.index.v1+json"
UNKNOWN_MEDIA = "application/vnd.example.bespoke.manifest.v1+json"


class RegistryFixture(unittest.TestCase):
    """每个用例独立的 registry + store，目录结构：

    team-a/app       多平台索引（linux/amd64 + linux/arm64，arm64 是嵌套索引）
    team-a/web       单平台 image，两个 tag 指向同一 digest（内容身份去重）
    team-b/util      单平台 image，用于 tag 移动/删除与 namespace diff
    legacy/old       未知 media type 的 manifest
    """

    auth_enabled = False
    page_size = 2
    duplicate_injection = True

    def setUp(self):
        self.registry = FakeRegistry(
            auth_enabled=self.auth_enabled,
            default_page_size=self.page_size,
            duplicate_injection=self.duplicate_injection,
        )
        self.base_url = self.registry.start()
        self.tmpdir = tempfile.mkdtemp(prefix="oci-catalog-test-")
        self.db_path = os.path.join(self.tmpdir, "catalog.db")
        self._build_content()

    def tearDown(self):
        self.registry.stop()
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    # -- 内容构造 -----------------------------------------------------------
    def _build_content(self):
        reg = self.registry

        # team-a/app: 顶层 index -> [amd64 image, arm64 嵌套 index]
        amd64_manifest = make_image_manifest(
            "sha256:" + "a1" * 32,
            ["sha256:" + "l1" * 32, "sha256:" + "l2" * 32],
        )
        self.amd64_digest = reg.put_manifest(
            "team-a/app", amd64_manifest,
            "application/vnd.oci.image.manifest.v1+json")

        arm64_v1 = make_image_manifest(
            "sha256:" + "a2" * 32, ["sha256:" + "l3" * 32])
        self.arm64_v1_digest = reg.put_manifest(
            "team-a/app", arm64_v1,
            "application/vnd.oci.image.manifest.v1+json")
        arm64_v2 = make_image_manifest(
            "sha256:" + "a3" * 32, ["sha256:" + "l4" * 32])
        self.arm64_v2_digest = reg.put_manifest(
            "team-a/app", arm64_v2,
            "application/vnd.oci.image.manifest.v1+json")

        nested_index = make_index_manifest([
            (self.arm64_v1_digest,
             "application/vnd.oci.image.manifest.v1+json",
             {"architecture": "arm64", "os": "linux", "variant": "v8"}),
            (self.arm64_v2_digest,
             "application/vnd.oci.image.manifest.v1+json",
             {"architecture": "arm64", "os": "linux", "variant": "v9"}),
        ])
        self.nested_index_digest = reg.put_manifest(
            "team-a/app", nested_index, INDEX_MEDIA)

        top_index = make_index_manifest([
            (self.amd64_digest,
             "application/vnd.oci.image.manifest.v1+json",
             {"architecture": "amd64", "os": "linux"}),
            (self.nested_index_digest, INDEX_MEDIA, None),
        ])
        self.top_index_digest = reg.put_manifest(
            "team-a/app", top_index, INDEX_MEDIA, tag="latest")
        # 另一个 tag 指向同一个 index digest（同 digest 多 tag）
        reg.retag("team-a/app", "v1.0", self.top_index_digest)

        # team-a/web: 单 image，stable 与 v2 指向同一内容
        web_manifest = make_image_manifest(
            "sha256:" + "c1" * 32, ["sha256:" + "lw" * 32])
        self.web_digest = reg.put_manifest(
            "team-a/web", web_manifest,
            "application/vnd.oci.image.manifest.v1+json", tag="stable")
        reg.retag("team-a/web", "v2", self.web_digest)

        # team-b/util
        util_v1 = make_image_manifest(
            "sha256:" + "u1" * 32, ["sha256:" + "lu" * 32])
        self.util_v1_digest = reg.put_manifest(
            "team-b/util", util_v1,
            "application/vnd.docker.distribution.manifest.v2+json",
            tag="v1")
        util_v2 = make_image_manifest(
            "sha256:" + "u2" * 32, ["sha256:" + "lv" * 32])
        self.util_v2_digest = reg.put_manifest(
            "team-b/util", util_v2,
            "application/vnd.docker.distribution.manifest.v2+json",
            tag="v2")

        # legacy/old: 未知 media type（结构不被识别，只登记身份）
        bespoke = {"customField": "xyz", "blobRef": "sha256:" + "x9" * 32}
        self.bespoke_digest = reg.put_manifest(
            "legacy/old", bespoke, UNKNOWN_MEDIA, tag="edge")

    # -- 工厂 ---------------------------------------------------------------
    def new_store(self) -> CatalogStore:
        return CatalogStore(self.db_path)

    def new_client(self, **kwargs) -> RegistryClient:
        kwargs.setdefault("username", "user" if self.auth_enabled else None)
        kwargs.setdefault("password", "pass" if self.auth_enabled else None)
        return RegistryClient(self.base_url, **kwargs)

    def new_collector(self, client=None, store=None, **kwargs) -> Collector:
        return Collector(
            client or self.new_client(),
            store or self.new_store(),
            page_size=self.page_size,
            **kwargs,
        )
