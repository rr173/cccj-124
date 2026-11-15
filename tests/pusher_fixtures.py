"""发布子系统测试共享 fixture：临时 layout + 对象仓 + 线程内接收端。

接收端是真实 HTTP 服务（线程内启动），客户端经真实网络交互；
不 mock 客户端函数。每个用例一份独立临时目录。
"""

import json
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from oci_catalog.blobstore import BlobStore
from oci_catalog.pusher.pusher import PushConfig
from oci_catalog.pusher.receiver import PushReceiver
from oci_catalog.pusher.sample_data import (build_layout, fixture_bytes,
                                            fixture_digests)


class PusherFixture(unittest.TestCase):
    """每个用例：layout 导入对象仓（名称 delivery-a）+ 接收端。"""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="pusher-test-")
        self.layout = build_layout(os.path.join(self.tmpdir, "layout"))
        self.store_path = os.path.join(self.tmpdir, "store")
        store = BlobStore(self.store_path)
        try:
            result = store.import_layout(self.layout.layout_dir,
                                         self.layout.root_a, "delivery-a")
            assert result.ok, result.to_dict()
            # 旧根也导入并绑定另一个名称（旧交付标签的源）
            result = store.import_layout(self.layout.layout_dir,
                                         self.layout.old_root, "old-root")
            assert result.ok, result.to_dict()
        finally:
            store.close()
        self.remote_dir = os.path.join(self.tmpdir, "remote")
        self.receiver = PushReceiver(self.remote_dir)
        self.receiver.start()
        self.progress_path = os.path.join(self.tmpdir, "progress.json")
        self.digests = fixture_digests()
        self.bytes_table = fixture_bytes()

    def tearDown(self):
        self.receiver.stop()
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    # -- 便捷操作 ---------------------------------------------------------
    def make_config(self, **overrides) -> PushConfig:
        params = dict(
            store_path=self.store_path,
            name="delivery-a",
            endpoint=self.receiver.base_url,
            repo="mirror/worker",
            tag="release-7",
            progress_path=self.progress_path,
            chunk_size=128,
            max_attempts=3,
            backoff=0.01,
        )
        params.update(overrides)
        return PushConfig(**params)

    def read_requests(self) -> list:
        if not os.path.exists(self.receiver.requests_path):
            return []
        with open(self.receiver.requests_path, encoding="utf-8") as fh:
            return [json.loads(line) for line in fh]

    def repo_dir(self, repo: str = "mirror/worker") -> str:
        return os.path.join(self.remote_dir, "repos",
                            repo.replace("/", "%2F"))

    def remote_blob(self, digest: str, repo: str = "mirror/worker") -> bytes:
        path = os.path.join(self.repo_dir(repo), "blobs", "sha256",
                            digest.split(":", 1)[1])
        with open(path, "rb") as fh:
            return fh.read()

    def remote_manifest(self, digest: str,
                        repo: str = "mirror/worker") -> bytes:
        path = os.path.join(self.repo_dir(repo), "manifests", "sha256",
                            digest.split(":", 1)[1])
        with open(path, "rb") as fh:
            return fh.read()

    def remote_tags(self, repo: str = "mirror/worker") -> dict:
        path = os.path.join(self.repo_dir(repo), "tags.json")
        if not os.path.exists(path):
            return {}
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)

    def preload_blob(self, logical_name: str,
                     repo: str = "mirror/worker") -> str:
        """预先在远端放一份对象（模拟已有远端对象复用）。"""
        data, _mt = self.bytes_table[logical_name]
        digest = self.digests[logical_name]
        blobs = os.path.join(self.repo_dir(repo), "blobs", "sha256")
        os.makedirs(blobs, exist_ok=True)
        with open(os.path.join(blobs, digest.split(":", 1)[1]), "wb") as fh:
            fh.write(data)
        return digest

    def preload_tag(self, tag: str, logical_manifest: str,
                    repo: str = "mirror/worker") -> str:
        """预先在远端放旧清单与旧交付标签。"""
        raw, mt = self.bytes_table[logical_manifest]
        digest = self.digests[logical_manifest]
        manifests = os.path.join(self.repo_dir(repo), "manifests", "sha256")
        os.makedirs(manifests, exist_ok=True)
        with open(os.path.join(manifests, digest.split(":", 1)[1]),
                  "wb") as fh:
            fh.write(raw)
        index_path = os.path.join(self.repo_dir(repo), "manifests",
                                  "index.json")
        index = {}
        if os.path.exists(index_path):
            with open(index_path, encoding="utf-8") as fh:
                index = json.load(fh)
        index[digest] = mt
        with open(index_path, "w", encoding="utf-8") as fh:
            json.dump(index, fh)
        tags_path = os.path.join(self.repo_dir(repo), "tags.json")
        tags = {}
        if os.path.exists(tags_path):
            with open(tags_path, encoding="utf-8") as fh:
                tags = json.load(fh)
        tags[tag] = digest
        with open(tags_path, "w", encoding="utf-8") as fh:
            json.dump(tags, fh)
        return digest

    def verify_remote_closure(self, repo: str = "mirror/worker") -> None:
        """逐字节核对远端根 A 闭包（除 old-* 外的全部夹具对象）。"""
        for name, (data, _mt) in self.bytes_table.items():
            if name.startswith("old-"):
                continue
            digest = self.digests[name]
            if "manifest" in name or "index" in name:
                got = self.remote_manifest(digest, repo)
            else:
                got = self.remote_blob(digest, repo)
            self.assertEqual(got, data, f"远端对象 {name} 字节不符")

    def requests_for(self, method: str, substring: str) -> list:
        return [r for r in self.read_requests()
                if r["method"] == method and substring in r["path"]]
