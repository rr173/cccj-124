"""假 OCI Distribution registry（仅用于测试，不访问真实仓库）。

实现的只读端点（Distribution Spec v1）：

* ``GET /v2/_catalog?n=<page size>&cursor=<opaque>`` —— 仓库目录分页
* ``GET /v2/<name>/tags/list?n=&cursor=``          —— tag 列表分页
* ``GET /v2/<name>/manifests/<reference>``          —— manifest（tag 或 digest 寻址）
* ``GET /v2/<name>/blobs/<digest>``                 —— 仅返回占位数据，采集器不会调用

测试能力：

* 不透明分页游标（base64 token，内部带 epoch 版本号），可注入重复条目；
* ``bump_cursor_epoch()`` 让所有旧游标立即失效（返回 416），模拟分页状态丢失；
* 可选 Bearer token 鉴权，带完整 WWW-Authenticate 协商流程与独立 token 端点；
* ``corrupt_manifest_digest()`` 让某个 digest 响应的 ``Docker-Content-Digest``
  头与实际内容不符，用于验证摘要校验与仓库隔离；
* 支持注册未知 media type 的 manifest，采集器必须只登记身份而不展开。
"""

from __future__ import annotations

import base64
import json
import threading
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Optional
from urllib.parse import urlparse, parse_qs, unquote

from .digest import sha256_digest, validate_digest, DigestError

# 采集器需要能识别的 manifest media type（OCI + Docker 两套）
IMAGE_MEDIA_TYPES = frozenset({
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
})
INDEX_MEDIA_TYPES = frozenset({
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
})


# ---------------------------------------------------------------------------
# 内存数据结构
# ---------------------------------------------------------------------------
@dataclass
class StoredManifest:
    """registry 中存储的一份 manifest。"""

    digest: str
    media_type: str
    raw: bytes
    # tag -> 该 manifest digest（同一内容可被多个 tag 引用，只存一份内容）
    tags: set[str] = field(default_factory=set)


@dataclass
class StoredRepo:
    name: str
    manifests: dict[str, StoredManifest] = field(default_factory=dict)
    tag_index: dict[str, str] = field(default_factory=dict)

    def put(self, manifest: dict, media_type: str, tag: Optional[str] = None) -> StoredManifest:
        raw = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
        digest = sha256_digest(raw)
        stored = self.manifests.get(digest)
        if stored is None:
            stored = StoredManifest(digest=digest, media_type=media_type, raw=raw)
            self.manifests[digest] = stored
        if tag:
            old = self.tag_index.get(tag)
            if old and old != digest and old in self.manifests:
                self.manifests[old].tags.discard(tag)
            self.tag_index[tag] = digest
            stored.tags.add(tag)
        return stored

    def delete_tag(self, tag: str) -> bool:
        digest = self.tag_index.pop(tag, None)
        if digest is None:
            return False
        stored = self.manifests.get(digest)
        if stored:
            stored.tags.discard(tag)
        return True

    def delete_manifest(self, digest: str) -> bool:
        stored = self.manifests.pop(digest, None)
        if stored is None:
            return False
        for tag in list(stored.tags):
            self.tag_index.pop(tag, None)
        return True


# ---------------------------------------------------------------------------
# 辅助构造函数：生成合规的 manifest 字典
# ---------------------------------------------------------------------------
def make_descriptor(digest: str, media_type: str, size: int = 1,
                    platform: Optional[dict] = None) -> dict:
    d = {"mediaType": media_type, "digest": digest, "size": size}
    if platform:
        d["platform"] = platform
    return d


def make_image_manifest(config_digest: str, layer_digests: list[str],
                        config_media: str = "application/vnd.oci.image.config.v1+json",
                        layer_media: str = "application/vnd.oci.image.layer.v1.tar+gzip",
                        subject: Optional[dict] = None) -> dict:
    manifest = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": make_descriptor(config_digest, config_media, 2),
        "layers": [make_descriptor(d, layer_media, 100) for d in layer_digests],
    }
    if subject:
        manifest["subject"] = subject
    return manifest


def make_index_manifest(children: list[tuple[str, str, Optional[dict]]]) -> dict:
    """children: [(digest, media_type, platform_dict_or_None), ...]"""
    return {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [
            make_descriptor(digest, media_type, 500, platform)
            for digest, media_type, platform in children
        ],
    }


# ---------------------------------------------------------------------------
# 游标：base64 封装的不透明 token，内含 epoch 与 offset
# ---------------------------------------------------------------------------
def _encode_cursor(epoch: int, offset: int) -> str:
    payload = json.dumps({"e": epoch, "o": offset}, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")


def _decode_cursor(token: str) -> tuple[int, int]:
    try:
        padded = token + "=" * (-len(token) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")))
        return int(payload["e"]), int(payload["o"])
    except Exception as exc:  # 任何解析失败都按无效游标处理
        raise ValueError("malformed cursor") from exc


# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------
class _RegistryHandler(BaseHTTPRequestHandler):
    server_version = "FakeOCI/1.0"

    # 静默标准库的访问日志，测试输出保持干净
    def log_message(self, fmt, *args):  # noqa: A003
        if self.server.verbose:  # type: ignore[attr-defined]
            super().log_message(fmt, *args)

    # -- 工具 ---------------------------------------------------------------
    @property
    def registry(self) -> "FakeRegistry":
        return self.server.registry  # type: ignore[attr-defined]

    def _send_json(self, status: int, payload: dict, extra_headers: Optional[dict] = None):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Docker-Distribution-API-Version", "registry/2.0")
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _send_bytes(self, status: int, body: bytes, content_type: str,
                    extra_headers: Optional[dict] = None):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Docker-Distribution-API-Version", "registry/2.0")
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _error(self, status: int, code: str, message: str,
               extra_headers: Optional[dict] = None):
        self._send_json(status, {"errors": [{"code": code, "message": message}]},
                        extra_headers)

    def _challenge(self, scope: str):
        reg = self.registry
        header = (
            f'Bearer realm="{reg.token_url()}",'
            f'service="{reg.token_service}",scope="{scope}"'
        )
        self._error(401, "UNAUTHORIZED", "authentication required",
                    {"WWW-Authenticate": header})

    def _check_auth(self, scope: str) -> bool:
        """返回 True 表示已放行；False 表示已写出 401 响应。"""
        reg = self.registry
        if not reg.auth_enabled:
            return True
        header = self.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            self._challenge(scope)
            return False
        token = header[len("Bearer "):].strip()
        try:
            claims = reg.verify_token(token)
        except Exception:
            self._challenge(scope)
            return False
        # scope 必须覆盖本次访问的资源
        if claims.get("access") != scope:
            self._error(403, "DENIED", f"token scope {claims.get('access')!r} "
                                       f"does not cover {scope!r}")
            return False
        return True

    # -- 路由 ---------------------------------------------------------------
    def do_GET(self):  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        query = parse_qs(parsed.query)

        if path == "/v2/" or path == "/v2":
            # 版本探测端点：与其他端点一样走完整鉴权协商
            if not self._check_auth(scope="registry:catalog:*"):
                return
            self._send_json(200, {})
            return

        if path == self.registry.token_path:
            self._handle_token(query)
            return

        if path == "/v2/_catalog":
            if not self._check_auth("registry:catalog:*"):
                return
            self._handle_catalog(query)
            return

        if path.endswith("/tags/list"):
            name = unquote(path[len("/v2/"):-len("/tags/list")])
            if not self._check_auth(f"repository:{name}:pull"):
                return
            self._handle_tags(name, query)
            return

        if "/manifests/" in path:
            name, _, reference = path[len("/v2/"):].partition("/manifests/")
            name = unquote(name)
            reference = unquote(reference)
            if not self._check_auth(f"repository:{name}:pull"):
                return
            self._handle_manifest(name, reference)
            return

        if "/blobs/" in path:
            name, _, digest = path[len("/v2/"):].partition("/blobs/")
            if not self._check_auth(f"repository:{unquote(name)}:pull"):
                return
            with self.registry._lock:
                self.registry.blob_requests.append((unquote(name), unquote(digest)))
            self._send_bytes(200, b"FAKE-BLOB-PLACEHOLDER",
                             "application/octet-stream")
            return

        self._error(404, "NOT_FOUND", f"unknown endpoint {path}")

    # -- token 端点 ---------------------------------------------------------
    def _handle_token(self, query: dict):
        reg = self.registry
        if not reg.auth_enabled:
            self._error(404, "NOT_FOUND", "auth disabled")
            return
        # 测试鉴权入口：token 端点强制 Basic 凭据（user:pass），
        # 匿名请求与错误凭据一律 401
        auth = self.headers.get("Authorization", "")
        import base64 as _b64
        try:
            scheme, raw = auth.split(" ", 1)
            if scheme.lower() != "basic" or _b64.b64decode(raw).decode() != "user:pass":
                self._error(401, "UNAUTHORIZED", "bad credentials")
                return
        except Exception:
            self._error(401, "UNAUTHORIZED", "authentication required")
            return
        scope = (query.get("scope") or [""])[0]
        token = reg.issue_token(scope)
        self._send_json(200, {
            "token": token,
            "access_token": token,
            "expires_in": 300,
            "issued_at": "2026-01-01T00:00:00Z",
        })

    # -- 分页列表 -----------------------------------------------------------
    def _paginate(self, items: list, query: dict) -> Optional[tuple[list, Optional[str], int]]:
        """通用分页。返回 (本页条目, 下一游标, 重复数) 或 None（已写错误响应）。"""
        reg = self.registry
        try:
            page_size = int((query.get("n") or [reg.default_page_size])[0])
        except ValueError:
            self._error(400, "BAD_REQUEST", "invalid page size")
            return None
        page_size = max(1, page_size)

        token = (query.get("cursor") or [None])[0]
        offset = 0
        if token is not None:
            try:
                epoch, offset = _decode_cursor(token)
            except ValueError:
                self._error(400, "BAD_REQUEST", "malformed cursor")
                return None
            if epoch != reg.cursor_epoch:
                # 游标 epoch 失效：模拟分页响应在采集过程中失效
                self._error(416, "RANGE_ERROR",
                            "pagination cursor is no longer valid")
                return None
            if offset < 0 or offset > len(items):
                self._error(416, "RANGE_ERROR", "cursor out of range")
                return None

        end = min(offset + page_size, len(items))
        page = list(items[offset:end])
        duplicates = 0
        # 故障注入：在页内重复本页第一个条目，模拟分页状态重叠；
        # 采集器必须去重，既不能把重复项当新数据，也不能因此死循环。
        # 游标仍按真实 end 推进，所以不会产生无限分页。
        if reg.duplicate_injection and page:
            page.append(page[0])
            duplicates = 1
        next_cursor = _encode_cursor(reg.cursor_epoch, end) if end < len(items) else None
        return page, next_cursor, duplicates

    def _handle_catalog(self, query: dict):
        names = sorted(self.registry.repos.keys())
        result = self._paginate(names, query)
        if result is None:
            return
        page, next_cursor, _ = result
        payload = {"repositories": page}
        headers = {}
        if next_cursor:
            headers["Link"] = (
                f'</v2/_catalog?n={query.get("n", [self.registry.default_page_size])[0]}'
                f'&cursor={next_cursor}>; rel="next"'
            )
        self._send_json(200, payload, headers)

    def _handle_tags(self, name: str, query: dict):
        repo = self.registry.repos.get(name)
        if repo is None:
            self._error(404, "NOT_FOUND", f"repository {name} not found")
            return
        tags = sorted(repo.tag_index.keys())
        result = self._paginate(tags, query)
        if result is None:
            return
        page, next_cursor, _ = result
        payload = {"name": name, "tags": page}
        headers = {}
        if next_cursor:
            headers["Link"] = (
                f'</v2/{name}/tags/list?n={query.get("n", [self.registry.default_page_size])[0]}'
                f'&cursor={next_cursor}>; rel="next"'
            )
        self._send_json(200, payload, headers)

    # -- manifest -----------------------------------------------------------
    def _handle_manifest(self, name: str, reference: str):
        repo = self.registry.repos.get(name)
        if repo is None:
            self._error(404, "NOT_FOUND", f"repository {name} not found")
            return
        with self.registry._lock:
            self.registry.manifest_requests += 1

        digest = reference
        if reference in repo.tag_index:
            digest = repo.tag_index[reference]
        else:
            try:
                validate_digest(reference)
            except DigestError:
                self._error(404, "NOT_FOUND", f"tag {reference} not found")
                return
        stored = repo.manifests.get(digest)
        if stored is None:
            # digest 寻址对象已被 GC，或 tag 指向的内容缺失
            self._error(404, "MANIFEST_UNKNOWN", f"manifest {digest} unknown")
            return

        declared_digest = digest
        corrupt = self.registry.corrupted.get((name, digest))
        if corrupt:
            declared_digest = corrupt  # 与实际内容不符的声明 digest
        headers = {
            "Docker-Content-Digest": declared_digest,
            "OCI-Subject": stored.digest,
        }
        self._send_bytes(200, stored.raw, stored.media_type, headers)


# ---------------------------------------------------------------------------
# registry 本体 + HTTP 服务封装
# ---------------------------------------------------------------------------
class FakeRegistry:
    """线程安全的内存假 registry。"""

    token_path = "/token"
    token_service = "fake-registry"

    def __init__(self, auth_enabled: bool = False, default_page_size: int = 2,
                 duplicate_injection: bool = False, verbose: bool = False):
        self._lock = threading.RLock()
        self.repos: dict[str, StoredRepo] = {}
        self.auth_enabled = auth_enabled
        self.default_page_size = default_page_size
        self.duplicate_injection = duplicate_injection
        self.verbose = verbose
        self.cursor_epoch = 1
        # (repo, digest) -> 伪造的错误 digest
        self.corrupted: dict[tuple[str, str], str] = {}
        self._server: Optional[ThreadingHTTPServer] = None
        self._port: int = 0
        self._token_counter = 0
        # 观测点：采集器不应访问 blob 端点（layer 不下载）
        self.blob_requests: list[tuple[str, str]] = []
        self.manifest_requests: int = 0

    # -- 数据装载 API（测试用） ---------------------------------------------
    def create_repository(self, name: str) -> StoredRepo:
        with self._lock:
            repo = self.repos.get(name)
            if repo is None:
                repo = StoredRepo(name=name)
                self.repos[name] = repo
            return repo

    def put_manifest(self, name: str, manifest: dict, media_type: str,
                     tag: Optional[str] = None) -> str:
        with self._lock:
            return self.create_repository(name).put(manifest, media_type, tag).digest

    def retag(self, name: str, tag: str, digest: str) -> None:
        """让已有 tag 改指向另一个已存在的 digest（模拟 tag 被覆盖）。

        支持跨仓库引用：真实 registry 允许通过 cross-repo mount 共享内容，
        目标仓库会登记同一 digest 的内容身份（只引用，不复制字节）。
        """
        with self._lock:
            repo = self.repos[name]
            if digest not in repo.manifests:
                source = next((r for r in self.repos.values()
                               if digest in r.manifests), None)
                if source is None:
                    raise KeyError(digest)
                stored = source.manifests[digest]
                repo.manifests[digest] = stored
            old = repo.tag_index.get(tag)
            if old and old in repo.manifests:
                repo.manifests[old].tags.discard(tag)
            repo.tag_index[tag] = digest
            repo.manifests[digest].tags.add(tag)

    def delete_tag(self, name: str, tag: str) -> None:
        with self._lock:
            if not self.repos[name].delete_tag(tag):
                raise KeyError(tag)

    def delete_manifest(self, name: str, digest: str) -> None:
        with self._lock:
            if not self.repos[name].delete_manifest(digest):
                raise KeyError(digest)

    def corrupt_manifest_digest(self, name: str, digest: str) -> None:
        """让该 manifest 的响应头声明一个错误 digest。"""
        with self._lock:
            fake = "sha256:" + "0" * 64
            if fake == digest:
                fake = "sha256:" + "f" * 64
            self.corrupted[(name, digest)] = fake

    def bump_cursor_epoch(self) -> None:
        """使所有已发放的分页游标立即失效。"""
        with self._lock:
            self.cursor_epoch += 1

    # -- token 机制 ---------------------------------------------------------
    def issue_token(self, scope: str) -> str:
        # 无签名的不透明假 token：base64(JSON)
        with self._lock:
            self._token_counter += 1
            payload = {"sub": "user", "access": scope, "seq": self._token_counter}
        return base64.urlsafe_b64encode(
            json.dumps(payload, separators=(",", ":")).encode()
        ).decode("ascii").rstrip("=")

    def verify_token(self, token: str) -> dict:
        padded = token + "=" * (-len(token) % 4)
        return json.loads(base64.urlsafe_b64decode(padded.encode("ascii")))

    # -- HTTP 生命周期 -------------------------------------------------------
    @property
    def port(self) -> int:
        return self._port

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self._port}"

    def token_url(self) -> str:
        return f"{self.base_url}{self.token_path}"

    def start(self) -> str:
        server = ThreadingHTTPServer(("127.0.0.1", 0), _RegistryHandler)
        server.registry = self  # type: ignore[attr-defined]
        server.verbose = self.verbose  # type: ignore[attr-defined]
        self._server = server
        self._port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        return self.base_url

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
