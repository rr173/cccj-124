"""交付接收端：本地 HTTP 服务，实现受支持的 OCI Distribution 子集。

这是演示与测试用的**真实接收端**：监听本地 HTTP，与发布器通过真实
网络交互；收到的字节、请求范围与清单发布顺序全部落盘，供新进程逐
字节验收。不 mock 任何客户端函数。

数据目录布局（接收端重启后状态仍在，上传会话也持久）::

    <root>/
      repos/<quoted-name>/
        blobs/sha256/<hex>          # 已完成对象字节
        manifests/sha256/<hex>      # 清单原字节
        manifests/index.json        # digest -> mediaType
        tags.json                   # 交付标签 -> digest
      uploads/<uuid>                # 上传会话已接收字节（持久）
      uploads/<uuid>.json           # 会话元数据（repo/session/size）
      requests.jsonl                # 全部请求记录（方法/路径/范围/状态）
      faults.json                   # 故障注入控制文件（见下）

受支持的 HTTP 子集（范围外扩展不实现）：

* ``HEAD /v2/<name>/blobs/<digest>`` → 200（长度 + Docker-Content-Digest）
  或 404；
* ``POST /v2/<name>/blobs/uploads/`` → 202 + Location（相对地址、自带
  ``session`` 查询参数；后续请求必须原样带回，否则 404）；
* ``PATCH <location>``：Content-Length + application/octet-stream +
  ``Content-Range: <start>-<end>``（含两端）；成功 202 + **新** Location
  （session 每次轮换）+ ``Range: 0-<end>``；错位块 416 + 当前
  Range/Location；
* ``GET <location>`` → 204 + 当前前缀 Range（空上传无 Range）；404 表示
  会话过期；
* ``PUT <location>?digest=...``（空请求体）→ 201 + Docker-Content-Digest；
  已收字节摘要与 digest 参数不符 → 400；允许零字节对象；
* ``PUT /v2/<name>/manifests/<reference>``：digest 引用时核对字节摘要；
  按文档 mediaType 做**直接依赖**检查（image manifest 的 config/layers
  必须已在 blobs，index 的子清单必须已在 manifests），缺失 → 400；
  201 + Docker-Content-Digest；
* ``GET /v2/<name>/manifests/<reference>`` → 200 原字节 + 摘要或 404；
* 可选固定 Bearer token：缺失/错误一律 401。

故障注入（``faults.json``，每次请求处理前读取，触发后消费并写回）：

* ``drop_patch``: ``{"at_count": N, "accept_bytes": M}`` —— 第 N 次
  PATCH 只接收 M 字节（落盘）后断开连接，不发响应；
* ``short_patch``: ``{"at_count": N, "accept_bytes": M}`` —— 第 N 次
  PATCH 只接收 M 字节但正常返回 202 与真实 Range；
* ``expire_after_patch``: ``{"at_count": N}`` —— 第 N 次 PATCH 成功后
  删除该会话（后续访问 404）；
* ``drop_put_complete``: ``{"digest": D}`` —— 该对象 PUT 完成落库、
  删除会话后断开连接（201 丢失）；
* ``drop_manifest_put``: ``{"reference": R}`` —— 该清单 PUT 落库后
  断开连接（201 丢失）；
* ``wrong_complete_digest``: ``{"digest": D}`` —— PUT 完成返回错误的
  Docker-Content-Digest；
* ``bad_range``: ``{"mode": "negative|nonprefix|overflow"}`` —— 下一次
  GET 上传会话返回非法 Range；
* ``cross_origin_location``: ``true`` —— 下一次 POST 返回跨来源
  Location；
* ``flaky_500``: ``{"count": N}`` —— 接下来 N 个请求返回 500；
* ``fake_blob_present``: ``{"<digest>": <size>}`` —— HEAD 谎报对象已
  存在（实际不在），用于制造清单发布时的真实依赖缺失。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import socket
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlparse

OCI_IMAGE_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
OCI_IMAGE_INDEX = "application/vnd.oci.image.index.v1+json"

_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_CONTENT_RANGE_RE = re.compile(r"^(\d+)-(\d+)$")

_READ_CHUNK = 64 * 1024


def _sha256_hex(path: str) -> str:
    hasher = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(_READ_CHUNK)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest()


def _quote_repo(name: str) -> str:
    return name.replace("%", "%25").replace("/", "%2F")


def _unquote_repo(name: str) -> str:
    return unquote(name)


class _RepoState:
    """单个仓库路径的服务端状态（内存视图，写穿透到磁盘）。"""

    def __init__(self, root: str, name: str):
        self.name = name
        self.dir = os.path.join(root, "repos", _quote_repo(name))
        self.blobs_dir = os.path.join(self.dir, "blobs", "sha256")
        self.manifests_dir = os.path.join(self.dir, "manifests", "sha256")
        os.makedirs(self.blobs_dir, exist_ok=True)
        os.makedirs(self.manifests_dir, exist_ok=True)
        self.media_index_path = os.path.join(self.dir, "manifests",
                                             "index.json")
        self.tags_path = os.path.join(self.dir, "tags.json")
        self.media_types: dict = {}
        self.tags: dict = {}
        if os.path.exists(self.media_index_path):
            with open(self.media_index_path, encoding="utf-8") as fh:
                self.media_types = json.load(fh)
        if os.path.exists(self.tags_path):
            with open(self.tags_path, encoding="utf-8") as fh:
                self.tags = json.load(fh)

    # -- blobs -----------------------------------------------------------
    def blob_path(self, digest: str) -> str:
        return os.path.join(self.blobs_dir, digest.split(":", 1)[1])

    def has_blob(self, digest: str) -> bool:
        return os.path.isfile(self.blob_path(digest))

    def blob_size(self, digest: str) -> int:
        return os.lstat(self.blob_path(digest)).st_size

    # -- manifests ---------------------------------------------------------
    def manifest_path(self, digest: str) -> str:
        return os.path.join(self.manifests_dir, digest.split(":", 1)[1])

    def has_manifest(self, digest: str) -> bool:
        return os.path.isfile(self.manifest_path(digest))

    def put_manifest(self, digest: str, media_type: str, raw: bytes) -> None:
        tmp = self.manifest_path(digest) + ".tmp"
        with open(tmp, "wb") as fh:
            fh.write(raw)
        os.replace(tmp, self.manifest_path(digest))
        self.media_types[digest] = media_type
        self._save_media_index()

    def _save_media_index(self) -> None:
        tmp = self.media_index_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(self.media_types, fh, sort_keys=True)
        os.replace(tmp, self.media_index_path)

    def set_tag(self, tag: str, digest: str) -> None:
        self.tags[tag] = digest
        tmp = self.tags_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(self.tags, fh, sort_keys=True)
        os.replace(tmp, self.tags_path)


class PushReceiver:
    """接收端本体：状态 + 线程化 HTTP 服务。"""

    def __init__(self, root: str, token: str | None = None,
                 verbose: bool = False):
        self.root = os.path.abspath(root)
        os.makedirs(os.path.join(self.root, "uploads"), exist_ok=True)
        self.token = token
        self.verbose = verbose
        self._lock = threading.RLock()
        self._repos: dict[str, _RepoState] = {}
        self._server: ThreadingHTTPServer | None = None
        self._port = 0
        self._request_seq = 0
        self._patch_count = 0
        self.requests_path = os.path.join(self.root, "requests.jsonl")
        self.faults_path = os.path.join(self.root, "faults.json")

    # ------------------------------------------------------------------
    # 仓库与上传会话
    # ------------------------------------------------------------------
    def repo(self, name: str) -> _RepoState:
        with self._lock:
            state = self._repos.get(name)
            if state is None:
                state = _RepoState(self.root, name)
                self._repos[name] = state
            return state

    def _upload_path(self, upload_id: str) -> str:
        return os.path.join(self.root, "uploads", upload_id)

    def _upload_meta_path(self, upload_id: str) -> str:
        return self._upload_path(upload_id) + ".json"

    def create_upload(self, repo_name: str) -> dict:
        upload_id = uuid.uuid4().hex
        meta = {"repo": repo_name, "session": uuid.uuid4().hex,
                "size": 0, "id": upload_id}
        with open(self._upload_path(upload_id), "wb"):
            pass
        self._save_upload_meta(meta)
        return meta

    def load_upload(self, upload_id: str) -> dict | None:
        if not re.fullmatch(r"[0-9a-f]{32}", upload_id or ""):
            return None
        meta_path = self._upload_meta_path(upload_id)
        if not os.path.isfile(meta_path):
            return None
        with open(meta_path, encoding="utf-8") as fh:
            meta = json.load(fh)
        meta["size"] = os.lstat(self._upload_path(upload_id)).st_size
        return meta

    def _save_upload_meta(self, meta: dict) -> None:
        tmp = self._upload_meta_path(meta["id"]) + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(meta, fh)
        os.replace(tmp, self._upload_meta_path(meta["id"]))

    def rotate_session(self, meta: dict) -> dict:
        meta = dict(meta)
        meta["session"] = uuid.uuid4().hex
        self._save_upload_meta(meta)
        return meta

    def delete_upload(self, upload_id: str) -> None:
        for path in (self._upload_path(upload_id),
                     self._upload_meta_path(upload_id)):
            try:
                os.unlink(path)
            except OSError:
                pass

    # ------------------------------------------------------------------
    # 请求记录与故障注入
    # ------------------------------------------------------------------
    def record_request(self, entry: dict) -> None:
        with self._lock:
            self._request_seq += 1
            entry = dict(entry)
            entry["seq"] = self._request_seq
            line = json.dumps(entry, ensure_ascii=False, sort_keys=True)
            with open(self.requests_path, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")

    def next_patch_count(self) -> int:
        with self._lock:
            self._patch_count += 1
            return self._patch_count

    def load_faults(self) -> dict:
        with self._lock:
            if not os.path.exists(self.faults_path):
                return {}
            try:
                with open(self.faults_path, encoding="utf-8") as fh:
                    return json.load(fh)
            except (OSError, json.JSONDecodeError):
                return {}

    def save_faults(self, faults: dict) -> None:
        with self._lock:
            tmp = self.faults_path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(faults, fh, indent=1, sort_keys=True)
            os.replace(tmp, self.faults_path)

    def consume_fault(self, faults: dict, key: str) -> object:
        """取出并删除一个一次性故障键，写回控制文件。"""
        value = faults.pop(key, None)
        self.save_faults(faults)
        return value

    # ------------------------------------------------------------------
    # HTTP 生命周期
    # ------------------------------------------------------------------
    @property
    def port(self) -> int:
        return self._port

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self._port}"

    def start(self) -> str:
        server = ThreadingHTTPServer(("127.0.0.1", 0), _ReceiverHandler)
        server.receiver = self          # type: ignore[attr-defined]
        server.daemon_threads = True
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


# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------
class _ReceiverHandler(BaseHTTPRequestHandler):
    server_version = "PushReceiver/1.0"

    def log_message(self, fmt, *args):  # noqa: A003
        if self.server.receiver.verbose:  # type: ignore[attr-defined]
            super().log_message(fmt, *args)

    @property
    def receiver(self) -> PushReceiver:
        return self.server.receiver  # type: ignore[attr-defined]

    # -- 工具 -------------------------------------------------------------
    def _drop_connection(self) -> None:
        """模拟"服务端已处理但回执丢失"：直接断开，不写任何响应。"""
        self.close_connection = True
        try:
            self.connection.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            self.connection.close()
        except OSError:
            pass

    def _record(self, method: str, status, note: str = "",
                content_range: str = "", content_length: int = 0) -> None:
        self.receiver.record_request({
            "method": method, "path": self.path, "status": status,
            "note": note, "content_range": content_range,
            "content_length": content_length})

    def _send(self, status: int, body: bytes = b"",
              headers: dict | None = None, method: str = "",
              note: str = "", content_range: str = "",
              content_length: int = 0) -> None:
        self.send_response(status)
        has_explicit_length = False
        if headers:
            for key, value in headers.items():
                if key.lower() == "content-length":
                    has_explicit_length = True
                self.send_header(key, value)
        if not has_explicit_length:
            self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body and self.command != "HEAD":
            self.wfile.write(body)
        self._record(method or self.command, status, note=note,
                     content_range=content_range,
                     content_length=content_length)

    def _error(self, status: int, code: str, message: str,
               headers: dict | None = None, method: str = "") -> None:
        body = json.dumps(
            {"errors": [{"code": code, "message": message}]}).encode("utf-8")
        merged = {"Content-Type": "application/json; charset=utf-8"}
        if headers:
            merged.update(headers)
        self._send(status, body, merged, method=method, note=code)

    def _check_auth(self, method: str) -> bool:
        token = self.receiver.token
        if token is None:
            return True
        header = self.headers.get("Authorization", "")
        if header == f"Bearer {token}":
            return True
        self._error(401, "UNAUTHORIZED", "authentication required",
                    method=method)
        return False

    def _read_body(self, limit: int | None = None) -> bytes:
        length = int(self.headers.get("Content-Length") or 0)
        if limit is not None:
            length = min(length, limit)
        remaining = length
        chunks = []
        while remaining > 0:
            piece = self.rfile.read(min(_READ_CHUNK, remaining))
            if not piece:
                break
            chunks.append(piece)
            remaining -= len(piece)
        return b"".join(chunks)

    def _flaky(self, method: str) -> bool:
        """全局 500 故障注入；返回 True 表示本请求已以 500 回应。"""
        faults = self.receiver.load_faults()
        flaky = faults.get("flaky_500")
        if not flaky or flaky.get("count", 0) <= 0:
            return False
        flaky["count"] -= 1
        if flaky["count"] <= 0:
            self.receiver.consume_fault(faults, "flaky_500")
        else:
            self.receiver.save_faults(faults)
        self._error(500, "INTERNAL_ERROR", "injected flaky failure",
                    method=method)
        return True

    # -- 路由 --------------------------------------------------------------
    def _route(self, method: str) -> None:
        if not self._check_auth(method):
            return
        if self._flaky(method):
            return
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)
        if not path.startswith("/v2/"):
            self._error(404, "NOT_FOUND", f"unknown endpoint {path}",
                        method=method)
            return
        rest = path[len("/v2/"):]
        if "/blobs/uploads/" in rest:
            name, _, tail = rest.partition("/blobs/uploads/")
            upload_id = tail.strip("/")
            if not upload_id:
                # POST /v2/<name>/blobs/uploads/ —— 创建空上传会话
                if method == "POST":
                    self._handle_start_upload(_unquote_repo(name))
                    return
            elif "/" not in upload_id:
                self._handle_upload(method, _unquote_repo(name), upload_id,
                                    query)
                return
        if "/blobs/" in rest:
            name, _, digest = rest.partition("/blobs/")
            digest = unquote(digest)
            if method == "HEAD":
                self._handle_head_blob(_unquote_repo(name), digest)
                return
        if "/manifests/" in rest:
            name, _, reference = rest.partition("/manifests/")
            reference = unquote(reference)
            if method == "PUT":
                self._handle_put_manifest(_unquote_repo(name), reference)
                return
            if method == "GET":
                self._handle_get_manifest(_unquote_repo(name), reference)
                return
        self._error(404, "NOT_FOUND", f"unknown endpoint {path}",
                    method=method)

    def do_HEAD(self):  # noqa: N802
        self._route("HEAD")

    def do_GET(self):  # noqa: N802
        self._route("GET")

    def do_POST(self):  # noqa: N802
        self._route("POST")

    def do_PATCH(self):  # noqa: N802
        self._route("PATCH")

    def do_PUT(self):  # noqa: N802
        self._route("PUT")

    # -- blob HEAD ---------------------------------------------------------
    def _handle_head_blob(self, repo_name: str, digest: str) -> None:
        repo = self.receiver.repo(repo_name)
        faults = self.receiver.load_faults()
        fake = faults.get("fake_blob_present") or {}
        if not repo.has_blob(digest) and digest in fake:
            # 谎报：对象实际不存在，用于制造清单发布时的真实依赖缺失
            self._send(200, b"", {
                "Docker-Content-Digest": digest,
                "Content-Length": str(fake[digest]),
            }, note="fake_blob_present")
            return
        if not repo.has_blob(digest):
            self._error(404, "BLOB_UNKNOWN", f"blob {digest} unknown")
            return
        self._send(200, b"", {
            "Docker-Content-Digest": digest,
            "Content-Length": str(repo.blob_size(digest)),
        })

    # -- 上传会话 -----------------------------------------------------------
    def _upload_location(self, repo_name: str, meta: dict) -> str:
        return (f"/v2/{_quote_repo(repo_name)}/blobs/uploads/"
                f"{meta['id']}?session={meta['session']}")

    def _handle_start_upload(self, repo_name: str) -> None:
        faults = self.receiver.load_faults()
        if faults.get("cross_origin_location"):
            self.receiver.consume_fault(faults, "cross_origin_location")
            self._send(202, b"", {
                "Location": "http://127.0.0.1:1/cross-origin/attack",
            }, method="POST", note="cross_origin_location")
            return
        self.receiver.repo(repo_name)   # 确保仓库目录存在
        meta = self.receiver.create_upload(repo_name)
        self._send(202, b"", {"Location": self._upload_location(
            repo_name, meta)}, method="POST")

    def _load_upload_for_request(self, repo_name: str, upload_id: str,
                                 query: dict, method: str) -> dict | None:
        meta = self.receiver.load_upload(upload_id)
        if meta is None or meta["repo"] != repo_name:
            self._error(404, "BLOB_UPLOAD_UNKNOWN",
                        f"upload {upload_id} unknown", method=method)
            return None
        session = (query.get("session") or [""])[0]
        if session != meta["session"]:
            self._error(404, "BLOB_UPLOAD_UNKNOWN",
                        "session parameter mismatch", method=method)
            return None
        return meta

    def _handle_upload(self, method: str, repo_name: str, upload_id: str,
                       query: dict) -> None:
        if method == "GET":
            self._handle_get_upload(repo_name, upload_id, query)
        elif method == "PATCH":
            self._handle_patch(repo_name, upload_id, query)
        elif method == "PUT":
            self._handle_put_upload(repo_name, upload_id, query)
        else:
            self._error(404, "NOT_FOUND", f"unknown upload method {method}",
                        method=method)

    def _handle_get_upload(self, repo_name: str, upload_id: str,
                           query: dict) -> None:
        meta = self._load_upload_for_request(repo_name, upload_id, query,
                                             "GET")
        if meta is None:
            return
        faults = self.receiver.load_faults()
        bad = faults.get("bad_range")
        if bad:
            self.receiver.consume_fault(faults, "bad_range")
            mode = bad.get("mode")
            if mode == "negative":
                value = "0--5"
            elif mode == "nonprefix":
                value = "5-10"
            else:
                value = "0-999999999"
            self._send(204, b"", {
                "Range": value,
                "Location": self._upload_location(repo_name, meta),
            }, method="GET", note=f"bad_range:{mode}")
            return
        headers = {"Location": self._upload_location(repo_name, meta)}
        if meta["size"] > 0:
            headers["Range"] = f"0-{meta['size'] - 1}"
        self._send(204, b"", headers, method="GET")

    def _handle_patch(self, repo_name: str, upload_id: str,
                      query: dict) -> None:
        meta = self._load_upload_for_request(repo_name, upload_id, query,
                                             "PATCH")
        if meta is None:
            return
        content_length = int(self.headers.get("Content-Length") or 0)
        content_range = self.headers.get("Content-Range") or ""
        match = _CONTENT_RANGE_RE.match(content_range)
        current = meta["size"]
        location = self._upload_location(repo_name, meta)
        range_header = f"0-{current - 1}" if current > 0 else None
        mismatch_headers = {"Location": location}
        if range_header:
            mismatch_headers["Range"] = range_header
        if (match is None
                or int(match.group(1)) != current
                or int(match.group(2)) != current + content_length - 1
                or content_length <= 0):
            self._error(416, "BLOB_UPLOAD_INVALID",
                        "chunk does not continue the received prefix",
                        headers=mismatch_headers, method="PATCH")
            return
        patch_no = self.receiver.next_patch_count()
        faults = self.receiver.load_faults()

        drop = faults.get("drop_patch")
        if drop and drop.get("at_count") == patch_no:
            accept = min(int(drop.get("accept_bytes", 0)), content_length)
            self._append_upload(upload_id, self._read_body(accept))
            times = int(drop.get("times", 1))
            if times > 1:
                drop["at_count"] = patch_no + 1
                drop["times"] = times - 1
                self.receiver.save_faults(faults)
            else:
                self.receiver.consume_fault(faults, "drop_patch")
            self._record("PATCH", "dropped",
                         note=f"drop_patch accepted={accept}",
                         content_range=content_range,
                         content_length=content_length)
            self._drop_connection()
            return

        short = faults.get("short_patch")
        if short and short.get("at_count") == patch_no:
            accept = min(int(short.get("accept_bytes", 0)), content_length)
            self._append_upload(upload_id, self._read_body(accept))
            self.receiver.consume_fault(faults, "short_patch")
            meta = self.receiver.load_upload(upload_id)
            meta = self.receiver.rotate_session(meta)
            new_current = meta["size"]
            self._send(202, b"", {
                "Location": self._upload_location(repo_name, meta),
                "Range": f"0-{new_current - 1}",
            }, method="PATCH", note=f"short_patch accepted={accept}",
                content_range=content_range, content_length=content_length)
            return

        self._append_upload(upload_id, self._read_body())
        meta = self.receiver.load_upload(upload_id)
        meta = self.receiver.rotate_session(meta)
        new_current = meta["size"]

        expire = faults.get("expire_after_patch")
        if expire and expire.get("at_count") == patch_no:
            self.receiver.consume_fault(faults, "expire_after_patch")
            self.receiver.delete_upload(upload_id)
            self._send(202, b"", {
                "Location": self._upload_location(repo_name, meta),
                "Range": f"0-{new_current - 1}",
            }, method="PATCH", note="expire_after_patch",
                content_range=content_range, content_length=content_length)
            return

        self._send(202, b"", {
            "Location": self._upload_location(repo_name, meta),
            "Range": f"0-{new_current - 1}",
        }, method="PATCH", content_range=content_range,
            content_length=content_length)

    def _append_upload(self, upload_id: str, data: bytes) -> None:
        with open(self.receiver._upload_path(upload_id), "ab") as fh:
            fh.write(data)

    def _handle_put_upload(self, repo_name: str, upload_id: str,
                           query: dict) -> None:
        meta = self._load_upload_for_request(repo_name, upload_id, query,
                                             "PUT")
        if meta is None:
            return
        digest = (query.get("digest") or [""])[0]
        if not _SHA256_RE.match(digest):
            self._error(400, "DIGEST_INVALID",
                        f"missing or invalid digest parameter: {digest!r}",
                        method="PUT")
            return
        self._read_body()   # 完成请求体应为空；读出并忽略
        upload_path = self.receiver._upload_path(upload_id)
        actual = "sha256:" + _sha256_hex(upload_path)
        if actual != digest:
            self._error(400, "DIGEST_INVALID",
                        f"received bytes digest {actual} != {digest}",
                        method="PUT")
            return
        repo = self.receiver.repo(repo_name)
        with open(upload_path, "rb") as src:
            data = src.read()
        tmp = repo.blob_path(digest) + ".tmp"
        with open(tmp, "wb") as fh:
            fh.write(data)
        os.replace(tmp, repo.blob_path(digest))
        self.receiver.delete_upload(upload_id)

        faults = self.receiver.load_faults()
        drop = faults.get("drop_put_complete") or {}
        if drop.get("digest") == digest:
            then_flaky = int(drop.get("then_flaky", 0))
            self.receiver.consume_fault(faults, "drop_put_complete")
            if then_flaky > 0:
                # 链式故障：回执丢失后连接仍不稳定（让本次命令用尽尝试）
                faults = self.receiver.load_faults()
                faults["flaky_500"] = {"count": then_flaky}
                self.receiver.save_faults(faults)
            self._record("PUT", "dropped",
                         note=f"drop_put_complete {digest}")
            self._drop_connection()
            return
        wrong = faults.get("wrong_complete_digest") or {}
        if wrong.get("digest") == digest:
            self.receiver.consume_fault(faults, "wrong_complete_digest")
            fake = "sha256:" + ("0" * 64 if digest[7:] != "0" * 64
                                else "f" * 64)
            self._send(201, b"", {"Docker-Content-Digest": fake},
                       method="PUT", note="wrong_complete_digest")
            return
        self._send(201, b"", {"Docker-Content-Digest": digest},
                   method="PUT")

    # -- manifest -----------------------------------------------------------
    def _handle_put_manifest(self, repo_name: str, reference: str) -> None:
        repo = self.receiver.repo(repo_name)
        raw = self._read_body()
        media_type = (self.headers.get("Content-Type") or "").split(";")[0]
        actual = "sha256:" + hashlib.sha256(raw).hexdigest()
        if _SHA256_RE.match(reference) and reference != actual:
            self._error(400, "DIGEST_INVALID",
                        f"manifest bytes digest {actual} != {reference}",
                        method="PUT")
            return
        digest = actual
        # 依赖检查：直接依赖必须先存在
        try:
            document = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._error(400, "MANIFEST_INVALID", "manifest is not valid JSON",
                        method="PUT")
            return
        doc_media = document.get("mediaType") or media_type
        if doc_media == OCI_IMAGE_MANIFEST:
            missing = []
            config = document.get("config") or {}
            if config.get("digest") and not repo.has_blob(config["digest"]):
                missing.append(config["digest"])
            for layer in document.get("layers") or []:
                if layer.get("digest") and not repo.has_blob(layer["digest"]):
                    missing.append(layer["digest"])
            if missing:
                self._error(400, "BLOB_UNKNOWN",
                            "missing blob dependencies: "
                            + ", ".join(sorted(missing)), method="PUT")
                return
        elif doc_media == OCI_IMAGE_INDEX:
            missing = [child["digest"]
                       for child in document.get("manifests") or []
                       if child.get("digest")
                       and not repo.has_manifest(child["digest"])]
            if missing:
                self._error(400, "MANIFEST_UNKNOWN",
                            "missing child manifests: "
                            + ", ".join(sorted(missing)), method="PUT")
                return
        repo.put_manifest(digest, media_type or doc_media, raw)
        is_tag = not _SHA256_RE.match(reference)
        if is_tag:
            repo.set_tag(reference, digest)

        faults = self.receiver.load_faults()
        drop = faults.get("drop_manifest_put") or {}
        if drop.get("reference") == reference:
            then_flaky = int(drop.get("then_flaky", 0))
            self.receiver.consume_fault(faults, "drop_manifest_put")
            if then_flaky > 0:
                faults = self.receiver.load_faults()
                faults["flaky_500"] = {"count": then_flaky}
                self.receiver.save_faults(faults)
            self._record("PUT", "dropped",
                         note=f"drop_manifest_put {reference}")
            self._drop_connection()
            return
        self._send(201, b"", {
            "Docker-Content-Digest": digest,
            "Location": f"/v2/{_quote_repo(repo_name)}/manifests/{digest}",
        }, method="PUT", note=f"tag={reference}" if is_tag else "")

    def _handle_get_manifest(self, repo_name: str, reference: str) -> None:
        repo = self.receiver.repo(repo_name)
        digest = reference
        if not _SHA256_RE.match(reference):
            digest = repo.tags.get(reference)
            if digest is None:
                self._error(404, "MANIFEST_UNKNOWN",
                            f"tag {reference} not found")
                return
        if not repo.has_manifest(digest):
            self._error(404, "MANIFEST_UNKNOWN",
                        f"manifest {digest} unknown")
            return
        with open(repo.manifest_path(digest), "rb") as fh:
            raw = fh.read()
        media_type = repo.media_types.get(
            digest, "application/vnd.oci.image.manifest.v1+json")
        self._send(200, raw, {
            "Content-Type": media_type,
            "Docker-Content-Digest": digest,
        })


# ---------------------------------------------------------------------------
# 独立进程入口：python3 -m oci_catalog.pusher.receiver
# ---------------------------------------------------------------------------
def main(argv: list | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="pusher_receiver",
        description="交付接收端：本地 HTTP 服务，保存字节与请求记录")
    parser.add_argument("--root", required=True, help="数据目录")
    parser.add_argument("--port", type=int, default=0,
                        help="监听端口（0 自动分配）")
    parser.add_argument("--ready-file", default=None,
                        help="就绪后写入端口信息的文件")
    parser.add_argument("--token", default=None,
                        help="要求客户端提供的固定 Bearer token")
    args = parser.parse_args(argv)

    receiver = PushReceiver(args.root, token=args.token)
    receiver.start()
    if args.port:
        # 指定端口时重启服务（测试外用例；演示用自动分配）
        receiver.stop()
        server = ThreadingHTTPServer(("127.0.0.1", args.port),
                                     _ReceiverHandler)
        server.receiver = receiver    # type: ignore[attr-defined]
        server.daemon_threads = True
        receiver._server = server
        receiver._port = args.port
        threading.Thread(target=server.serve_forever, daemon=True).start()
    if args.ready_file:
        with open(args.ready_file, "w", encoding="utf-8") as fh:
            json.dump({"port": receiver.port, "pid": os.getpid()}, fh)
    print(f"receiver listening on {receiver.base_url}", flush=True)
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
