"""发布侧 HTTP 客户端：受支持的 OCI Distribution 子集。

只实现题目要求的子集，不做范围外扩展（无跨仓挂载、并行块、重定向、
token 协商）：

* ``HEAD /v2/<name>/blobs/<digest>``：200（长度 + Docker-Content-Digest）
  或 404；长度或摘要矛盾报 :class:`ProtocolProblem`；
* ``POST /v2/<name>/blobs/uploads/`` → 202 + Location；
* ``PATCH <location>``：Content-Length + ``Content-Type:
  application/octet-stream`` + ``Content-Range: <start>-<end>``（含两端），
  202 返回新 Location 与 ``Range: 0-<end>``；错位块 416 携带当前
  Range/Location，抛 :class:`RangeMismatch` 供对账；
* ``GET <location>``：204 + 当前前缀 Range（空上传无 Range）或 404；
* ``PUT <location>?digest=...``（空请求体）→ 201 + Docker-Content-Digest；
* ``PUT /v2/<name>/manifests/<reference>``：原内容类型 + 原字节，
  201 的 Docker-Content-Digest 必须等于字节实际摘要；
* ``GET /v2/<name>/manifests/<reference>``：读回原字节与摘要，用于
  检查已完成状态及消解发布回执丢失。

协议纪律：

* **Location**：可为相对地址、可每次变化、可自带查询参数；客户端解析
  后完整保留（含查询参数），并限制在与配置端点**同一来源**——跨来源
  Location 一律拒绝，绝不向它发送数据或凭据；
* **Range**：必须是 ``0-<end>`` 前缀且 ``end+1 <= 对象大小``；负数、
  非前缀、越过本对象大小等不可能状态一律拒绝；
* **鉴权**：使用调用者提供的固定 Bearer token；401/403 抛
  :class:`AuthProblem`（明确失败，不无限重试）；
* **重定向**：不跟随（3xx 视为协议错误）；
* **错误分类**：网络异常/连接中断/超时/5xx → :class:`TransientProblem`
  （由编排层做有限重试）；其他意外 4xx → :class:`ProtocolProblem`。
"""

from __future__ import annotations

import re
import socket
from dataclasses import dataclass
from http.client import IncompleteRead, RemoteDisconnected
from typing import Optional
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urljoin, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from ..digest import sha256_digest
from .errors import (AuthProblem, ProtocolProblem, RangeMismatch,
                     SessionGone, TransientProblem)
from .progress import endpoint_origin, normalize_endpoint

_PREFIX_RANGE_RE = re.compile(r"^0-(\d+)$")

USER_AGENT = "oci-pusher/1.0"


class _NoRedirect(HTTPRedirectHandler):
    """本题不需要重定向：一律不跟随，交给错误分类处理。"""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


@dataclass(frozen=True)
class HeadInfo:
    """HEAD blob 的服务端事实。"""

    digest: str
    size: int


@dataclass(frozen=True)
class UploadStatus:
    """GET 上传会话的服务端事实：已确认前缀与（可能更新的）位置。"""

    offset: int
    location: Optional[str]


@dataclass(frozen=True)
class PatchAck:
    """PATCH 202 的服务端确认：新前缀与（可能变化的）新位置。"""

    offset: int
    location: Optional[str]


def parse_prefix_range(value: Optional[str], size: int, where: str) -> int:
    """把 ``Range: 0-<end>`` 解析为已确认前缀字节数。

    ``value`` 为 None 表示空上传（服务端未给 Range），返回 0。
    负数、非前缀、格式非法、越过本对象大小都是不可能状态，一律
    :class:`ProtocolProblem`。
    """
    if value is None:
        return 0
    match = _PREFIX_RANGE_RE.match(value.strip())
    if match is None:
        raise ProtocolProblem(
            f"{where}: 非法 Range（只接受 0-<end> 前缀）: {value!r}")
    offset = int(match.group(1)) + 1
    if offset > size:
        raise ProtocolProblem(
            f"{where}: Range 前缀 {offset} 越过本对象大小 {size}: "
            f"{value!r}")
    return offset


class PushHttpClient:
    """对单个目标端点的发布客户端（固定 Bearer token，无协商）。"""

    def __init__(self, endpoint: str, token: Optional[str] = None,
                 timeout: float = 10.0):
        self.endpoint = normalize_endpoint(endpoint)
        self.origin = endpoint_origin(endpoint)
        self.token = token
        self.timeout = timeout
        self._opener = build_opener(_NoRedirect())

    # ------------------------------------------------------------------
    # 地址解析：Location 可为相对地址、可带查询参数；必须同源
    # ------------------------------------------------------------------
    def resolve_location(self, location: Optional[str], where: str) -> str:
        if not location or not isinstance(location, str):
            raise ProtocolProblem(f"{where}: 响应缺少 Location 头")
        absolute = urljoin(self.endpoint + "/", location)
        parts = urlsplit(absolute)
        scheme = parts.scheme.lower()
        host = (parts.hostname or "").lower()
        if scheme not in ("http", "https") or not host:
            raise ProtocolProblem(
                f"{where}: Location 不是合法 http(s) 地址: {location!r}")
        default = 443 if scheme == "https" else 80
        try:
            port = parts.port or default
        except ValueError as exc:
            raise ProtocolProblem(
                f"{where}: Location 端口非法: {location!r}") from exc
        if (scheme, host, port) != self.origin:
            raise ProtocolProblem(
                f"{where}: 拒绝跨来源 Location（不会向它发送数据或凭据）: "
                f"{location!r}")
        return absolute

    # ------------------------------------------------------------------
    # 底层请求（单次，不重试；错误分类）
    # ------------------------------------------------------------------
    def _request(self, method: str, url: str, body: Optional[bytes] = None,
                 headers: Optional[dict] = None,
                 expect: tuple = (200,)) -> tuple:
        """发一次请求；返回 (状态码, 响应头, 响应体)。

        ``expect`` 列出调用者愿意自行解释的状态码（含 4xx）；其余状态：
        401/403 → AuthProblem；5xx → TransientProblem；3xx 与其他 →
        ProtocolProblem。网络异常/超时/连接中断 → TransientProblem。
        """
        request_headers = {"User-Agent": USER_AGENT}
        if self.token is not None:
            request_headers["Authorization"] = f"Bearer {self.token}"
        if headers:
            request_headers.update(headers)
        req = Request(url, data=body, headers=request_headers, method=method)
        try:
            with self._opener.open(req, timeout=self.timeout) as resp:
                status = resp.status
                response_headers = dict(resp.headers.items())
                payload = resp.read()
        except HTTPError as exc:
            status = exc.code
            response_headers = (dict(exc.headers.items())
                                if exc.headers is not None else {})
            try:
                payload = exc.read()
            except Exception:
                payload = b""
            if status == 401:
                raise AuthProblem(
                    f"鉴权失败(401) {method} {url}: "
                    f"{payload.decode('utf-8', errors='replace')}")
            if status == 403:
                raise AuthProblem(
                    f"鉴权失败(403) {method} {url}: "
                    f"{payload.decode('utf-8', errors='replace')}")
            if 500 <= status <= 599:
                raise TransientProblem(
                    f"服务端故障({status}) {method} {url}: "
                    f"{payload.decode('utf-8', errors='replace')}")
            if status in expect:
                return status, response_headers, payload
            if 300 <= status <= 399:
                raise ProtocolProblem(
                    f"不支持重定向({status}) {method} {url}")
            raise ProtocolProblem(
                f"意外响应({status}) {method} {url}: "
                f"{payload.decode('utf-8', errors='replace')}")
        except (URLError, RemoteDisconnected, IncompleteRead,
                ConnectionError, BrokenPipeError, socket.timeout,
                TimeoutError, OSError) as exc:
            raise TransientProblem(f"网络异常 {method} {url}: {exc}") from exc
        if status not in expect:
            raise ProtocolProblem(
                f"意外响应({status}) {method} {url}: "
                f"{payload.decode('utf-8', errors='replace')}")
        return status, response_headers, payload

    @staticmethod
    def _header(headers: dict, name: str) -> Optional[str]:
        lowered = name.lower()
        for key, value in headers.items():
            if key.lower() == lowered:
                return value
        return None

    # ------------------------------------------------------------------
    # blob 检查
    # ------------------------------------------------------------------
    def head_blob(self, repo: str, digest: str, size: int
                  ) -> Optional[HeadInfo]:
        """HEAD 检查对象是否已存在；长度或摘要矛盾报协议错误。"""
        url = (f"{self.endpoint}/v2/{quote(repo, safe='/')}/blobs/"
               f"{quote(digest, safe=':')}")
        status, headers, _ = self._request("HEAD", url, expect=(200, 404))
        if status == 404:
            return None
        served_digest = self._header(headers, "Docker-Content-Digest")
        if served_digest is not None and served_digest != digest:
            raise ProtocolProblem(
                f"HEAD {digest}: 服务端摘要 {served_digest} 与请求矛盾")
        length_raw = self._header(headers, "Content-Length")
        if length_raw is None:
            raise ProtocolProblem(f"HEAD {digest}: 缺少 Content-Length")
        try:
            served_size = int(length_raw)
        except ValueError as exc:
            raise ProtocolProblem(
                f"HEAD {digest}: Content-Length 非法: {length_raw!r}") from exc
        if served_size != size:
            raise ProtocolProblem(
                f"HEAD {digest}: 服务端长度 {served_size} 与本地 {size} 矛盾")
        return HeadInfo(digest=digest, size=served_size)

    # ------------------------------------------------------------------
    # 上传会话
    # ------------------------------------------------------------------
    def start_upload(self, repo: str) -> str:
        """POST 创建空上传会话，返回解析后的 Location（保留查询参数）。"""
        url = f"{self.endpoint}/v2/{quote(repo, safe='/')}/blobs/uploads/"
        _, headers, _ = self._request("POST", url, body=b"", expect=(202,))
        return self.resolve_location(self._header(headers, "Location"),
                                     "POST uploads")

    def get_upload(self, location: str, size: int) -> Optional[UploadStatus]:
        """GET 上传会话：204 + 前缀 Range；404 表示会话过期。"""
        url = self.resolve_location(location, "GET upload")
        status, headers, _ = self._request("GET", url, expect=(204, 404))
        if status == 404:
            return None
        offset = parse_prefix_range(self._header(headers, "Range"), size,
                                    "GET upload")
        new_location = self._header(headers, "Location")
        resolved = (self.resolve_location(new_location, "GET upload")
                    if new_location else None)
        return UploadStatus(offset=offset, location=resolved)

    def patch_chunk(self, location: str, start: int, chunk: bytes,
                    size: int) -> PatchAck:
        """PATCH 一个块；416 错位抛 RangeMismatch（携带服务端前缀）。

        成功时以服务端 ``Range`` 头确认的前缀为准（可能与本地推算不同）；
        会话 404 抛 :class:`SessionGone`。
        """
        url = self.resolve_location(location, "PATCH")
        end = start + len(chunk) - 1
        headers = {
            "Content-Type": "application/octet-stream",
            "Content-Range": f"{start}-{end}",
        }
        status, response_headers, _ = self._request(
            "PATCH", url, body=chunk, headers=headers, expect=(202, 404, 416))
        if status == 404:
            raise SessionGone(f"PATCH {url}: 上传会话已过期(404)")
        range_header = self._header(response_headers, "Range")
        offset = parse_prefix_range(range_header, size, "PATCH 响应")
        new_location = self._header(response_headers, "Location")
        resolved = (self.resolve_location(new_location, "PATCH")
                    if new_location else None)
        if status == 416:
            raise RangeMismatch(
                f"PATCH 错位块：服务端确认前缀 {offset}", offset=offset,
                location=resolved)
        return PatchAck(offset=offset, location=resolved)

    def complete_upload(self, location: str, digest: str) -> None:
        """PUT 完成对象（空请求体 + digest 查询参数）；核对 201 摘要。

        会话 404 抛 :class:`SessionGone`（调用方应先 HEAD 核对对象是否
        已经存在，再决定是否重传）。
        """
        url = self.resolve_location(location, "PUT upload")
        separator = "&" if "?" in url else "?"
        url = f"{url}{separator}digest={quote(digest, safe=':')}"
        status, headers, _ = self._request("PUT", url, body=b"",
                                           expect=(201, 404))
        if status == 404:
            raise SessionGone(f"PUT {url}: 上传会话已过期(404)")
        served = self._header(headers, "Docker-Content-Digest")
        if served != digest:
            raise ProtocolProblem(
                f"PUT 完成 {digest}: 服务端回执摘要 {served!r} 不符")

    # ------------------------------------------------------------------
    # 清单
    # ------------------------------------------------------------------
    def put_manifest(self, repo: str, reference: str, media_type: str,
                     raw: bytes) -> None:
        """以原内容类型和原字节 PUT 清单；核对 201 摘要。"""
        url = (f"{self.endpoint}/v2/{quote(repo, safe='/')}/manifests/"
               f"{quote(reference, safe=':')}")
        _, headers, _ = self._request(
            "PUT", url, body=raw,
            headers={"Content-Type": media_type}, expect=(201,))
        expected = sha256_digest(raw)
        served = self._header(headers, "Docker-Content-Digest")
        if served != expected:
            raise ProtocolProblem(
                f"PUT manifest {reference}: 服务端回执摘要 {served!r} "
                f"与内容摘要 {expected} 不符")

    def get_manifest(self, repo: str, reference: str
                     ) -> Optional[tuple]:
        """GET 清单：返回 (原字节, 摘要)；404 返回 None。

        响应的 ``Docker-Content-Digest`` 若与实际字节摘要矛盾，报协议
        错误——远端事实不可信时不能据此推进进度。
        """
        url = (f"{self.endpoint}/v2/{quote(repo, safe='/')}/manifests/"
               f"{quote(reference, safe=':')}")
        status, headers, payload = self._request("GET", url,
                                                 expect=(200, 404))
        if status == 404:
            return None
        actual = sha256_digest(payload)
        served = self._header(headers, "Docker-Content-Digest")
        if served is not None and served != actual:
            raise ProtocolProblem(
                f"GET manifest {reference}: 摘要头 {served} 与内容 "
                f"{actual} 不符")
        return payload, actual
