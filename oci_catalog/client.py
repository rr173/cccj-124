"""OCI Distribution API 只读 HTTP 客户端。

职责边界：

* 只做网络访问与协议解析，不做持久化；
* 支持匿名与 Bearer token 两种鉴权（完整 WWW-Authenticate 协商）；
* 分页接口同时识别响应体中的游标与 ``Link: rel="next"`` 头，并对重复条目去重；
* 拉取 manifest 时强制校验 ``Docker-Content-Digest`` 与实际内容是否一致，
  不一致抛 :class:`DigestMismatch`；
* **不提供 blob 下载方法**——治理采集只需要 manifest 元数据。
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlencode, quote, urlparse, parse_qs
from urllib.request import Request, urlopen
from urllib.error import HTTPError

from .digest import sha256_digest, matches
from .models import (
    AuthError,
    CursorInvalid,
    Descriptor,
    HTTPError as OCIHTTPError,
    ManifestInfo,
    ManifestKind,
    NotFound,
    PageResult,
    DigestMismatch,
)
from .fake_registry import IMAGE_MEDIA_TYPES, INDEX_MEDIA_TYPES

# 拉 manifest 时声明可接受的全部 manifest media type
_ACCEPT = ", ".join(sorted(IMAGE_MEDIA_TYPES | INDEX_MEDIA_TYPES))

_LINK_RE = re.compile(r'<?([^>;]+)>?\s*(?:;\s*(.*))?')
_PARAM_RE = re.compile(r'(\w+)\s*=\s*"([^"]*)"')


@dataclass
class BearerChallenge:
    realm: str
    service: str = ""
    scope: str = ""


def _parse_www_authenticate(header: str) -> Optional[BearerChallenge]:
    """解析 ``Bearer realm="...",service="...",scope="..."``。"""
    if not header or not header.lower().startswith("bearer "):
        return None
    params = dict(_PARAM_RE.findall(header))
    if "realm" not in params:
        return None
    return BearerChallenge(
        realm=params["realm"],
        service=params.get("service", ""),
        scope=params.get("scope", ""),
    )


def _parse_link_next(link_header: Optional[str]) -> Optional[str]:
    """从 RFC 5988 Link 头中取 ``rel="next"`` 的 URI。"""
    if not link_header:
        return None
    for part in link_header.split(","):
        m = _LINK_RE.match(part.strip())
        if not m:
            continue
        uri, params_str = m.group(1), m.group(2) or ""
        params = {k.lower(): v for k, v in _PARAM_RE.findall(params_str)}
        if params.get("rel", "").lower() == "next":
            return uri
    return None


def _cursor_from_link(link_uri: Optional[str]) -> Optional[str]:
    if not link_uri:
        return None
    query = parse_qs(urlparse(link_uri).query)
    values = query.get("cursor")
    return values[0] if values else None


class RegistryClient:
    """对单个 registry endpoint 的只读客户端。"""

    def __init__(self, base_url: str, username: Optional[str] = None,
                 password: Optional[str] = None, timeout: float = 10.0):
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password
        self.timeout = timeout
        # scope -> token；不同资源的 scope 不同，需分别缓存
        self._tokens: dict[str, str] = {}

    # -- 底层 HTTP ----------------------------------------------------------
    def _request(self, url: str, accept: str, scope: str,
                 token: Optional[str] = None,
                 retried: bool = False) -> tuple[bytes, dict]:
        # 默认复用该 scope 已缓存的 token（真实客户端行为）；
        # 显式传入 token 用于 401 协商后的唯一一次重试
        if token is None:
            token = self._tokens.get(scope)
        headers = {"Accept": accept, "User-Agent": "oci-catalog-collector/1.0"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        req = Request(url, headers=headers, method="GET")
        try:
            with urlopen(req, timeout=self.timeout) as resp:
                return resp.read(), dict(resp.headers.items())
        except HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            if exc.code == 401:
                challenge = _parse_www_authenticate(
                    exc.headers.get("WWW-Authenticate", "")
                )
                # 每个请求最多协商重试一次；scope 不足等 403 不在此分支
                if challenge is not None and not retried:
                    new_token = self._negotiate_token(challenge, scope)
                    return self._request(url, accept, scope,
                                         token=new_token, retried=True)
                raise AuthError(f"鉴权失败: {body}") from exc
            if exc.code == 404:
                raise NotFound(body) from exc
            if exc.code == 403:
                raise AuthError(f"鉴权失败(403): {body}") from exc
            if exc.code == 416:
                raise CursorInvalid(body) from exc
            # 部分 registry 用 400 + RANGE_ERROR 表达游标失效
            if exc.code == 400 and "RANGE_ERROR" in body:
                raise CursorInvalid(body) from exc
            raise OCIHTTPError(exc.code, body, url) from exc

    def _negotiate_token(self, challenge: BearerChallenge, scope: str) -> str:
        """访问 token realm 换取 Bearer token，并按 scope 缓存。"""
        params = {}
        if challenge.service:
            params["service"] = challenge.service
        if scope or challenge.scope:
            params["scope"] = scope or challenge.scope
        url = challenge.realm
        if params:
            url = f"{url}?{urlencode(params)}"
        headers = {"Accept": "application/json"}
        if self.username is not None:
            import base64
            raw = f"{self.username}:{self.password or ''}".encode()
            headers["Authorization"] = "Basic " + base64.b64encode(raw).decode()
        req = Request(url, headers=headers, method="GET")
        try:
            with urlopen(req, timeout=self.timeout) as resp:
                payload = json.loads(resp.read())
        except HTTPError as exc:
            raise AuthError(
                f"token 端点返回 {exc.code}: "
                f"{exc.read().decode('utf-8', errors='replace')}"
            ) from exc
        token = payload.get("token") or payload.get("access_token")
        if not token:
            raise AuthError("token 响应缺少 token/access_token 字段")
        self._tokens[scope] = token
        return token

    def ping(self) -> None:
        """版本探测；若 registry 要求鉴权则完成一次协商（catalog scope）。"""
        try:
            self._request(f"{self.base_url}/v2/", "application/json",
                          scope="registry:catalog:*")
        except AuthError:
            raise
        # ping 成功后 catalog scope 的 token 已缓存（若需要）

    # -- 分页通用逻辑 --------------------------------------------------------
    def _list_page(self, url: str, body_key: str, scope: str,
                   cursor: Optional[str], page_size: Optional[int]) -> PageResult:
        sep = "&" if "?" in url else "?"
        params = []
        if page_size is not None:
            params.append(f"n={page_size}")
        if cursor is not None:
            params.append(f"cursor={cursor}")
        full_url = url + (sep + "&".join(params) if params else "")
        body, headers = self._request(full_url, "application/json", scope)
        payload = json.loads(body)
        raw_items = payload.get(body_key) or []

        # 游标优先取 Link 头（规范位置），回退到 body 无法表达时为 None
        next_link = _parse_link_next(headers.get("Link") or headers.get("link"))
        next_cursor = _cursor_from_link(next_link)

        # 去重：假 registry 可能在页首重复上一页尾条目。真实 registry 也可能
        # 因分页状态变动产生重叠，重复条目必须被丢弃而不是当作新数据。
        seen: set = set()
        items: list = []
        duplicates = 0
        for item in raw_items:
            if item in seen:
                duplicates += 1
                continue
            seen.add(item)
            items.append(item)
        return PageResult(items=items, next_cursor=next_cursor, duplicates=duplicates)

    def list_repositories_page(self, cursor: Optional[str] = None,
                               page_size: Optional[int] = None) -> PageResult:
        return self._list_page(
            f"{self.base_url}/v2/_catalog", "repositories",
            scope="registry:catalog:*", cursor=cursor, page_size=page_size,
        )

    def list_tags_page(self, repository: str, cursor: Optional[str] = None,
                       page_size: Optional[int] = None) -> PageResult:
        name = quote(repository, safe="/")
        return self._list_page(
            f"{self.base_url}/v2/{name}/tags/list", "tags",
            scope=f"repository:{repository}:pull",
            cursor=cursor, page_size=page_size,
        )

    # -- manifest -----------------------------------------------------------
    def get_manifest(self, repository: str, reference: str) -> ManifestInfo:
        """拉取并解析 manifest。

        ``reference`` 可以是 tag 或 digest。无论用什么寻址，都用响应头声明的
        ``Docker-Content-Digest`` 校验实际字节；tag 寻址时返回的 digest 即该
        tag 当前指向的内容身份。
        """
        name = quote(repository, safe="/")
        url = f"{self.base_url}/v2/{name}/manifests/{quote(reference, safe='')}"
        raw, headers = self._request(url, _ACCEPT,
                                     scope=f"repository:{repository}:pull")
        header_map = {k.lower(): v for k, v in headers.items()}
        media_type = header_map.get("content-type", "").split(";")[0].strip()
        declared = header_map.get("docker-content-digest", "")
        actual = sha256_digest(raw)

        if declared and declared != actual:
            raise DigestMismatch(expected=declared, actual=actual,
                                 repository=repository)
        digest = declared or actual
        # 防御：即便没有声明头，也保证 digest 与内容一致
        if not matches(raw, digest):
            raise DigestMismatch(expected=digest, actual=actual,
                                 repository=repository)

        try:
            document = json.loads(raw)
        except json.JSONDecodeError:
            # 非 JSON 的未知格式：登记为 UNKNOWN，不展开
            return ManifestInfo(digest=digest, media_type=media_type,
                                kind=ManifestKind.UNKNOWN, size=len(raw))

        doc_media = document.get("mediaType") or media_type
        if doc_media in IMAGE_MEDIA_TYPES:
            return self._parse_image(digest, doc_media, document, len(raw))
        if doc_media in INDEX_MEDIA_TYPES:
            return self._parse_index(digest, doc_media, document, len(raw))
        # 未知 media type：保留身份，不尝试解释结构
        return ManifestInfo(digest=digest, media_type=doc_media,
                            kind=ManifestKind.UNKNOWN, size=len(raw))

    @staticmethod
    def _parse_image(digest: str, media_type: str, doc: dict,
                     size: int) -> ManifestInfo:
        config = Descriptor.from_dict(doc["config"]) if doc.get("config") else None
        layers = tuple(Descriptor.from_dict(d) for d in doc.get("layers") or [])
        subject = Descriptor.from_dict(doc["subject"]) if doc.get("subject") else None
        return ManifestInfo(
            digest=digest, media_type=media_type, kind=ManifestKind.IMAGE,
            config=config, layers=layers, size=size, subject=subject,
        )

    @staticmethod
    def _parse_index(digest: str, media_type: str, doc: dict,
                     size: int) -> ManifestInfo:
        children = tuple(Descriptor.from_dict(d) for d in doc.get("manifests") or [])
        return ManifestInfo(
            digest=digest, media_type=media_type, kind=ManifestKind.INDEX,
            manifests=children, size=size,
        )
