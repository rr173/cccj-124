"""发布进度文件：绑定校验、状态机与原子落盘。

进度文件是**可中断后继续**的载体，设计要点：

* **绑定**：进度与 ``(源仓, 保留名称, 精确根, 目标端点, 仓库路径,
  交付标签)`` 绑定。继续时命令行参数与绑定任何一项冲突，都在发送
  任何写请求之前拒绝（:class:`ProgressProblem`）。
* **保守口径**：``confirmed`` 只记录**已被服务端响应确认**的字节前缀。
  "请求已发出但本地尚未确认"不靠猜：每个写请求**发出前**先把状态机
  推进到对应中间态（``uploading``/``completing``/``publishing``）落盘，
  响应确认后再推进到终态。进程在两者之间死亡时，进度停在中间态，
  恢复逻辑据此向服务端对账（GET 上传状态 / HEAD 对象 / GET 清单），
  以服务端事实为准，而不是只写一份成功标志。
* **损坏不覆盖**：JSON 语法错误、格式标识不符、结构缺字段、对象集合
  与固定闭包不一致，都按损坏拒绝——不覆盖、不新建、不当作新任务。
* **原子落盘**：写临时文件 + fsync + ``os.replace``，进度文件本身
  不会写出半份。

进度文件只记录摘要、偏移与状态等元数据；对象字节绝不编码进进度。
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from .errors import ProgressProblem

FORMAT = "oci-pusher-progress/v1"

# 对象状态机
PENDING = "pending"          # 未触碰（恢复时先 HEAD/GET 对账再决定）
UPLOADING = "uploading"      # 已有上传会话，confirmed 为已确认前缀
COMPLETING = "completing"    # PUT 完成请求已发出、响应未确认
PUBLISHING = "publishing"    # manifest/tag 的 PUT 已发出、响应未确认
DONE = "done"                # 服务端已确认（201 核对一致 / HEAD/GET 核对一致）

OBJECT_STATES = frozenset({PENDING, UPLOADING, COMPLETING, PUBLISHING, DONE})
TAG_STATES = frozenset({PENDING, PUBLISHING, DONE})

# 对象类别
KIND_BLOB = "blob"           # config / layer：走上传会话
KIND_MANIFEST = "manifest"   # 清单：PUT /manifests/<digest>，子先于父

_ENDPOINT_RE = re.compile(r"^https?://", re.IGNORECASE)
_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def normalize_endpoint(endpoint: str) -> str:
    """归一化目标服务地址：小写 scheme/host、显式端口、无尾斜杠。

    只允许 http/https 裸端点（可带端口，不带路径）；带路径、查询、
    用户信息的地址拒绝——Location 同源校验以归一化结果为准。
    """
    from urllib.parse import urlsplit
    if not isinstance(endpoint, str) or not _ENDPOINT_RE.match(endpoint):
        raise ProgressProblem(f"目标服务地址必须是 http(s)://host[:port]: "
                              f"{endpoint!r}")
    parts = urlsplit(endpoint)
    if parts.hostname is None:
        raise ProgressProblem(f"目标服务地址缺少主机名: {endpoint!r}")
    if parts.path not in ("", "/") or parts.query or parts.fragment:
        raise ProgressProblem(
            f"目标服务地址不应带路径/查询/片段: {endpoint!r}")
    if parts.username or parts.password:
        raise ProgressProblem("目标服务地址不应内嵌用户信息")
    scheme = parts.scheme.lower()
    host = parts.hostname.lower()
    try:
        port = parts.port
    except ValueError as exc:
        raise ProgressProblem(f"目标服务地址端口非法: {endpoint!r}") from exc
    default = 443 if scheme == "https" else 80
    if port is None or port == default:
        return f"{scheme}://{host}"
    return f"{scheme}://{host}:{port}"


def endpoint_origin(endpoint: str) -> tuple:
    """归一化端点的 (scheme, host, port)，用于 Location 同源校验。"""
    from urllib.parse import urlsplit
    parts = urlsplit(normalize_endpoint(endpoint))
    default = 443 if parts.scheme == "https" else 80
    return (parts.scheme, parts.hostname, parts.port or default)


@dataclass(frozen=True)
class Binding:
    """进度绑定的六元组：继续时任何一项冲突都在写请求前拒绝。"""

    store: str          # 源仓位置（绝对路径）
    name: str           # 保留名称（恢复时据此重新打开固定读者）
    root_digest: str    # 精确根（打开读者后必须逐字一致）
    endpoint: str       # 归一化目标服务地址
    repo: str           # 仓库路径
    tag: str            # 交付标签

    def to_dict(self) -> dict:
        return {"store": self.store, "name": self.name,
                "root_digest": self.root_digest, "endpoint": self.endpoint,
                "repo": self.repo, "tag": self.tag}

    @classmethod
    def from_dict(cls, node: object) -> "Binding":
        if not isinstance(node, dict):
            raise ProgressProblem("进度绑定必须是对象")
        try:
            store = node["store"]
            name = node["name"]
            root_digest = node["root_digest"]
            endpoint = node["endpoint"]
            repo = node["repo"]
            tag = node["tag"]
        except KeyError as exc:
            raise ProgressProblem(f"进度绑定缺少字段: {exc}") from exc
        for field_name, value in (("store", store), ("name", name),
                                  ("root_digest", root_digest),
                                  ("endpoint", endpoint), ("repo", repo),
                                  ("tag", tag)):
            if not isinstance(value, str) or not value:
                raise ProgressProblem(
                    f"进度绑定字段 {field_name} 必须是非空字符串")
        if not _SHA256_RE.match(root_digest):
            raise ProgressProblem(f"进度绑定的根 digest 非法: {root_digest!r}")
        return cls(store=store, name=name, root_digest=root_digest,
                   endpoint=endpoint, repo=repo, tag=tag)

    def conflicts(self, other: "Binding") -> list[str]:
        """逐项比较，返回冲突字段说明列表（空列表表示一致）。"""
        problems = []
        for field_name in ("store", "name", "root_digest", "endpoint",
                           "repo", "tag"):
            mine = getattr(self, field_name)
            theirs = getattr(other, field_name)
            if mine != theirs:
                problems.append(f"{field_name}: 进度={mine!r} 参数={theirs!r}")
        return problems


@dataclass
class ObjectEntry:
    """一个闭包对象的交付状态（blob 或 manifest）。"""

    digest: str
    kind: str
    media_type: str
    size: int
    state: str = PENDING
    location: Optional[str] = None   # 上传会话地址（含服务端查询参数）
    confirmed: int = 0               # 服务端已响应确认的前缀字节数

    def to_dict(self) -> dict:
        return {"digest": self.digest, "kind": self.kind,
                "media_type": self.media_type, "size": self.size,
                "state": self.state, "location": self.location,
                "confirmed": self.confirmed}

    @classmethod
    def from_dict(cls, digest: str, node: object) -> "ObjectEntry":
        if not isinstance(node, dict):
            raise ProgressProblem(f"对象 {digest} 的进度项必须是对象")
        try:
            kind = node["kind"]
            media_type = node["media_type"]
            size = node["size"]
            state = node["state"]
            location = node["location"]
            confirmed = node["confirmed"]
        except KeyError as exc:
            raise ProgressProblem(f"对象 {digest} 的进度项缺少字段: {exc}") \
                from exc
        if kind not in (KIND_BLOB, KIND_MANIFEST):
            raise ProgressProblem(f"对象 {digest} 的 kind 非法: {kind!r}")
        if not isinstance(media_type, str):
            raise ProgressProblem(f"对象 {digest} 的 media_type 非法")
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            raise ProgressProblem(f"对象 {digest} 的 size 非法: {size!r}")
        if state not in OBJECT_STATES:
            raise ProgressProblem(f"对象 {digest} 的 state 非法: {state!r}")
        if location is not None and not isinstance(location, str):
            raise ProgressProblem(f"对象 {digest} 的 location 非法")
        if (not isinstance(confirmed, int) or isinstance(confirmed, bool)
                or confirmed < 0 or confirmed > size):
            raise ProgressProblem(
                f"对象 {digest} 的 confirmed 非法: {confirmed!r}")
        return cls(digest=digest, kind=kind, media_type=media_type,
                   size=size, state=state, location=location,
                   confirmed=confirmed)


class Progress:
    """一份进度文件的内存视图；每次状态推进后立即 :meth:`save`。"""

    def __init__(self, path: str, binding: Binding,
                 objects: dict, manifest_order: list,
                 tag_state: str = PENDING, status: str = "in_progress",
                 created_at: Optional[str] = None):
        self.path = path
        self.binding = binding
        self.objects: dict[str, ObjectEntry] = objects
        self.manifest_order = list(manifest_order)
        self.tag_state = tag_state
        self.status = status
        self.created_at = created_at or _utcnow()

    # ------------------------------------------------------------------
    # 构造与加载
    # ------------------------------------------------------------------
    @staticmethod
    def peek_bound_root(path: str) -> Optional[str]:
        """读取已有进度绑定的根 digest；文件不存在返回 None。

        只解析绑定字段，用于在打开读者后先判断"源名称是否仍指向本次
        任务选定的根"；完整校验由 :meth:`load` 完成。损坏的进度在此
        同样拒绝（不覆盖、不新建）。
        """
        if not os.path.exists(path):
            return None
        try:
            with open(path, "rb") as fh:
                node = json.loads(fh.read().decode("utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ProgressProblem(
                f"进度文件损坏，拒绝覆盖: {path}: {exc}") from exc
        if not isinstance(node, dict) or node.get("format") != FORMAT:
            raise ProgressProblem(f"进度文件格式标识不符: "
                                  f"{node.get('format')!r}")
        binding = Binding.from_dict(node.get("binding"))
        return binding.root_digest

    @classmethod
    def create(cls, path: str, binding: Binding,
               closure: dict, manifest_order: list) -> "Progress":
        """按固定闭包建立新进度：全部对象 pending。"""
        objects = {}
        manifest_set = set(manifest_order)
        for digest, desc in closure.items():
            kind = KIND_MANIFEST if digest in manifest_set else KIND_BLOB
            objects[digest] = ObjectEntry(
                digest=digest, kind=kind, media_type=desc.media_type,
                size=desc.size)
        progress = cls(path=path, binding=binding, objects=objects,
                       manifest_order=manifest_order)
        progress.save()
        return progress

    @classmethod
    def load(cls, path: str, binding: Binding,
             closure: dict, manifest_order: list) -> "Progress":
        """加载已有进度并校验绑定与完整性。

        * 文件不存在：按新任务创建；
        * JSON 损坏 / 格式不符 / 结构缺字段 / 对象集合与闭包不一致：
          :class:`ProgressProblem`（损坏），不覆盖、不新建；
        * 绑定六元组任何一项冲突：:class:`ProgressProblem`（冲突），
          在发送任何写请求之前拒绝。
        """
        if not os.path.exists(path):
            return cls.create(path, binding, closure, manifest_order)
        try:
            with open(path, "rb") as fh:
                raw = fh.read()
        except OSError as exc:
            raise ProgressProblem(f"进度文件不可读: {path}: {exc}") from exc
        try:
            node = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ProgressProblem(
                f"进度文件损坏（不是合法 JSON），拒绝覆盖: {path}: {exc}"
            ) from exc
        if not isinstance(node, dict):
            raise ProgressProblem("进度文件损坏：顶层必须是对象")
        if node.get("format") != FORMAT:
            raise ProgressProblem(
                f"进度文件格式标识不符: {node.get('format')!r}")
        stored_binding = Binding.from_dict(node.get("binding"))
        conflicts = stored_binding.conflicts(binding)
        if conflicts:
            raise ProgressProblem(
                "进度绑定与本次参数冲突（在发送写请求前拒绝）: "
                + "; ".join(conflicts))
        order_node = node.get("manifest_order")
        if (not isinstance(order_node, list)
                or any(not isinstance(d, str) for d in order_node)):
            raise ProgressProblem("进度文件损坏：manifest_order 非法")
        if list(order_node) != list(manifest_order):
            raise ProgressProblem(
                "进度文件损坏：manifest_order 与固定闭包不一致")
        objects_node = node.get("objects")
        if not isinstance(objects_node, dict):
            raise ProgressProblem("进度文件损坏：objects 必须是对象")
        if set(objects_node) != set(closure):
            missing = sorted(set(closure) - set(objects_node))
            extra = sorted(set(objects_node) - set(closure))
            raise ProgressProblem(
                f"进度文件损坏：对象集合与固定闭包不一致"
                f"（缺 {len(missing)} 项、多 {len(extra)} 项）")
        objects = {}
        for digest, entry_node in objects_node.items():
            entry = ObjectEntry.from_dict(digest, entry_node)
            desc = closure[digest]
            if entry.size != desc.size or entry.media_type != desc.media_type:
                raise ProgressProblem(
                    f"进度文件损坏：对象 {digest} 的描述与固定闭包不一致")
            objects[digest] = entry
        tag_state = node.get("tag_state")
        if tag_state not in TAG_STATES:
            raise ProgressProblem(f"进度文件损坏：tag_state 非法: "
                                  f"{tag_state!r}")
        status = node.get("status")
        if status not in ("in_progress", "completed"):
            raise ProgressProblem(f"进度文件损坏：status 非法: {status!r}")
        created_at = node.get("created_at")
        if not isinstance(created_at, str):
            raise ProgressProblem("进度文件损坏：created_at 非法")
        return cls(path=path, binding=stored_binding, objects=objects,
                   manifest_order=list(order_node), tag_state=tag_state,
                   status=status, created_at=created_at)

    # ------------------------------------------------------------------
    # 落盘
    # ------------------------------------------------------------------
    def to_dict(self) -> dict:
        return {
            "format": FORMAT,
            "binding": self.binding.to_dict(),
            "status": self.status,
            "created_at": self.created_at,
            "updated_at": _utcnow(),
            "manifest_order": list(self.manifest_order),
            "objects": {digest: entry.to_dict()
                        for digest, entry in sorted(self.objects.items())},
            "tag_state": self.tag_state,
        }

    def save(self) -> None:
        """原子落盘：临时文件 + fsync + replace；绝不写出半份。"""
        payload = json.dumps(self.to_dict(), indent=2,
                             ensure_ascii=False, sort_keys=True).encode("utf-8")
        directory = os.path.dirname(os.path.abspath(self.path)) or "."
        os.makedirs(directory, exist_ok=True)
        tmp_path = self.path + ".tmp"
        fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(payload)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp_path, self.path)
        except BaseException:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise

    # ------------------------------------------------------------------
    # 汇总
    # ------------------------------------------------------------------
    def counts(self) -> dict:
        summary = {state: 0 for state in sorted(OBJECT_STATES)}
        for entry in self.objects.values():
            summary[entry.state] += 1
        return summary
