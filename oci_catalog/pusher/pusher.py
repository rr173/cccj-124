"""发布编排：从固定读者上下文取原字节，按依赖序送达远端仓库。

流程（一次 :func:`push` 调用）：

1. 打开源仓并以 ``open_reader(name)`` **固定**名称当时的根——本次运行
   只交付这个根；本机名称中途被更新不会让本次交付混入另一份镜像
   （读者上下文受对象仓保护）。恢复时名称不再指向进度绑定的根、或
   闭包字节已不可读，明确拒绝（:class:`SourceProblem`），不悄悄换根。
2. 加载/创建进度文件并校验绑定；任何冲突在发送写请求之前拒绝。
3. blob（config/layer，不透明原字节）逐个交付：HEAD 复用 → 上传会话
   分块 PATCH → PUT 完成。共享对象按 digest 只送一次。
4. manifest 按依赖序（子清单先于引用它的父索引，根最后）以**原内容
   类型和原字节** PUT 到 ``/v2/<name>/manifests/<digest>``——不重新
   序列化、不解包、不重压缩。
5. 全部清单就绪后，才把根原字节 PUT 到交付标签；此前任何失败都不会
   改动标签原有指向。

恢复对账（运行时重试与跨进程恢复共用同一条路径）：

* 每个非 done 对象都先问服务端事实再决定下一步：HEAD 对象、GET 上传
  会话、GET 清单。本地 ``confirmed`` 只是保守下界，**不能**直接代表
  远端事实；
* PATCH/PUT 响应丢失：下一轮循环先 GET 会话，以服务端确认的前缀继续
  ——合法前缀即使落在上次块内部，也从它后面接上，不重复拼入前缀、
  不跳掉剩余字节；
* PUT 完成响应丢失且会话 404：先 HEAD 对象，已存在即完成，不反复
  重传已完成对象；不存在才重开会话重传这个对象；
* 会话过期（GET 404）且对象不存在：新开会话重新发送这个对象；
* 清单/标签 PUT 回执丢失：GET 读回核对，已等于本次内容即完成；
* 错位块（416）：以响应携带的 Range/Location 校正后继续。

只处理选定闭包；失败时远端可能留下尚无交付标签引用的完整 blob 或
清单，本组件不尝试跨 HTTP 请求的整体回滚。
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from typing import Optional

from ..blobstore.layout import SourceError as LayoutSourceError
from ..blobstore.layout import parse_manifest
from ..blobstore.store import BlobStore, StoreError, UnknownNameError
from .client import PushHttpClient
from .errors import (AuthProblem, ProtocolProblem, PushError, RangeMismatch,
                     RetryExhausted, SessionGone, SourceProblem,
                     TransientProblem)
from .progress import (COMPLETING, DONE, KIND_BLOB, PENDING, PUBLISHING,
                       UPLOADING, Binding, Progress, normalize_endpoint)

DEFAULT_CHUNK_SIZE = 1024 * 1024
DEFAULT_MAX_ATTEMPTS = 3
DEFAULT_TIMEOUT = 10.0
DEFAULT_BACKOFF = 0.2

STATUS_COMPLETED = "completed"
STATUS_IN_PROGRESS = "in_progress"


@dataclass(frozen=True)
class PushConfig:
    """一次交付命令的全部参数。"""

    store_path: str          # 源仓位置
    name: str                # 保留名称
    endpoint: str            # 目标服务地址
    repo: str                # 仓库路径
    tag: str                 # 交付标签
    progress_path: str       # 进度文件路径
    token: Optional[str] = None        # 固定 Bearer token
    chunk_size: int = DEFAULT_CHUNK_SIZE
    max_attempts: int = DEFAULT_MAX_ATTEMPTS
    timeout: float = DEFAULT_TIMEOUT
    backoff: float = DEFAULT_BACKOFF

    def validate(self) -> None:
        if self.chunk_size <= 0:
            raise SourceProblem("chunk_size 必须为正整数")
        if self.max_attempts <= 0:
            raise SourceProblem("max_attempts 必须为正整数")
        if self.timeout <= 0:
            raise SourceProblem("timeout 必须为正数")
        if not self.name or not self.name.strip():
            raise SourceProblem("保留名称不能为空")
        if not self.repo or self.repo != self.repo.strip() \
                or self.repo.startswith("/") or self.repo.endswith("/") \
                or "//" in self.repo:
            raise SourceProblem(f"仓库路径非法: {self.repo!r}")
        if not self.tag or self.tag != self.tag.strip() or ":" in self.tag \
                or "/" in self.tag:
            raise SourceProblem(f"交付标签非法: {self.tag!r}")
        normalize_endpoint(self.endpoint)  # 非法端点在此拒绝


@dataclass
class PushResult:
    """一次命令的结局（成功或待继续；不可继续的错误以异常抛出）。"""

    status: str              # completed | in_progress
    root_digest: str
    repo: str
    tag: str
    progress_path: str
    counts: dict = field(default_factory=dict)
    bytes_sent: int = 0      # 本次运行实际经 PATCH 发送的字节数
    message: str = ""

    def to_dict(self) -> dict:
        return {"status": self.status, "root_digest": self.root_digest,
                "repo": self.repo, "tag": self.tag,
                "progress_path": self.progress_path, "counts": self.counts,
                "bytes_sent": self.bytes_sent, "message": self.message}


class _Engine:
    """单个根闭包的交付状态机（运行时重试与跨进程恢复共用）。"""

    def __init__(self, reader, client: PushHttpClient, progress: Progress,
                 config: PushConfig):
        self.reader = reader
        self.client = client
        self.progress = progress
        self.config = config
        self.repo = progress.binding.repo
        self.attempts = 0
        self.bytes_sent = 0

    # -- 有限尝试 -------------------------------------------------------
    # 额度统计**连续未获确认的写尝试**（含对账读的失败）：任何写步骤被
    # 服务端完整确认（会话建立、块被确认、PUT 完成、对象/清单/标签经
    # 核对已在远端）才清零；对账读（HEAD/GET）成功不清零——它只说明
    # 网络可达，不说明上次写被接受。额度用尽抛 RetryExhausted。
    def _confirmed(self) -> None:
        self.attempts = 0

    def _transient(self, exc: BaseException) -> None:
        self.attempts += 1
        if self.attempts >= self.config.max_attempts:
            raise RetryExhausted(
                f"连续 {self.attempts} 次可重试失败，额度用尽；"
                f"进度已保存，带同一进度文件重跑即可继续: {exc}") from exc
        time.sleep(self.config.backoff)

    # -- 有界读取：从固定闭包按偏移取一段 -------------------------------
    def _read_at(self, digest: str, offset: int, length: int) -> bytes:
        """读取闭包对象的 [offset, offset+length) 段（内存有界）。

        逐块跳过前缀，不把整层读入内存；字节缺失/长度不符说明源仓在
        两次命令之间被回收，明确拒绝（不悄悄换根）。
        """
        buf = bytearray()
        pos = 0
        try:
            for chunk in self.reader.read_chunks(digest,
                                                 self.config.chunk_size):
                if pos + len(chunk) <= offset:
                    pos += len(chunk)
                    continue
                start = max(0, offset - pos)
                piece = chunk[start:start + (length - len(buf))]
                buf += piece
                pos += len(chunk)
                if len(buf) >= length:
                    break
        except StoreError as exc:
            raise SourceProblem(
                f"源仓对象 {digest} 的字节已不可读，拒绝继续: {exc}") from exc
        if len(buf) != length:
            raise SourceProblem(
                f"源仓对象 {digest} 只能读到 {len(buf)}/{length} 字节"
                f"（偏移 {offset}），闭包已不完整，拒绝继续")
        return bytes(buf)

    # -- blob 状态机 ----------------------------------------------------
    def _push_blob(self, digest: str) -> None:
        entry = self.progress.objects[digest]
        if entry.state == DONE:
            return
        size = entry.size
        while True:
            # 1) 远端已有该对象？（复用，或上次 PUT 成功但回执丢失）
            try:
                head = self.client.head_blob(self.repo, digest, size)
            except TransientProblem as exc:
                self._transient(exc)
                continue
            if head is not None:
                entry.state = DONE
                entry.location = None
                entry.confirmed = size
                self.progress.save()
                self._confirmed()
                return
            # 2) 没有会话则新开会话
            if entry.location is None:
                try:
                    entry.location = self.client.start_upload(self.repo)
                except TransientProblem as exc:
                    self._transient(exc)
                    continue
                entry.confirmed = 0
                entry.state = UPLOADING
                self.progress.save()
                self._confirmed()
            # 3) 对账：以服务端确认的前缀为准（不按本地记住的字节数）
            try:
                status = self.client.get_upload(entry.location, size)
            except TransientProblem as exc:
                self._transient(exc)
                continue
            if status is None:
                # 会话过期且对象不存在：重开会话重新发送这个对象；
                # 反复过期说明服务端不稳定，计入尝试额度防死循环
                entry.location = None
                entry.confirmed = 0
                entry.state = UPLOADING
                self.progress.save()
                self._transient(SessionGone(digest))
                continue
            if status.location:
                entry.location = status.location
            if status.offset != entry.confirmed:
                entry.confirmed = status.offset
            self.progress.save()
            # 4) 还有字节要发：从服务端确认的前缀后面接上
            if entry.confirmed < size:
                length = min(self.config.chunk_size, size - entry.confirmed)
                chunk = self._read_at(digest, entry.confirmed, length)
                try:
                    ack = self.client.patch_chunk(
                        entry.location, entry.confirmed, chunk, size)
                except RangeMismatch as mismatch:
                    # 416 对账：以响应携带的 Range/Location 校正；
                    # 无进展计入额度防死循环
                    progressed = mismatch.offset > entry.confirmed
                    entry.confirmed = mismatch.offset
                    if mismatch.location:
                        entry.location = mismatch.location
                    self.progress.save()
                    if not progressed:
                        self._transient(mismatch)
                    continue
                except SessionGone:
                    entry.location = None
                    entry.confirmed = 0
                    self.progress.save()
                    self._transient(SessionGone(digest))
                    continue
                except TransientProblem as exc:
                    # 块可能已落在服务端而响应丢失：下一轮先对账
                    self._transient(exc)
                    continue
                entry.confirmed = ack.offset
                if ack.location:
                    entry.location = ack.location
                self.bytes_sent += len(chunk)
                self.progress.save()
                self._confirmed()
                continue
            # 5) 前缀已完整：PUT 完成（发出前落盘 completing）
            entry.state = COMPLETING
            self.progress.save()
            try:
                self.client.complete_upload(entry.location, digest)
            except SessionGone:
                # 完成请求结果未知且会话已不在：下一轮 HEAD 核对对象
                entry.location = None
                self.progress.save()
                self._transient(SessionGone(digest))
                continue
            except TransientProblem as exc:
                # 完成回执丢失：下一轮 HEAD/GET 对账，不直接判失败
                self._transient(exc)
                continue
            entry.state = DONE
            entry.location = None
            entry.confirmed = size
            self.progress.save()
            self._confirmed()
            return

    # -- manifest 状态机（子先于父，原字节不重新序列化） -----------------
    def _push_manifest(self, digest: str) -> None:
        entry = self.progress.objects[digest]
        if entry.state == DONE:
            return
        try:
            raw = self.reader.read_all(digest)
        except StoreError as exc:
            raise SourceProblem(
                f"源仓清单 {digest} 的字节已不可读，拒绝继续: {exc}") from exc
        while True:
            # 对账：上次 PUT 可能已成功而回执丢失
            try:
                got = self.client.get_manifest(self.repo, digest)
            except TransientProblem as exc:
                self._transient(exc)
                continue
            if got is not None:
                served_raw, served_digest = got
                if served_digest != digest or served_raw != raw:
                    raise ProtocolProblem(
                        f"远端清单 {digest} 与本地内容不一致，拒绝继续")
                entry.state = DONE
                self.progress.save()
                self._confirmed()
                return
            entry.state = PUBLISHING     # PUT 发出前落盘
            self.progress.save()
            try:
                self.client.put_manifest(self.repo, digest,
                                         entry.media_type, raw)
            except TransientProblem as exc:
                self._transient(exc)
                continue
            entry.state = DONE
            self.progress.save()
            self._confirmed()
            return

    # -- 交付标签：最后一步；此前失败绝不动标签 --------------------------
    def _publish_tag(self) -> None:
        if self.progress.tag_state == DONE:
            return
        root_digest = self.progress.binding.root_digest
        tag = self.progress.binding.tag
        entry = self.progress.objects[root_digest]
        try:
            raw = self.reader.read_all(root_digest)
        except StoreError as exc:
            raise SourceProblem(
                f"源仓根 {root_digest} 的字节已不可读，拒绝继续: {exc}"
            ) from exc
        while True:
            # 先核对标签现状：上次 PUT 可能已改成功但回执丢失
            try:
                got = self.client.get_manifest(self.repo, tag)
            except TransientProblem as exc:
                self._transient(exc)
                continue
            if got is not None and got[1] == root_digest and got[0] == raw:
                self.progress.tag_state = DONE
                self.progress.save()
                self._confirmed()
                return
            self.progress.tag_state = PUBLISHING   # PUT 发出前落盘
            self.progress.save()
            try:
                self.client.put_manifest(self.repo, tag,
                                         entry.media_type, raw)
            except TransientProblem as exc:
                self._transient(exc)
                continue
            self.progress.tag_state = DONE
            self.progress.save()
            self._confirmed()
            return

    # -- 总流程 ----------------------------------------------------------
    def run(self) -> None:
        blobs = sorted(digest for digest, entry in self.progress.objects.items()
                       if entry.kind == KIND_BLOB)
        for digest in blobs:
            self._push_blob(digest)
        for digest in self.progress.manifest_order:
            self._push_manifest(digest)
        self._publish_tag()
        self.progress.status = STATUS_COMPLETED
        self.progress.save()


def _manifest_order(reader, root_digest: str) -> list:
    """从根沿描述符 DFS：子清单先于引用它的父索引（支持嵌套索引）。

    清单原字节经 ``parse_manifest`` 重新校验（摘要一致、结构合法），
    但推送时只用原字节，绝不重新序列化。
    """
    order: list = []
    seen: set = set()

    def visit(digest: str) -> None:
        if digest in seen:
            return
        seen.add(digest)
        try:
            raw = reader.read_all(digest)
        except StoreError as exc:
            raise SourceProblem(
                f"源仓清单 {digest} 的字节已不可读，拒绝继续: {exc}") from exc
        try:
            parsed = parse_manifest(raw, digest)
        except LayoutSourceError as exc:
            raise SourceProblem(f"源仓清单 {digest} 无法解析: {exc}") from exc
        for child in parsed.children:
            visit(child.digest)
        order.append(digest)

    visit(root_digest)
    return order


def push(config: PushConfig) -> PushResult:
    """执行一次交付命令；可中断后继续。

    * 成功：返回 ``status == "completed"`` 的 :class:`PushResult`；
    * 待继续：可重试故障额度用尽，抛 :class:`RetryExhausted`（进度已
      保存，带同一进度文件与同一组参数重跑即可继续）；
    * 不可继续：:class:`SourceProblem` / :class:`ProgressProblem` /
      :class:`ProtocolProblem`（含 :class:`AuthProblem`）。
    """
    config.validate()
    store = BlobStore(config.store_path)
    try:
        try:
            reader = store.open_reader(config.name)
        except UnknownNameError as exc:
            raise SourceProblem(
                f"源仓中没有保留名称 {config.name!r}，无法交付: {exc}"
            ) from exc
        except StoreError as exc:
            raise SourceProblem(f"源仓闭包不可读，拒绝交付: {exc}") from exc
        with reader:
            root = reader.root
            # 源保护：已有进度时，名称必须仍指向本次任务最初选定的根；
            # 进程间隔中名称被更新/删除都明确拒绝，不悄悄换用新根
            bound_root = Progress.peek_bound_root(config.progress_path)
            if bound_root is not None and bound_root != root.digest:
                raise SourceProblem(
                    f"源名称 {config.name!r} 现在指向 {root.digest}，"
                    f"与进度绑定的根 {bound_root} 不一致；拒绝继续"
                    f"（不悄悄换用新根）")
            binding = Binding(
                store=os.path.abspath(config.store_path),
                name=config.name,
                root_digest=root.digest,
                endpoint=normalize_endpoint(config.endpoint),
                repo=config.repo,
                tag=config.tag)
            closure = {desc.digest: desc for desc in reader.objects()}
            manifest_order = _manifest_order(reader, root.digest)
            # 绑定校验/损坏检查都在发送任何写请求之前完成
            progress = Progress.load(config.progress_path, binding,
                                     closure, manifest_order)
            client = PushHttpClient(config.endpoint, token=config.token,
                                    timeout=config.timeout)
            engine = _Engine(reader, client, progress, config)
            engine.run()
            return PushResult(
                status=STATUS_COMPLETED,
                root_digest=root.digest,
                repo=config.repo,
                tag=config.tag,
                progress_path=config.progress_path,
                counts=progress.counts(),
                bytes_sent=engine.bytes_sent,
                message=f"交付标签 {config.tag} 已确认指向 {root.digest}")
    finally:
        store.close()
