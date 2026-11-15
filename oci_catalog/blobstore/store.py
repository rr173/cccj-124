"""本机共享 OCI 原始对象仓：导入闭包、命名保留、固定读取与两阶段回收。

目录布局（``root`` 由调用者指定，所有内容都在同一文件系统内）::

    root/
        store.db                  # 元数据（SQLite，WAL）
        blobs/sha256/<前2位>/<hex># 原始对象（普通文件，按校验过的 digest 命名）
        staging/<import_id>/      # 未发布暂存字节
        staging/<import_id>.lock  # 导入暂存锁（导入全程持有）
        trash/<uuid>              # 删除中的对象（重启恢复用）
        locks/publish.lock        # 发布/回收协调锁
        readers/<reader_id>.lock  # 读者保护锁（读者全程持有）

协调与恢复（详见 ``README.md``）：

* 导入把所有闭包对象**逐块复制**进暂存目录并核对长度/摘要；任何诊断都
  整体失败，不移动、不绑定名称、不改动原目录。
* 发布在 ``locks/publish.lock`` 下进行：先把暂存对象原子改名进 ``blobs``，
  再在**一个 SQLite 事务**里登记对象、manifest 边、闭包与名称。可见名称
  绝不会指向半份内容；崩溃只可能留下无元数据的孤儿文件（重启时按
  ``objects`` 表核对后清理）。
* 读者在打开上下文时短暂持有发布锁，登记 reader 行并取得 reader 锁；
  之后读取期间不再持有发布锁，因此其他进程仍可发布无关引用、规划空间、
  回收不受保护对象。reader 锁由内核在进程退出（含 SIGKILL）时释放，
  回收据此辨认死亡读者，不靠固定超时。
* 回收计划保存候选清单；应用时在发布锁下重新检查引用与读者，逐项记录
  ``deleted`` / ``already_deleted`` / ``skipped``，因此中途退出后重跑同一
  清单能如实区分三种情况。

本模块只处理原始字节的共享存储与生命周期：不运行镜像、不联网、不解析
tar 文件树、不分析软件清单，也不读写其他既有数据库。
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Iterator, Optional

from .layout import (
    DIGEST_MISMATCH,
    OCI_IMAGE_INDEX,
    OCI_IMAGE_MANIFEST,
    SIZE_MISMATCH,
    Diagnostic,
    Descriptor,
    ParsedManifest,
    SourceError,
    is_sha256,
    parse_manifest,
    read_layout_root,
)
from .locking import FileLock, lock_is_held, process_alive, process_identity

DEFAULT_CHUNK_SIZE = 1024 * 1024

# 导入结果状态
IMPORTED = "imported"
FAILED = "failed"

# 名称操作结果
NAME_SET = "set"
NAME_REPLACED = "replaced"
NAME_DELETED = "deleted"
NAME_NOT_FOUND = "not_found"

# 回收项结果
GC_DELETED = "deleted"
GC_ALREADY_DELETED = "already_deleted"
GC_SKIPPED = "skipped"

# 读者/仓库状态
READER_ACTIVE = "active"
READER_CLOSED = "closed"
READER_EXITED = "exited"   # 进程已终止，保护在下次回收时释放

# 仓库一致性异常（回收前必须报告，不得当成“没有引用”）
REPO_OK = "ok"
REPO_CORRUPT = "corrupt"

SCHEMA = """
-- 对象：按 sha256 唯一；physical 字节长度在接收时核对
CREATE TABLE IF NOT EXISTS objects (
    digest       TEXT PRIMARY KEY,
    size         INTEGER NOT NULL,
    blob_relpath TEXT NOT NULL UNIQUE,
    created_at   TEXT NOT NULL
);

-- manifest 元数据（原始字节也作为对象保存；这里记录结构类型）
CREATE TABLE IF NOT EXISTS manifests (
    digest     TEXT PRIMARY KEY REFERENCES objects(digest),
    media_type TEXT NOT NULL,
    kind       TEXT NOT NULL              -- index | image
);

-- manifest 对子对象的边（image 的 config/layers，index 的 children）
CREATE TABLE IF NOT EXISTS manifest_edges (
    parent_digest TEXT NOT NULL REFERENCES manifests(digest),
    position      INTEGER NOT NULL,
    role          TEXT NOT NULL,          -- config | layer | child
    child_digest  TEXT NOT NULL REFERENCES objects(digest),
    media_type    TEXT NOT NULL,
    size          INTEGER NOT NULL,
    PRIMARY KEY (parent_digest, position)
);
CREATE INDEX IF NOT EXISTS idx_edges_child ON manifest_edges(child_digest);

-- 完整闭包：一个根 manifest 及其沿描述符可达的全部对象
CREATE TABLE IF NOT EXISTS closures (
    closure_id   INTEGER PRIMARY KEY AUTOINCREMENT,
    root_digest  TEXT NOT NULL UNIQUE REFERENCES manifests(digest),
    created_at   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS closure_objects (
    closure_id INTEGER NOT NULL REFERENCES closures(closure_id)
                   ON DELETE CASCADE,
    digest     TEXT NOT NULL REFERENCES objects(digest),
    role       TEXT NOT NULL,             -- root | manifest | config | layer
    PRIMARY KEY (closure_id, digest)
);

-- 保留名称：多对一指向根 manifest；改指向或删除不改原对象
CREATE TABLE IF NOT EXISTS refs (
    name        TEXT PRIMARY KEY,
    root_digest TEXT NOT NULL REFERENCES closures(root_digest),
    updated_at  TEXT NOT NULL
);

-- 读者：可见性快照 + 保护期
CREATE TABLE IF NOT EXISTS readers (
    reader_id    TEXT PRIMARY KEY,
    root_digest  TEXT NOT NULL,
    status       TEXT NOT NULL,           -- active | closed | exited
    pid          INTEGER NOT NULL,
    proc_start   TEXT NOT NULL,
    boot_id      TEXT NOT NULL,
    opened_at    TEXT NOT NULL,
    closed_at    TEXT
);

-- 回收计划（候选清单）与逐项应用结果
CREATE TABLE IF NOT EXISTS gc_plans (
    plan_id       TEXT PRIMARY KEY,
    created_at    TEXT NOT NULL,
    unique_bytes  INTEGER NOT NULL,
    object_count  INTEGER NOT NULL,
    candidates_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS gc_plan_objects (
    plan_id  TEXT NOT NULL REFERENCES gc_plans(plan_id),
    digest   TEXT NOT NULL,
    size     INTEGER NOT NULL,
    staged_relpath TEXT,                  -- 未发布暂存对象才有
    orphan_relpath TEXT,                  -- 发布残留孤儿才有
    PRIMARY KEY (plan_id, digest)
);

CREATE TABLE IF NOT EXISTS gc_runs (
    run_id     TEXT PRIMARY KEY,
    plan_id    TEXT NOT NULL REFERENCES gc_plans(plan_id),
    applied_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS gc_items (
    run_id    TEXT NOT NULL REFERENCES gc_runs(run_id),
    digest    TEXT NOT NULL,
    outcome   TEXT NOT NULL,              -- deleted | already_deleted | skipped
    reason    TEXT NOT NULL,
    PRIMARY KEY (run_id, digest)
);

-- 失败的导入（只留诊断，不产生名称或可见内容）
CREATE TABLE IF NOT EXISTS import_failures (
    failure_id  INTEGER PRIMARY KEY AUTOINCREMENT,
    source_path TEXT NOT NULL,
    failed_at   TEXT NOT NULL,
    diagnostics_json TEXT NOT NULL
);
"""


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


class StoreError(ValueError):
    """对象仓状态异常或操作参数非法。"""


class UnknownNameError(KeyError):
    """名称不存在。"""


class UnknownPlanError(KeyError):
    """回收计划不存在。"""


class ClosedReaderError(RuntimeError):
    """读取上下文已关闭。"""


@dataclass
class ImportResult:
    status: str
    root_digest: Optional[str] = None
    closure_id: Optional[int] = None
    objects_added: int = 0
    objects_existing: int = 0
    bytes_added: int = 0
    name: Optional[str] = None
    name_status: Optional[str] = None
    diagnostics: list[Diagnostic] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.status == IMPORTED

    def to_dict(self) -> dict:
        return {
            "status": self.status,
            "root_digest": self.root_digest,
            "closure_id": self.closure_id,
            "objects_added": self.objects_added,
            "objects_existing": self.objects_existing,
            "bytes_added": self.bytes_added,
            "name": self.name,
            "name_status": self.name_status,
            "diagnostics": [d.to_dict() for d in self.diagnostics],
        }


@dataclass
class RefInfo:
    name: str
    root: Descriptor
    updated_at: str

    def to_dict(self) -> dict:
        return {"name": self.name, "root": self.root.to_dict(),
                "updated_at": self.updated_at}


@dataclass
class GcPlan:
    plan_id: str
    created_at: str
    candidates: list[dict]
    unique_bytes: int
    skipped_missing: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"plan_id": self.plan_id, "created_at": self.created_at,
                "object_count": len(self.candidates),
                "unique_bytes": self.unique_bytes,
                "candidates": self.candidates,
                "skipped_missing": self.skipped_missing}


@dataclass
class GcRun:
    run_id: str
    plan_id: str
    applied_at: str
    items: list[dict]
    freed_bytes: int

    def to_dict(self) -> dict:
        summary = {GC_DELETED: 0, GC_ALREADY_DELETED: 0, GC_SKIPPED: 0}
        for item in self.items:
            summary[item["outcome"]] = summary.get(item["outcome"], 0) + 1
        return {"run_id": self.run_id, "plan_id": self.plan_id,
                "applied_at": self.applied_at, "freed_bytes": self.freed_bytes,
                "summary": summary, "items": self.items}


def _digest_hex(digest: str) -> str:
    return digest.split(":", 1)[1]


def _file_size(path: str) -> int:
    return os.lstat(path).st_size


def _copy_verified(src: str, dst: str, expected_digest: str,
                   expected_size: int, chunk_size: int) -> None:
    """逐块复制并同时核对长度与摘要；不把整个对象读入内存。

    复制完成后 fsync 目标文件，返回时目标字节已落盘。任何不符都抛出
    SourceError，调用者负责清理暂存目录。
    """
    hasher = hashlib.sha256()
    written = 0
    fd = os.open(dst, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    with open(src, "rb") as fin, os.fdopen(fd, "wb") as fout:
        while True:
            chunk = fin.read(chunk_size)
            if not chunk:
                break
            written += len(chunk)
            hasher.update(chunk)
            fout.write(chunk)
        fout.flush()
        os.fsync(fout.fileno())
    if written != expected_size:
        raise SourceError(
            f"{src}: 实际长度 {written} 与描述 size {expected_size} 不符",
            code=SIZE_MISMATCH)
    actual = "sha256:" + hasher.hexdigest()
    if actual != expected_digest:
        raise SourceError(
            f"{src}: 实际摘要 {actual} 与描述 digest {expected_digest} 不符",
            code=DIGEST_MISMATCH)


def _link_count(path: str) -> int:
    try:
        return os.stat(path).st_nlink
    except OSError:
        return 0


class BlobStore:
    """本机共享 OCI 原始对象仓（元数据独立 SQLite + 对象普通文件）。

    一个进程可以同时打开同一目录下的多个 :class:`BlobStore`；可见性由
    SQLite 事务与文件锁协调，见模块文档。
    """

    def __init__(self, root: str, chunk_size: int = DEFAULT_CHUNK_SIZE):
        if chunk_size <= 0:
            raise StoreError("chunk_size 必须为正整数")
        self.root = os.path.abspath(root)
        self.chunk_size = chunk_size
        self.db_path = os.path.join(self.root, "store.db")
        self.blobs_dir = os.path.join(self.root, "blobs")
        self.staging_dir = os.path.join(self.root, "staging")
        self.trash_dir = os.path.join(self.root, "trash")
        self.readers_dir = os.path.join(self.root, "readers")
        self.locks_dir = os.path.join(self.root, "locks")
        for path in (self.blobs_dir, self.staging_dir, self.trash_dir,
                     self.readers_dir, self.locks_dir):
            os.makedirs(path, exist_ok=True)
        self.conn = sqlite3.connect(self.db_path, timeout=30)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.execute("PRAGMA journal_mode = WAL")
        self.conn.execute("PRAGMA synchronous = FULL")
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    # ------------------------------------------------------------------
    # 基础
    # ------------------------------------------------------------------
    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> "BlobStore":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def blob_path(self, digest: str) -> str:
        if not is_sha256(digest):
            raise StoreError(f"非法 sha256 digest: {digest!r}")
        hexpart = _digest_hex(digest)
        return os.path.join(self.blobs_dir, "sha256", hexpart[:2], hexpart)

    @property
    def publish_lock_path(self) -> str:
        return os.path.join(self.locks_dir, "publish.lock")

    def _publish_lock(self) -> FileLock:
        return FileLock(self.publish_lock_path)

    def _reader_lock_path(self, reader_id: str) -> str:
        return os.path.join(self.readers_dir, f"{reader_id}.lock")

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        """写事务：显式 BEGIN IMMEDIATE，异常回滚。"""
        try:
            self.conn.execute("BEGIN IMMEDIATE")
            yield self.conn
        except BaseException:
            self.conn.rollback()
            raise
        else:
            self.conn.commit()
    # ------------------------------------------------------------------
    # 导入：沿描述符展开闭包，完整核验后原子发布
    # ------------------------------------------------------------------
    def import_layout(self, layout_dir: str, root_digest: str,
                      name: Optional[str] = None) -> ImportResult:
        """把本地 OCI Image Layout 的一个根闭包纳入对象仓。

        * 只接受 image manifest 或可递归展开的 image index；
        * 沿描述符走完根、子 manifest、config 与 layer 闭包；
        * manifest 保持输入原字节，config/layer 当不透明字节；
        * 每份对象逐块复制进暂存目录，核对真实长度与 sha256；
        * 全部成功后才发布：先移动字节，再单事务登记闭包与名称。
          失败不产生名称、不留下可见内容，原有同名引用仍可用；
        * 名称若已存在且指向不同根，按“明确替换”更新；同名同根幂等。
        """
        import_id = uuid.uuid4().hex
        staging = os.path.join(self.staging_dir, import_id)
        # 先取得暂存锁再创建目录：回收据此能区分“正在导入”与“崩溃残留”
        staging_lock = FileLock(os.path.join(self.staging_dir,
                                             f"{import_id}.lock"))
        staging_lock.acquire()
        os.makedirs(staging)
        try:
            return self._import_into_staging(
                layout_dir, root_digest, name, staging)
        finally:
            staging_lock.release()
            shutil.rmtree(staging, ignore_errors=True)
            try:
                os.unlink(os.path.join(self.staging_dir,
                                       f"{import_id}.lock"))
            except OSError:
                pass

    def _import_into_staging(self, layout_dir: str, root_digest: str,
                             name: Optional[str],
                             staging: str) -> ImportResult:
        diagnostics: list[Diagnostic] = []

        def fail() -> ImportResult:
            return self._record_failure(layout_dir, diagnostics)

        if not is_sha256(root_digest):
            diagnostics.append(Diagnostic(
                "invalid_digest",
                f"根 manifest 必须是 'sha256:' + 64 位小写十六进制: "
                f"{root_digest!r}"))
            return fail()
        if name is not None and (not isinstance(name, str)
                                 or not name.strip()
                                 or name != name.strip()):
            diagnostics.append(Diagnostic(
                "invalid_name",
                f"保留名称必须是非空且无首尾空白的字符串: {name!r}"))
            return fail()

        try:
            layout = read_layout_root(layout_dir, root_digest)
        except SourceError as exc:
            diagnostics.append(Diagnostic(exc.code, str(exc),
                                          location=exc.location))
            return fail()
        layout_dir = layout.layout_dir

        # -- 1. 沿描述符展开闭包（只读输入目录，记录声明） ---------------
        manifests, declared_media, declared_size = self._walk_closure(
            layout_dir, root_digest, layout.root, diagnostics)
        if diagnostics:
            return fail()

        # -- 2. 全部对象逐块复制进暂存目录，同时再次核验 -------------------
        staged: dict[str, tuple[int, str, str]] = {}  # digest -> (size, rel, role)
        staged_paths: dict[str, str] = {}
        expected_objects: dict[str, tuple[str, str, int, str]] = {}
        expected_objects[root_digest] = (
            layout.root.media_type, "manifest", layout.root.size, "root")
        for parsed in manifests.values():
            kids: list[tuple[Descriptor, str]] = []
            if parsed.config is not None:
                kids.append((parsed.config, "config"))
            kids += [(d, "layer") for d in parsed.layers]
            kids += [(d, "child") for d in parsed.children]
            for desc, role in kids:
                if role == "child":
                    role = "manifest"
                if desc.digest in expected_objects:
                    continue
                expected_objects[desc.digest] = (
                    desc.media_type, role, desc.size, "")
        for digest in sorted(expected_objects):
            media, role, size, _ = expected_objects[digest]
            src = os.path.join(layout_dir, "blobs", "sha256",
                               _digest_hex(digest))
            rel = os.path.join("sha256", _digest_hex(digest)[:2],
                               _digest_hex(digest))
            dst = os.path.join(staging, rel)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            try:
                _copy_verified(src, dst, digest, size, self.chunk_size)
            except (SourceError, OSError) as exc:
                code = getattr(exc, "code", "unreadable_source")
                diagnostics.append(Diagnostic(
                    code, str(exc), manifest=digest))
                continue
            staged[digest] = (size, rel, role)
            staged_paths[digest] = dst

        # manifest 原始字节必须与输入完全一致，发布时就地取暂存文件
        if diagnostics:
            return fail()

        # -- 3. 发布：先移动字节，再单事务登记 ---------------------------
        try:
            with self._publish_lock():
                outcome = self._publish_closure(
                    staged, staged_paths, manifests, expected_objects,
                    root_digest, name)
        except OSError as exc:
            diagnostics.append(Diagnostic(
                "publish_failed", f"发布对象字节失败: {exc}",
                manifest=root_digest))
            return fail()

        return ImportResult(
            status=IMPORTED, root_digest=root_digest,
            closure_id=outcome["closure_id"],
            objects_added=outcome["added"], objects_existing=outcome["existing"],
            bytes_added=outcome["added_bytes"], name=name,
            name_status=outcome["name_status"])

    def _walk_closure(self, layout_dir: str, root_digest: str,
                      root: Descriptor, diagnostics: list[Diagnostic]
                      ) -> tuple[dict[str, ParsedManifest], dict[str, str],
                                 dict[str, int]]:
        """沿描述符展开一个根的闭包（只读），并核对每个 manifest 的真实字节。

        只把声明为 manifest 的对象按 JSON 解析；config/layer 当不透明字节，
        但仍在此处核验长度与摘要。缺失对象、坏长度、坏摘要、不支持的
        manifest 类型、重复键、同摘要矛盾描述都追加到 ``diagnostics``。
        """
        declared_media: dict[str, str] = {root_digest: root.media_type}
        declared_size: dict[str, int] = {root_digest: root.size}
        manifests: dict[str, ParsedManifest] = {}
        pending: list[str] = [root_digest]
        while pending:
            digest = pending.pop(0)
            if digest in manifests:
                continue
            src = os.path.join(layout_dir, "blobs", "sha256",
                               _digest_hex(digest))
            expected_size = declared_size[digest]
            try:
                actual_size = _file_size(src)
            except OSError as exc:
                diagnostics.append(Diagnostic(
                    "missing_object", f"闭包对象缺失: {src}: {exc}",
                    manifest=digest))
                continue
            if actual_size != expected_size:
                diagnostics.append(Diagnostic(
                    "size_mismatch",
                    f"{src}: 实际长度 {actual_size} 与描述 size "
                    f"{expected_size} 不符", manifest=digest))
                continue

            declared = declared_media.get(digest, "")
            expects_manifest = (digest == root_digest
                                or declared in (OCI_IMAGE_MANIFEST,
                                                OCI_IMAGE_INDEX))
            if not expects_manifest:
                # config/layer：不透明字节。这里只看存在与长度；完整
                # 摘要校验在逐块复制时对实际字节做，不依赖目录条目。
                continue
            try:
                with open(src, "rb") as fh:
                    raw = fh.read()
            except OSError as exc:
                diagnostics.append(Diagnostic(
                    "unreadable_source", f"无法读取 {src}: {exc}",
                    manifest=digest))
                continue
            actual = "sha256:" + hashlib.sha256(raw).hexdigest()
            if actual != digest:
                diagnostics.append(Diagnostic(
                    "digest_mismatch",
                    f"{src}: 实际摘要 {actual} 与描述 digest {digest} 不符",
                    manifest=digest))
                continue
            try:
                parsed = parse_manifest(raw, digest)
            except SourceError as exc:
                diagnostics.append(Diagnostic(
                    exc.code, str(exc), manifest=digest,
                    location=exc.location))
                continue
            if parsed.media_type != declared:
                diagnostics.append(Diagnostic(
                    "descriptor_media_mismatch",
                    f"{digest}: 描述 mediaType {declared!r} 与文档内 "
                    f"{parsed.media_type!r} 不一致", manifest=digest))
                continue
            manifests[digest] = parsed
            children = list(parsed.children)
            if parsed.config is not None:
                children.append(parsed.config)
            children.extend(parsed.layers)
            for child in children:
                old_media = declared_media.get(child.digest)
                old_size = declared_size.get(child.digest)
                if old_media is not None:
                    if (old_media != child.media_type
                            or old_size != child.size):
                        diagnostics.append(Diagnostic(
                            "conflicting_descriptor",
                            f"{child.digest} 在不同描述符中矛盾: "
                            f"({old_media}, {old_size}) vs "
                            f"({child.media_type}, {child.size})",
                            manifest=digest, location=child.location))
                    continue
                declared_media[child.digest] = child.media_type
                declared_size[child.digest] = child.size
                pending.append(child.digest)
        return manifests, declared_media, declared_size

    def _record_failure(self, source_path: str,
                        diagnostics: list[Diagnostic]) -> ImportResult:
        with self._transaction() as conn:
            conn.execute(
                "INSERT INTO import_failures "
                "(source_path, failed_at, diagnostics_json) "
                "VALUES (?, ?, ?)",
                (source_path, _utcnow(),
                 json.dumps([d.to_dict() for d in diagnostics],
                            ensure_ascii=False)))
        return ImportResult(status=FAILED, diagnostics=list(diagnostics))

    def _publish_closure(self, staged: dict[str, tuple[int, str, str]],
                         staged_paths: dict[str, str],
                         manifests: dict[str, ParsedManifest],
                         expected_objects: dict[str, tuple[str, str, int, str]],
                         root_digest: str,
                         name: Optional[str]) -> dict:
        """在发布锁下把暂存字节改名进对象路径并单事务登记元数据。

        可恢复性：

        * 字节先落到最终路径（同文件系统 ``os.replace`` / ``os.link``），
          元数据事务后提交。若进程在改名之后、提交之前退出，只会留下
          无 ``objects`` 行的孤儿文件；它们不可见，也不会被任何名称指向。
        * 对仓内已存在且长度正确的对象绝不覆盖（内容寻址）；
          若最终路径已存在但大小不符，先移到 ``trash`` 再放入新字节，
          避免用坏字节替换好字节。
        * 元数据事务是唯一可见性边界：``closures``/``closures_objects``/
          ``refs`` 在同一事务里写入，读者永远看不到半份闭包。
        """
        conn = self.conn
        existing = {row["digest"]: row["size"] for row in conn.execute(
            "SELECT digest, size FROM objects")}
        for digest, (size, _rel, _role) in staged.items():
            if digest in existing and existing[digest] != size:
                raise OSError(
                    f"仓内 {digest} 长度 {existing[digest]} 与输入 {size} "
                    f"不符，拒绝覆盖")

        final_paths: dict[str, str] = {}
        for digest, (size, rel, _role) in staged.items():
            src = staged_paths[digest]
            final = self.blob_path(digest)
            os.makedirs(os.path.dirname(final), exist_ok=True)
            if os.path.lexists(final):
                if os.path.isfile(final) and not os.path.islink(final) \
                        and _file_size(final) == size:
                    # 仓内已有同摘要同长度对象：内容寻址，丢弃暂存副本
                    os.unlink(src)
                    final_paths[digest] = final
                    continue
                # 最终路径被长度不符的文件占据（异常残留）：先隔离再放入
                self._quarantine_path(final)
            # 同文件系统 os.replace 原子；发布锁下无并发写者
            os.replace(src, final)
            final_paths[digest] = final

        added = 0
        existing_count = 0
        added_bytes = 0
        try:
            with self._transaction() as tx:
                now = _utcnow()
                for digest, (size, rel, role) in staged.items():
                    row = tx.execute(
                        "SELECT size FROM objects WHERE digest = ?",
                        (digest,)).fetchone()
                    if row is not None:
                        existing_count += 1
                        continue
                    tx.execute(
                        "INSERT INTO objects (digest, size, blob_relpath, "
                        "created_at) VALUES (?, ?, ?, ?)",
                        (digest, size, rel, now))
                    added += 1
                    added_bytes += size
                for digest, parsed in manifests.items():
                    tx.execute(
                        "INSERT INTO manifests (digest, media_type, kind) "
                        "VALUES (?, ?, ?) ON CONFLICT(digest) DO UPDATE SET "
                        "media_type = excluded.media_type, "
                        "kind = excluded.kind",
                        (digest, parsed.media_type,
                         "index" if parsed.is_index else "image"))
                    kids: list[tuple[Descriptor, str]] = []
                    if parsed.config is not None:
                        kids.append((parsed.config, "config"))
                    kids += [(d, "layer") for d in parsed.layers]
                    kids += [(d, "child") for d in parsed.children]
                    for position, (desc, role) in enumerate(kids):
                        tx.execute(
                            "INSERT OR REPLACE INTO manifest_edges "
                            "(parent_digest, position, role, child_digest, "
                            "media_type, size) VALUES (?, ?, ?, ?, ?, ?)",
                            (digest, position, role, desc.digest,
                             desc.media_type, desc.size))
                closure = tx.execute(
                    "SELECT closure_id FROM closures WHERE root_digest = ?",
                    (root_digest,)).fetchone()
                if closure is None:
                    cur = tx.execute(
                        "INSERT INTO closures (root_digest, created_at) "
                        "VALUES (?, ?)", (root_digest, now))
                    closure_id = cur.lastrowid
                else:
                    closure_id = closure["closure_id"]
                role_of = {
                    dg: ("root" if dg == root_digest else values[1])
                    for dg, values in expected_objects.items()}
                for digest in staged:
                    tx.execute(
                        "INSERT OR IGNORE INTO closure_objects "
                        "(closure_id, digest, role) VALUES (?, ?, ?)",
                        (closure_id, digest, role_of.get(digest, "object")))
                name_status = None
                if name is not None:
                    old = tx.execute(
                        "SELECT root_digest FROM refs WHERE name = ?",
                        (name,)).fetchone()
                    if old is None:
                        name_status = NAME_SET
                    elif old["root_digest"] != root_digest:
                        name_status = NAME_REPLACED
                    else:
                        name_status = NAME_SET
                    tx.execute(
                        "INSERT INTO refs (name, root_digest, updated_at) "
                        "VALUES (?, ?, ?) "
                        "ON CONFLICT(name) DO UPDATE SET "
                        "root_digest = excluded.root_digest, "
                        "updated_at = excluded.updated_at",
                        (name, root_digest, now))
        except BaseException:
            # 元数据事务失败：本次新移动的字节成为无主孤儿；留在 blobs
            # 不影响可见性，回收时按“不在 objects 表”清理。
            raise
        return {"closure_id": closure_id, "added": added,
                "existing": existing_count, "added_bytes": added_bytes,
                "name_status": name_status}

    def _quarantine_path(self, path: str) -> None:
        target = os.path.join(self.trash_dir, uuid.uuid4().hex)
        try:
            os.replace(path, target)
        except OSError:
            pass

    # ------------------------------------------------------------------
    # 名称管理：显式设置/替换/删除；删除名称不 unlink 原对象
    # ------------------------------------------------------------------
    def list_refs(self) -> list[RefInfo]:
        """列出保留名称；根元数据不完整时抛 StoreError（状态异常）。"""
        rows = self.conn.execute(
            "SELECT r.name, r.root_digest, r.updated_at "
            "FROM refs r ORDER BY r.name").fetchall()
        result: list[RefInfo] = []
        for row in rows:
            media = self.conn.execute(
                "SELECT media_type FROM manifests WHERE digest = ?",
                (row["root_digest"],)).fetchone()
            size = self.conn.execute(
                "SELECT size FROM objects WHERE digest = ?",
                (row["root_digest"],)).fetchone()
            if media is None or size is None:
                raise StoreError(
                    "仓库状态异常：名称 %r 的根 %s 元数据不完整"
                    % (row["name"], row["root_digest"]))
            result.append(RefInfo(
                name=row["name"],
                root=Descriptor(media["media_type"], row["root_digest"],
                                size["size"]),
                updated_at=row["updated_at"]))
        return result

    def get_ref(self, name: str) -> RefInfo:
        for info in self.list_refs():
            if info.name == name:
                return info
        raise UnknownNameError(name)

    def resolve_name(self, name: str) -> str:
        row = self.conn.execute(
            "SELECT root_digest FROM refs WHERE name = ?", (name,)).fetchone()
        if row is None:
            raise UnknownNameError(name)
        return row["root_digest"]

    def set_ref(self, name: str, root_digest: str) -> str:
        """把名称指向一个**已完整持有**的闭包根；返回 set/replaced。

        只允许指向已发布闭包：名称永远不会指向半份内容。
        """
        if not isinstance(name, str) or not name.strip() or name != name.strip():
            raise StoreError(f"保留名称必须是非空且无首尾空白的字符串: {name!r}")
        if not is_sha256(root_digest):
            raise StoreError(f"根必须是合法 sha256 digest: {root_digest!r}")
        closure = self.conn.execute(
            "SELECT closure_id FROM closures WHERE root_digest = ?",
            (root_digest,)).fetchone()
        if closure is None:
            raise StoreError(
                f"本仓没有 {root_digest} 的完整闭包，不能创建名称")
        with self._publish_lock():
            with self._transaction() as tx:
                old = tx.execute(
                    "SELECT root_digest FROM refs WHERE name = ?",
                    (name,)).fetchone()
                status = (NAME_SET if old is None
                          or old["root_digest"] == root_digest
                          else NAME_REPLACED)
                tx.execute(
                    "INSERT INTO refs (name, root_digest, updated_at) "
                    "VALUES (?, ?, ?) ON CONFLICT(name) DO UPDATE SET "
                    "root_digest = excluded.root_digest, "
                    "updated_at = excluded.updated_at",
                    (name, root_digest, _utcnow()))
        return status

    def delete_ref(self, name: str) -> str:
        """删除名称；只移除引用，不立即 unlink 任何对象。"""
        with self._publish_lock():
            with self._transaction() as tx:
                cur = tx.execute("DELETE FROM refs WHERE name = ?", (name,))
                if cur.rowcount == 0:
                    return NAME_NOT_FOUND
        return NAME_DELETED

    # ------------------------------------------------------------------
    # 读取：固定闭包 + 分块读取；context 关闭前对象受保护
    # ------------------------------------------------------------------
    def open_reader(self, name: str) -> "BlobReader":
        """以一个上下文固定名称**当时**指向的根。

        打开时短暂持有发布锁：登记 reader 行（可见性快照）并取得 reader
        锁；随后释放发布锁。读取期间其它进程可发布无关引用、规划空间、
        回收不受保护对象。名称此后改指向/删除不影响已打开的读者。

        已有闭包若在本仓缺损，打开即报仓库状态异常（不静默当成空闭包）。
        """
        with self._publish_lock():
            root_digest = self.resolve_name(name)
            problems = self._closure_problems(root_digest)
            if problems:
                raise StoreError(
                    "仓库状态异常：名称 %r 的闭包不完整: %s"
                    % (name, "; ".join(problems)))
            reader_id = uuid.uuid4().hex
            lock_path = self._reader_lock_path(reader_id)
            lock = FileLock(lock_path)
            lock.acquire()
            pid, proc_start, boot_id = process_identity()
            try:
                with self._transaction() as tx:
                    tx.execute(
                        "INSERT INTO readers (reader_id, root_digest, status, "
                        "pid, proc_start, boot_id, opened_at) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (reader_id, root_digest, READER_ACTIVE, pid,
                         proc_start, boot_id, _utcnow()))
            except BaseException:
                lock.release()
                try:
                    os.unlink(lock_path)
                except OSError:
                    pass
                raise
        return BlobReader(self, reader_id, root_digest, lock)

    # ------------------------------------------------------------------
    # 仓库状态：引用/读者闭包缺损时报告异常，不得当成“无引用”
    # ------------------------------------------------------------------
    def _closure_digests(self, root_digest: str) -> set[str]:
        rows = self.conn.execute(
            "SELECT digest FROM closure_objects WHERE closure_id = "
            "(SELECT closure_id FROM closures WHERE root_digest = ?)",
            (root_digest,)).fetchall()
        return {row["digest"] for row in rows}

    def _closure_problems(self, root_digest: str) -> list[str]:
        """检查一个根闭包的元数据与对象字节是否完整。

        三条独立核对避免“缺损被当成没有引用”：

        1. 根必须有 ``closures`` 与 ``manifests`` 行；
        2. 沿 ``manifest_edges`` 从根可达的对象集合必须与
           ``closure_objects`` 的登记一致（发现只删了登记/只删了边的漂移）；
        3. 每个闭包对象的元数据存在、字节文件存在且长度一致。
        """
        problems: list[str] = []
        if not is_sha256(root_digest):
            return [f"根 digest 非法: {root_digest!r}"]
        closure = self.conn.execute(
            "SELECT closure_id FROM closures WHERE root_digest = ?",
            (root_digest,)).fetchone()
        if closure is None:
            return [f"闭包 {root_digest} 不存在"]
        if self.conn.execute("SELECT 1 FROM manifests WHERE digest = ?",
                             (root_digest,)).fetchone() is None:
            problems.append(f"根 {root_digest} 缺少 manifest 元数据")
        rows = self.conn.execute(
            "SELECT co.digest, o.size FROM closure_objects co "
            "LEFT JOIN objects o ON o.digest = co.digest "
            "WHERE co.closure_id = ?", (closure["closure_id"],)).fetchall()
        if not rows:
            problems.append(f"闭包 {root_digest} 没有登记任何对象")
        registered = {row["digest"] for row in rows}
        edge_reachable = self._reachable_objects({root_digest})
        for digest in sorted(edge_reachable - registered):
            problems.append(
                f"对象 {digest} 可从根到达但未登记在闭包中")
        for digest in sorted(registered - edge_reachable):
            problems.append(
                f"对象 {digest} 登记在闭包中但从根不可达")
        for row in rows:
            if row["size"] is None:
                problems.append(f"对象 {row['digest']} 无元数据行")
                continue
            path = self.blob_path(row["digest"])
            try:
                if _file_size(path) != row["size"]:
                    problems.append(
                        f"对象 {row['digest']} 长度不符（元数据 "
                        f"{row['size']}）")
            except OSError:
                problems.append(f"对象 {row['digest']} 的字节文件缺失")
        return problems

    def check_health(self) -> dict:
        """全仓一致性检查：返回 {'status': ok|corrupt, 'problems': [...]}。"""
        problems: list[str] = []
        for row in self.conn.execute(
                "SELECT name, root_digest FROM refs ORDER BY name").fetchall():
            for problem in self._closure_problems(row["root_digest"]):
                problems.append(f"引用 {row['name']}: {problem}")
        active = self._protected_reader_roots()
        for root in active:
            for problem in self._closure_problems(root):
                problems.append(f"活跃读者闭包: {problem}")
        return {"status": REPO_CORRUPT if problems else REPO_OK,
                "problems": problems}

    # ------------------------------------------------------------------
    # 回收：两阶段（计划 -> 明确应用），逐项复核当前引用与活跃读者
    # ------------------------------------------------------------------
    def _reap_dead_readers(self) -> list[dict]:
        """把已死亡读者的保护释放（reader 行置 exited，删除其锁文件）。

        判定顺序：

        1. reader 行仍是 active 且锁文件**无人持有** -> 进程已退出
           （含 SIGKILL / os._exit），直接释放；
        2. 锁文件无法打开/探测时，用 pid + 进程启动时间 + boot_id 作保守
           回退；无法判断时保持保护，绝不靠固定秒数宣告慢读者失效。
        """
        released: list[dict] = []
        now = _utcnow()
        for row in self.conn.execute(
                "SELECT * FROM readers WHERE status = ?",
                (READER_ACTIVE,)).fetchall():
            lock_path = self._reader_lock_path(row["reader_id"])
            held = lock_is_held(lock_path)
            dead = False
            reason = ""
            if held is False:
                dead = True
                reason = "reader 锁无人持有（进程已退出）"
            elif held is None:
                alive = process_alive(row["pid"], row["proc_start"],
                                      row["boot_id"])
                if alive is False:
                    dead = True
                    reason = "进程不存在或 PID 已复用"
            if not dead:
                continue
            with self._transaction() as tx:
                cur = tx.execute(
                    "UPDATE readers SET status = ?, closed_at = ? "
                    "WHERE reader_id = ? AND status = ?",
                    (READER_EXITED, now, row["reader_id"], READER_ACTIVE))
                if cur.rowcount:
                    released.append({"reader_id": row["reader_id"],
                                     "root_digest": row["root_digest"],
                                     "reason": reason})
            try:
                os.unlink(lock_path)
            except OSError:
                pass
        return released

    def _protected_reader_roots(self) -> set[str]:
        self._reap_dead_readers()
        rows = self.conn.execute(
            "SELECT DISTINCT root_digest FROM readers WHERE status = ?",
            (READER_ACTIVE,)).fetchall()
        return {row["root_digest"] for row in rows}

    def _active_reader_count(self) -> int:
        return self.conn.execute(
            "SELECT COUNT(*) AS c FROM readers WHERE status = ?",
            (READER_ACTIVE,)).fetchone()["c"]

    def _referenced_roots(self) -> set[str]:
        return {row["root_digest"] for row in self.conn.execute(
            "SELECT root_digest FROM refs")}

    def _reachable_objects(self, roots: set[str]) -> set[str]:
        """沿 manifest 边从若干根求可达对象闭包（roots 本身也计入）。"""
        reachable: set[str] = set()
        pending = list(roots)
        while pending:
            digest = pending.pop()
            if digest in reachable:
                continue
            reachable.add(digest)
            rows = self.conn.execute(
                "SELECT child_digest FROM manifest_edges "
                "WHERE parent_digest = ?", (digest,)).fetchall()
            for row in rows:
                if row["child_digest"] not in reachable:
                    pending.append(row["child_digest"])
        return reachable

    def plan_gc(self) -> GcPlan:
        """生成可释放空间计划（只保存候选，不删除任何字节）。

        * 参与可达性的根 = 当前保留名称 + 活跃读者固定闭包；
        * 任何引用或活跃读者的闭包缺损 -> 抛 :class:`StoreError`
          （仓库状态异常），不允许把“读不到”当成“没引用”；
        * 候选 = 不在 objects 表中、或属于 objects 表但不可达的完整对象；
          未发布暂存（无 objects 行）且无持有锁的字节也计入可释放，
          但正在进行的导入不会被当成垃圾。
        """
        with self._publish_lock():
            return self._plan_gc_locked()

    def _validate_closure_or_raise(self, roots: set[str]) -> None:
        problems: list[str] = []
        for root in sorted(roots):
            problems.extend(self._closure_problems(root))
        if problems:
            raise StoreError("仓库状态异常，拒绝生成回收计划: "
                             + "; ".join(problems))

    def _plan_gc_locked(self) -> GcPlan:
        ref_roots = self._referenced_roots()
        reader_roots = self._protected_reader_roots()
        protected_roots = ref_roots | reader_roots
        self._validate_closure_or_raise(protected_roots)
        reachable = self._reachable_objects(protected_roots)

        rows = self.conn.execute(
            "SELECT digest, size, blob_relpath FROM objects ORDER BY digest"
        ).fetchall()
        candidates: list[dict] = []
        total = 0
        missing: list[dict] = []
        known_paths: set[str] = set()
        for row in rows:
            known_paths.add(os.path.realpath(
                self.blob_path(row["digest"])))
            if row["digest"] in reachable:
                continue
            path = self.blob_path(row["digest"])
            try:
                actual = _file_size(path)
            except OSError:
                missing.append({"digest": row["digest"],
                                "size": row["size"],
                                "reason": "对象文件已不存在"})
                continue
            if actual != row["size"]:
                missing.append({"digest": row["digest"],
                                "size": row["size"],
                                "reason": f"文件长度 {actual} 与元数据不符"})
                continue
            candidates.append({"digest": row["digest"], "size": row["size"]})
            total += row["size"]

        # 发布事务崩溃留下的孤儿：有字节、无 objects 行。它们不可达，
        # 但仍交人核对后随计划回收。
        for dirpath, _dirnames, filenames in os.walk(
                os.path.join(self.blobs_dir, "sha256")):
            for filename in filenames:
                full = os.path.join(dirpath, filename)
                if os.path.realpath(full) in known_paths:
                    continue
                digest = "sha256:" + filename
                if not is_sha256(digest):
                    missing.append({"digest": "", "size": _file_size(full),
                                    "reason": f"非法对象文件名: {full}"})
                    continue
                size = _file_size(full)
                candidates.append({"digest": digest, "size": size,
                                   "orphan_relpath": os.path.relpath(
                                       full, self.root)})
                total += size

        # 未发布暂存：没有 objects 行、不在任何闭包内、暂存锁无人持有
        if os.path.isdir(self.staging_dir):
            for entry in sorted(os.listdir(self.staging_dir)):
                if entry.endswith(".lock"):
                    continue
                staging_path = os.path.join(self.staging_dir, entry)
                if not os.path.isdir(staging_path):
                    continue
                lock_path = os.path.join(self.staging_dir, f"{entry}.lock")
                if lock_is_held(lock_path) is True:
                    continue  # 正在进行的导入
                for dirpath, _dirnames, filenames in os.walk(staging_path):
                    for filename in filenames:
                        full = os.path.join(dirpath, filename)
                        digest = "sha256:" + filename
                        if not is_sha256(digest):
                            continue
                        if self.conn.execute(
                                "SELECT 1 FROM objects WHERE digest = ?",
                                (digest,)).fetchone():
                            continue
                        size = _file_size(full)
                        candidates.append({
                            "digest": digest, "size": size,
                            "staged_relpath": os.path.relpath(
                                full, self.root)})
                        total += size

        plan_id = uuid.uuid4().hex
        created = _utcnow()
        with self._transaction() as tx:
            tx.execute(
                "INSERT INTO gc_plans (plan_id, created_at, unique_bytes, "
                "object_count, candidates_json) VALUES (?, ?, ?, ?, ?)",
                (plan_id, created, total, len(candidates),
                 json.dumps(candidates, ensure_ascii=False)))
            for candidate in candidates:
                tx.execute(
                    "INSERT INTO gc_plan_objects (plan_id, digest, size, "
                    "staged_relpath, orphan_relpath) VALUES (?, ?, ?, ?, ?)",
                    (plan_id, candidate["digest"], candidate["size"],
                     candidate.get("staged_relpath"),
                     candidate.get("orphan_relpath")))
        return GcPlan(plan_id=plan_id, created_at=created,
                      candidates=candidates, unique_bytes=total,
                      skipped_missing=missing)

    def apply_gc(self, plan_id: str) -> GcRun:
        """显式应用一份计划；应用时重新检查当前引用与活跃读者。

        * 候选后来受到保护 -> ``skipped``，并说明原因；
        * 已在此前应用中被删除 -> ``already_deleted``；
        * 仍然无保护 -> 删除并记 ``deleted``；
        * 只处理计划里的对象，计划生成后新出现的对象不参与。
        * 不要求整份计划一致：某一项状态变化不影响无关候选继续删除。
        """
        with self._publish_lock():
            return self._apply_gc_locked(plan_id)

    def _apply_gc_locked(self, plan_id: str) -> GcRun:
        """逐项应用先前保存的候选清单。

        处理顺序刻意先落盘再记结果：

        1. 对每个候选重新计算当前可达性（引用 + 活跃读者）并检查元数据；
        2. 对对象文件先 ``rename`` 到 ``trash/`` 再记 ``deleted``，最后才
           删除元数据行；中途退出时重跑会看到文件已在 trash、对象行仍在，
           记为 ``already_deleted``（不会声称“从未发生”）；
        3. 每一行结果单独提交（``gc_items`` 主键防止重复），因此某项状态
           变化不会让无关候选被整批放弃。
        """
        plan = self.conn.execute(
            "SELECT * FROM gc_plans WHERE plan_id = ?",
            (plan_id,)).fetchone()
        if plan is None:
            raise UnknownPlanError(plan_id)
        self._reap_dead_readers()
        roots = self._referenced_roots() | self._protected_reader_roots()
        self._validate_closure_or_raise(roots)
        reachable = self._reachable_objects(roots)

        rows = self.conn.execute(
            "SELECT digest, size, staged_relpath, orphan_relpath "
            "FROM gc_plan_objects WHERE plan_id = ? ORDER BY digest",
            (plan_id,)).fetchall()
        run_id = uuid.uuid4().hex
        applied = _utcnow()
        with self._transaction() as tx:
            tx.execute(
                "INSERT INTO gc_runs (run_id, plan_id, applied_at) "
                "VALUES (?, ?, ?)", (run_id, plan_id, applied))
            already_recorded = {
                row["digest"] for row in tx.execute(
                    "SELECT digest FROM gc_items WHERE run_id = ?",
                    (run_id,))}
        existing_items = {
            row["digest"]: {"digest": row["digest"], "size": row["size"],
                            "outcome": row["outcome"],
                            "reason": row["reason"]}
            for row in self.conn.execute(
                "SELECT i.digest, i.outcome, i.reason, p.size FROM gc_items i "
                "JOIN gc_plan_objects p ON p.plan_id = ? "
                "AND p.digest = i.digest WHERE i.run_id = ?",
                (plan_id, run_id)).fetchall()}
        items: list[dict] = []
        freed = 0
        for row in rows:
            digest = row["digest"]
            size = row["size"]
            if digest in already_recorded:
                previous = existing_items.get(digest)
                if previous is not None:
                    items.append(previous)
                continue
            item = self._apply_one_candidate(
                run_id, plan_id, digest, size, row["staged_relpath"],
                row["orphan_relpath"], reachable)
            if item["outcome"] == GC_DELETED:
                freed += size
            items.append(item)
        self._cleanup_planned_staging(rows)
        self._cleanup_redundant_staging()
        self._prune_empty_blob_dirs()
        return GcRun(run_id=run_id, plan_id=plan_id, applied_at=applied,
                     items=items, freed_bytes=freed)

    def _apply_one_candidate(self, run_id: str, plan_id: str, digest: str,
                             size: int, staged_relpath: Optional[str],
                             orphan_relpath: Optional[str],
                             reachable: set[str]) -> dict:
        """处理单个候选，并把结果原子写入 gc_items（可重复调用）。"""
        obj = self.conn.execute(
            "SELECT size, blob_relpath FROM objects WHERE digest = ?",
            (digest,)).fetchone()
        if obj is None and not staged_relpath and not orphan_relpath:
            return self._record_gc_item(
                run_id, digest, GC_ALREADY_DELETED,
                "对象元数据与字节均不存在（此前已删除）", size=size)
        if obj is not None and digest in reachable:
            return self._record_gc_item(
                run_id, digest, GC_SKIPPED,
                "当前保留引用或活跃读者仍可达", size=size)
        if obj is not None:
            path = self.blob_path(digest)
        elif staged_relpath:
            path = os.path.join(self.root, staged_relpath)
        else:
            path = os.path.join(self.root, orphan_relpath)
        if obj is not None:
            try:
                actual = _file_size(path)
            except OSError:
                # 候选不可达且字节已不在：可能是上一次应用在
                # “移动字节”与“删除元数据”之间退出。清理遗留元数据，
                # 使重跑收敛；已受保护的对象在计划阶段就会因闭包缺损
                # 报仓库异常，不会走到这里。
                if digest in reachable:
                    return self._record_gc_item(
                        run_id, digest, GC_SKIPPED,
                        "当前保留引用或活跃读者仍可达但字节缺失，"
                        "按仓库异常处理", size=size)
                self._forget_object(digest)
                return self._record_gc_item(
                    run_id, digest, GC_ALREADY_DELETED,
                    "对象文件已不存在（清理上次中断的元数据）", size=size)
            if actual != obj["size"]:
                return self._record_gc_item(
                    run_id, digest, GC_SKIPPED,
                    "对象文件长度与元数据不符，按仓库异常处理", size=size)
        elif staged_relpath:
            # 未发布暂存：必须仍无 objects 行、且暂存锁无人持有
            staging_entry = staged_relpath.split(os.sep)[0]
            lock_path = os.path.join(self.staging_dir, staging_entry + ".lock")
            if lock_is_held(lock_path) is True:
                return self._record_gc_item(
                    run_id, digest, GC_SKIPPED,
                    "暂存目录仍被导入过程持有", size=size)
            try:
                actual = _file_size(path)
            except OSError:
                return self._record_gc_item(
                    run_id, digest, GC_ALREADY_DELETED,
                    "暂存文件已不存在", size=size)
            if actual != size:
                return self._record_gc_item(
                    run_id, digest, GC_SKIPPED, "暂存文件长度与计划不符", size=size)
        # 先把字节移入 trash（物理释放前的可恢复位置），再记结果
        trash_name = os.path.join(self.trash_dir, uuid.uuid4().hex)
        try:
            os.replace(path, trash_name)
        except OSError as exc:
            return self._record_gc_item(
                run_id, digest, GC_SKIPPED,
                f"无法移动对象字节（{exc}），保持原状", size=size)
        item = self._record_gc_item(
            run_id, digest, GC_DELETED, "无保留引用与活跃读者", size=size)
        try:
            os.unlink(trash_name)
        except OSError:
            pass
        if obj is not None:
            self._forget_object(digest)
        self._prune_empty_blob_dirs()
        return item

    def _forget_object(self, digest: str) -> None:
        """删除已无字节对象的元数据，并清掉因此变空的闭包登记。

        候选清单只列“当前不可达”的完整对象；其父 manifest 与本对象
        不可能仍受保留引用或活跃读者保护（否则不可达判断不成立）。
        """
        with self._transaction() as tx:
            closure_ids = [row["closure_id"] for row in tx.execute(
                "SELECT DISTINCT closure_id FROM closure_objects "
                "WHERE digest = ?", (digest,)).fetchall()]
            # 指向本对象或其父对象的边都要清掉，否则外键阻止删除
            tx.execute("DELETE FROM manifest_edges WHERE child_digest = ?",
                       (digest,))
            tx.execute("DELETE FROM manifest_edges WHERE parent_digest = ?",
                       (digest,))
            tx.execute("DELETE FROM closure_objects WHERE digest = ?",
                       (digest,))
            # 若本对象自己是某个闭包的根，闭包登记必须一并消失
            tx.execute("DELETE FROM closures WHERE root_digest = ?",
                       (digest,))
            tx.execute("DELETE FROM manifests WHERE digest = ?", (digest,))
            tx.execute("DELETE FROM objects WHERE digest = ?", (digest,))
            for closure_id in closure_ids:
                remaining = tx.execute(
                    "SELECT COUNT(*) AS c FROM closure_objects "
                    "WHERE closure_id = ?", (closure_id,)).fetchone()["c"]
                if remaining:
                    continue
                root = tx.execute(
                    "SELECT root_digest FROM closures WHERE closure_id = ?",
                    (closure_id,)).fetchone()
                if root is None:
                    continue
                tx.execute("DELETE FROM closures WHERE closure_id = ?",
                           (closure_id,))
                dangling = tx.execute(
                    "SELECT COUNT(*) AS c FROM closures WHERE root_digest = ?",
                    (root["root_digest"],)).fetchone()["c"]
                still_edge = tx.execute(
                    "SELECT COUNT(*) AS c FROM manifest_edges "
                    "WHERE child_digest = ?", (root["root_digest"],)
                ).fetchone()["c"]
                if dangling == 0 and still_edge == 0:
                    tx.execute("DELETE FROM manifests WHERE digest = ?",
                               (root["root_digest"],))

    def _prune_empty_blob_dirs(self) -> None:
        """回收后清掉空的 hash 前缀目录（尽力而为，不影响正确性）。"""
        base = os.path.join(self.blobs_dir, "sha256")
        try:
            for entry in os.listdir(base):
                path = os.path.join(base, entry)
                if os.path.isdir(path) and not os.listdir(path):
                    os.rmdir(path)
        except OSError:
            pass

    def _record_gc_item(self, run_id: str, digest: str, outcome: str,
                        reason: str, size: int = 0) -> dict:
        with self._transaction() as tx:
            tx.execute(
                "INSERT OR REPLACE INTO gc_items "
                "(run_id, digest, outcome, reason) VALUES (?, ?, ?, ?)",
                (run_id, digest, outcome, reason))
        return {"digest": digest, "size": size, "outcome": outcome,
                "reason": reason}

    def _cleanup_planned_staging(self, rows) -> None:
        """回收到期后清理**本计划**涉及的暂存目录。

        正在导入的目录有暂存锁，探测到持有者即保留。计划内新对象已由
        逐项应用删除；剩下的可能只是“仓内已有同摘要对象”的重复副本
        （复制完成后、发布前崩溃），在无锁且确认都已持有时一并清掉。
        """
        entries = {row["staged_relpath"].split(os.sep)[1]
                   for row in rows if row["staged_relpath"]}
        self._cleanup_staging_entries(entries)

    def _cleanup_redundant_staging(self) -> None:
        """清掉只含“仓内已有对象”副本的无主暂存（回收后调用）。"""
        if not os.path.isdir(self.staging_dir):
            return
        entries = {entry for entry in os.listdir(self.staging_dir)
                   if not entry.endswith(".lock")
                   and os.path.isdir(os.path.join(self.staging_dir, entry))}
        self._cleanup_staging_entries(entries)

    def _cleanup_staging_entries(self, entries: set[str]) -> None:
        for entry in sorted(entries):
            path = os.path.join(self.staging_dir, entry)
            lock_path = os.path.join(self.staging_dir, f"{entry}.lock")
            if lock_is_held(lock_path) is True:
                continue
            if not os.path.isdir(path):
                continue
            files = [os.path.join(dirpath, filename)
                     for dirpath, _dirnames, filenames in os.walk(path)
                     for filename in filenames]
            # 只要还有一个不在 objects 表中的文件，就保留整个目录：
            # 它的字节可能仍在候选清单里，交人核对。
            if any(not is_sha256("sha256:" + os.path.basename(f))
                   or self.conn.execute(
                       "SELECT 1 FROM objects WHERE digest = ?",
                       ("sha256:" + os.path.basename(f),)).fetchone() is None
                   for f in files):
                continue
            for filename in files:
                try:
                    os.unlink(filename)
                except OSError:
                    pass
            shutil.rmtree(path, ignore_errors=True)
            try:
                os.unlink(lock_path)
            except OSError:
                pass

    def _cleanup_orphan_staging(self) -> None:
        """恢复用：清掉无锁且不属于任何对象的暂存目录（正在导入的不动）。"""
        if not os.path.isdir(self.staging_dir):
            return
        for entry in os.listdir(self.staging_dir):
            if entry.endswith(".lock"):
                continue
            path = os.path.join(self.staging_dir, entry)
            if not os.path.isdir(path):
                continue
            lock_path = os.path.join(self.staging_dir, f"{entry}.lock")
            if lock_is_held(lock_path) is True:
                continue
            shutil.rmtree(path, ignore_errors=True)
            try:
                os.unlink(lock_path)
            except OSError:
                pass

    def list_gc_plans(self) -> list[dict]:
        return [dict(row) for row in self.conn.execute(
            "SELECT plan_id, created_at, unique_bytes, object_count "
            "FROM gc_plans ORDER BY created_at")]

    def list_gc_runs(self) -> list[dict]:
        runs = []
        for row in self.conn.execute(
                "SELECT run_id, plan_id, applied_at FROM gc_runs "
                "ORDER BY applied_at"):
            record = dict(row)
            record["items"] = [dict(item) for item in self.conn.execute(
                "SELECT digest, outcome, reason FROM gc_items "
                "WHERE run_id = ? ORDER BY digest", (row["run_id"],))]
            runs.append(record)
        return runs

    # ------------------------------------------------------------------
    # 恢复辅助：无主孤儿对象与暂存清理
    # ------------------------------------------------------------------
    def recover(self) -> dict:
        """重开进程后的保守恢复（可重复调用）。

        * 清理 ``trash/`` 中的隔离残留；
        * 删除 ``staging/`` 下无主（锁无人持有）且不属于任何对象的暂存；
        * 不删除 ``blobs/`` 中“有字节、无元数据”的文件：它们可能是
          发布事务崩溃留下的孤儿，但没有元数据就没有任何名称指向它们，
          回收计划会把它们列为候选，交人确认后再删（避免误删正在发布
          的对象字节）；
        * 一致性检查结果随返回值报告。
        """
        removed_trash = 0
        if os.path.isdir(self.trash_dir):
            for entry in os.listdir(self.trash_dir):
                path = os.path.join(self.trash_dir, entry)
                try:
                    os.unlink(path)
                    removed_trash += 1
                except OSError:
                    pass
        self._cleanup_orphan_staging()
        return {"removed_trash": removed_trash,
                "health": self.check_health()}

    def stats(self) -> dict:
        """对象仓基本账目：对象数、唯一字节、名称数、活跃读者数。"""
        obj = self.conn.execute(
            "SELECT COUNT(*) AS c, COALESCE(SUM(size), 0) AS s "
            "FROM objects").fetchone()
        return {
            "object_count": obj["c"],
            "unique_bytes": obj["s"],
            "ref_count": self.conn.execute(
                "SELECT COUNT(*) AS c FROM refs").fetchone()["c"],
            "closure_count": self.conn.execute(
                "SELECT COUNT(*) AS c FROM closures").fetchone()["c"],
            "active_readers": self._active_reader_count(),
        }


class BlobReader:
    """固定某个根闭包的使用期上下文。

    * ``root`` 是打开时的根描述符（名称后来改指向/删除都不影响）；
    * ``objects()`` 给出闭包内对象的描述符（按 digest 稳定排序）；
    * ``open(digest)`` / ``read_chunks(digest)`` 只能读取**固定闭包**内的
      对象；闭包外 digest 一律拒绝，不会因为描述符路径穿越到宿主文件；
    * 上下文关闭时立即解除保护（reader 行置 closed 并释放 flock）。
      进程被强制结束时 flock 由内核释放，下一次回收辨认并释放保护。
    """

    def __init__(self, store: BlobStore, reader_id: str, root_digest: str,
                 lock: FileLock):
        self.store = store
        self.reader_id = reader_id
        self.root_digest = root_digest
        self._lock = lock
        self._closed = False
        self._allowed: set[str] = set()
        row = store.conn.execute(
            "SELECT media_type FROM manifests WHERE digest = ?",
            (root_digest,)).fetchone()
        self._root_media = row["media_type"] if row else ""
        size_row = store.conn.execute(
            "SELECT size FROM objects WHERE digest = ?",
            (root_digest,)).fetchone()
        self._root_size = size_row["size"] if size_row else 0

    # -- 基本属性 --------------------------------------------------------
    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def root(self) -> Descriptor:
        return Descriptor(self._root_media, self.root_digest, self._root_size)

    def _ensure_open(self) -> None:
        if self._closed:
            raise ClosedReaderError("读取上下文已关闭")

    def _load_allowed(self) -> set[str]:
        if not self._allowed:
            rows = self.store.conn.execute(
                "SELECT digest FROM closure_objects WHERE closure_id = "
                "(SELECT closure_id FROM closures WHERE root_digest = ?)",
                (self.root_digest,)).fetchall()
            self._allowed = {row["digest"] for row in rows}
        return self._allowed

    def object_digests(self) -> list[str]:
        self._ensure_open()
        return sorted(self._load_allowed())

    def objects(self) -> list[Descriptor]:
        """闭包内全部对象的描述符（role 随 ``roles()`` 查询）。"""
        self._ensure_open()
        rows = self.store.conn.execute(
            "SELECT co.digest, co.role, o.size, "
            "COALESCE(m.media_type, e.media_type, '') AS media_type "
            "FROM closure_objects co JOIN objects o ON o.digest = co.digest "
            "LEFT JOIN manifests m ON m.digest = co.digest "
            "LEFT JOIN manifest_edges e ON e.child_digest = co.digest "
            "WHERE co.closure_id = (SELECT closure_id FROM closures "
            "WHERE root_digest = ?) GROUP BY co.digest ORDER BY co.digest",
            (self.root_digest,)).fetchall()
        return [Descriptor(row["media_type"], row["digest"], row["size"])
                for row in rows]

    def roles(self) -> dict[str, str]:
        self._ensure_open()
        rows = self.store.conn.execute(
            "SELECT digest, role FROM closure_objects WHERE closure_id = "
            "(SELECT closure_id FROM closures WHERE root_digest = ?)",
            (self.root_digest,)).fetchall()
        return {row["digest"]: row["role"] for row in rows}

    def describe(self, digest: str) -> Descriptor:
        """读取闭包内某对象的描述符；闭包外 digest 拒绝。"""
        self._ensure_open()
        if digest not in self._load_allowed():
            raise StoreError(
                f"读者 {self.reader_id} 的固定闭包不包含对象 {digest}")
        row = self.store.conn.execute(
            "SELECT o.size, COALESCE(m.media_type, e.media_type, '') AS mt "
            "FROM objects o LEFT JOIN manifests m ON m.digest = o.digest "
            "LEFT JOIN manifest_edges e ON e.child_digest = o.digest "
            "WHERE o.digest = ? LIMIT 1", (digest,)).fetchone()
        if row is None:
            raise StoreError(f"仓库状态异常：对象 {digest} 的元数据缺失")
        return Descriptor(row["mt"], digest, row["size"])

    # -- 读取 ------------------------------------------------------------
    def open(self, digest: str) -> Iterator[bytes]:
        """按 digest 打开闭包内对象，逐块产出原始字节（不整层入内存）。"""
        self._ensure_open()
        if digest not in self._load_allowed():
            raise StoreError(
                f"读者 {self.reader_id} 的固定闭包不包含对象 {digest}")
        path = self.store.blob_path(digest)
        try:
            with open(path, "rb") as fh:
                while True:
                    chunk = fh.read(self.store.chunk_size)
                    if not chunk:
                        break
                    yield chunk
        except FileNotFoundError as exc:
            raise StoreError(
                f"仓库状态异常：闭包对象 {digest} 的字节缺失: {exc}") from exc

    def read_all(self, digest: str) -> bytes:
        """读取闭包内对象全部字节（小对象方便用；大层请用 ``open``）。"""
        return b"".join(self.open(digest))

    def read_chunks(self, digest: str, chunk_size: Optional[int] = None
                    ) -> Iterator[bytes]:
        self._ensure_open()
        if digest not in self._load_allowed():
            raise StoreError(
                f"读者 {self.reader_id} 的固定闭包不包含对象 {digest}")
        path = self.store.blob_path(digest)
        size = chunk_size or self.store.chunk_size
        try:
            with open(path, "rb") as fh:
                while True:
                    chunk = fh.read(size)
                    if not chunk:
                        break
                    yield chunk
        except FileNotFoundError as exc:
            raise StoreError(
                f"仓库状态异常：闭包对象 {digest} 的字节缺失: {exc}") from exc

    # -- 关闭 ------------------------------------------------------------
    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            with self.store._transaction() as tx:
                tx.execute(
                    "UPDATE readers SET status = ?, closed_at = ? "
                    "WHERE reader_id = ? AND status = ?",
                    (READER_CLOSED, _utcnow(), self.reader_id, READER_ACTIVE))
        finally:
            self._lock.release()
            try:
                os.unlink(self.store._reader_lock_path(self.reader_id))
            except OSError:
                pass

    def __enter__(self) -> "BlobReader":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()
