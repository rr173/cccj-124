"""镜像层文件视图的独立 SQLite 存储：绑定校验、单镜像事务构建。

与既有库的关系：

* **独立数据库文件**：文件视图写入本库；目录库（CatalogStore 的 SQLite
  文件）只以只读方式打开，用于校验镜像绑定并读取 manifest 层序；
  构建过程不写目录库、不产生 tag 事件，也不触碰 SBOM 库。
* 绑定目标必须是目录中已收录的**单平台 image manifest**
  （``kind='image'``）：tag、index digest、unknown manifest、未收录
  摘要分别以 ``binding_not_digest`` / ``binding_not_image`` /
  ``binding_unknown_digest`` 拒绝。

事务与失败语义：

* 每个镜像一个事务。任何诊断（缺层映射、归档不可读、摘要不符、
  不支持的压缩、非法成员路径、不可解析硬链接等）都会让本次构建
  整体失败：不写任何视图行，只在 ``view_failures`` 留诊断，
  失败镜像不可能被查询成一份成功视图。
* 同一镜像重复构建：旧视图整体替换（``replaced``），不留修订历史。
* 同一层被多个镜像引用：每个镜像各自按自己的层序完整归并，
  不存在“已处理过就跳过”的全局层缓存；只有文件内容字节按
  sha256 在本库内去重（内容寻址，跨视图共享）。
"""

from __future__ import annotations

import json
import os
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from ..digest import DigestError, parse_digest, sha256_digest
from .layer_archive import (
    DIGEST_MISMATCH,
    MISSING_LAYER_ARCHIVE,
    UNREADABLE_ARCHIVE,
    LayerIngestError,
    TreeMerge,
    ViewDiagnostic,
    parse_layer_archive,
)

SCHEMA = """
-- 每个镜像一份归并完成的文件视图
CREATE TABLE IF NOT EXISTS image_views (
    view_id         INTEGER PRIMARY KEY AUTOINCREMENT,
    image_digest    TEXT NOT NULL UNIQUE,
    layer_count     INTEGER NOT NULL,
    entry_count     INTEGER NOT NULL,
    built_at        TEXT NOT NULL
);

-- 构建该视图时实际使用的层序（逐镜像记录，不按层去重）
CREATE TABLE IF NOT EXISTS view_layers (
    view_id         INTEGER NOT NULL REFERENCES image_views(view_id)
                        ON DELETE CASCADE,
    position        INTEGER NOT NULL,
    layer_digest    TEXT NOT NULL,
    media_type      TEXT NOT NULL,
    archive_path    TEXT NOT NULL,
    PRIMARY KEY (view_id, position)
);

-- 文件内容字节：内容寻址，库内去重（跨视图共享同一物理内容）
CREATE TABLE IF NOT EXISTS contents (
    content_id      INTEGER PRIMARY KEY AUTOINCREMENT,
    sha256          TEXT NOT NULL UNIQUE,
    size            INTEGER NOT NULL,
    data            BLOB NOT NULL
);

-- 归并后的文件树条目
CREATE TABLE IF NOT EXISTS entries (
    entry_id        INTEGER PRIMARY KEY AUTOINCREMENT,
    view_id         INTEGER NOT NULL REFERENCES image_views(view_id)
                        ON DELETE CASCADE,
    path            TEXT NOT NULL,
    entry_type      TEXT NOT NULL,   -- file | dir | symlink | hardlink
    size            INTEGER NOT NULL DEFAULT 0,
    mode            INTEGER NOT NULL DEFAULT 0,
    layer_digest    TEXT NOT NULL,   -- 最近改变该路径的层
    member_name     TEXT NOT NULL,   -- 判定所依据的 tar 成员名
    member_index    INTEGER NOT NULL,-- 该成员在其归档中的位置
    link_target     TEXT NOT NULL DEFAULT '',
    content_id      INTEGER REFERENCES contents(content_id),
    implicit        INTEGER NOT NULL DEFAULT 0,
    UNIQUE (view_id, path)
);
CREATE INDEX IF NOT EXISTS idx_entries_view_path ON entries(view_id, path);

-- 构建失败诊断（失败镜像没有任何可查询视图）
CREATE TABLE IF NOT EXISTS view_failures (
    failure_id      INTEGER PRIMARY KEY AUTOINCREMENT,
    image_digest    TEXT,
    failed_at       TEXT NOT NULL,
    diagnostics_json TEXT NOT NULL
);
"""

# 构建结果状态
BUILT = "built"
REPLACED = "replaced"
FAILED = "failed"

# 绑定类诊断码
BINDING_NOT_DIGEST = "binding_not_digest"
BINDING_UNKNOWN_DIGEST = "binding_unknown_digest"
BINDING_NOT_IMAGE = "binding_not_image"


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class BuildResult:
    """单镜像视图构建结果。"""

    image_digest: str
    status: str
    view_id: Optional[int] = None
    layer_count: int = 0
    entry_count: int = 0
    diagnostics: list[ViewDiagnostic] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.status != FAILED

    def to_dict(self) -> dict:
        return {
            "image_digest": self.image_digest,
            "status": self.status,
            "view_id": self.view_id,
            "layer_count": self.layer_count,
            "entry_count": self.entry_count,
            "diagnostics": [d.to_dict() for d in self.diagnostics],
        }


class FileViewStore:
    """镜像层文件视图的独立 SQLite 存储。"""

    def __init__(self, views_db_path: str, catalog_db_path: str):
        """:param catalog_db_path: 既有镜像目录库文件，只读访问。"""
        self.views_db_path = views_db_path
        self.catalog_db_path = catalog_db_path
        self.conn = sqlite3.connect(views_db_path)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.execute("PRAGMA journal_mode = WAL")
        self.conn.executescript(SCHEMA)
        self.conn.commit()
        self._catalog_conn = self._open_catalog_readonly(catalog_db_path)

    def close(self) -> None:
        self.conn.close()
        if self._catalog_conn is not None:
            self._catalog_conn.close()

    @staticmethod
    def _open_catalog_readonly(path: str) -> Optional[sqlite3.Connection]:
        """以只读模式打开目录库；路径按 file URI 转义，避免特殊字符破坏 URI。"""
        if not os.path.exists(path):
            return None
        from urllib.parse import quote
        absolute = os.path.abspath(path)
        uri = "file://" + quote(absolute, safe="/")
        try:
            conn = sqlite3.connect(uri + "?mode=ro", uri=True)
        except sqlite3.OperationalError:
            # 极端环境（内存库、特殊挂载）回退普通连接；本工具仍只执行 SELECT
            conn = sqlite3.connect(path)
        conn.row_factory = sqlite3.Row
        return conn

    # ------------------------------------------------------------------
    # 绑定校验与层序（只读目录库）
    # ------------------------------------------------------------------
    def validate_binding(self, image_digest: str) -> list[ViewDiagnostic]:
        """校验绑定目标是目录中已收录的单平台 image manifest。"""
        try:
            algorithm, _ = parse_digest(image_digest)
            if algorithm != "sha256":
                raise DigestError("只支持 sha256")
        except DigestError as exc:
            return [ViewDiagnostic(
                BINDING_NOT_DIGEST,
                f"绑定目标不是合法 sha256 digest（tag/索引名不可作为绑定）: "
                f"{exc}", image_digest=image_digest)]

        if self._catalog_conn is None:
            return [ViewDiagnostic(
                BINDING_UNKNOWN_DIGEST,
                f"目录库不可用或未收录该 digest: {image_digest}",
                image_digest=image_digest)]
        row = self._catalog_conn.execute(
            "SELECT digest, kind, media_type FROM manifests WHERE digest = ?",
            (image_digest,)).fetchone()
        if row is None:
            return [ViewDiagnostic(
                BINDING_UNKNOWN_DIGEST,
                f"目录中未收录该 digest: {image_digest}",
                image_digest=image_digest)]
        if row["kind"] != "image":
            return [ViewDiagnostic(
                BINDING_NOT_IMAGE,
                f"绑定目标 kind={row['kind']!r} 不是单平台 image manifest "
                f"（index/unknown 不可构建文件视图）: {image_digest}",
                image_digest=image_digest)]
        return []

    def manifest_layers(self, image_digest: str) -> list[sqlite3.Row]:
        """从目录库读取该镜像的层序（position 升序）。"""
        if self._catalog_conn is None:
            return []
        return list(self._catalog_conn.execute(
            "SELECT position, layer_digest, media_type FROM manifest_layers "
            "WHERE manifest_digest = ? ORDER BY position", (image_digest,)))

    # ------------------------------------------------------------------
    # 构建
    # ------------------------------------------------------------------
    def build_view(self, image_digest: str,
                   layer_archives: dict[str, str]) -> BuildResult:
        """为一个单平台镜像构建文件视图。

        :param layer_archives: 调用者提供的 ``layer digest -> 本地归档路径``
            映射；manifest 中每个层都必须有映射，归档字节与层 digest
            必须一致。映射只在本次构建内生效，不缓存、不跨镜像复用
            归并结果。
        """
        diagnostics = self.validate_binding(image_digest)
        if diagnostics:
            return self._record_failure(image_digest, diagnostics)

        layers = self.manifest_layers(image_digest)
        merge = TreeMerge(image_digest)
        used_archives: list[tuple[str, str, str]] = []  # (digest, media, path)
        for layer in layers:
            layer_digest = layer["layer_digest"]
            media_type = layer["media_type"]
            archive_path = layer_archives.get(layer_digest)
            if archive_path is None:
                return self._record_failure(image_digest, [ViewDiagnostic(
                    MISSING_LAYER_ARCHIVE,
                    f"缺少层 {layer_digest} 的本地归档映射"
                    f"（media type {media_type!r}）",
                    image_digest=image_digest, layer_digest=layer_digest)])
            try:
                with open(archive_path, "rb") as fh:
                    raw = fh.read()
            except OSError as exc:
                return self._record_failure(image_digest, [ViewDiagnostic(
                    UNREADABLE_ARCHIVE,
                    f"无法读取层归档文件 {archive_path}: {exc}",
                    image_digest=image_digest, layer_digest=layer_digest)])
            actual = sha256_digest(raw)
            if actual != layer_digest:
                return self._record_failure(image_digest, [ViewDiagnostic(
                    DIGEST_MISMATCH,
                    f"归档原始字节摘要与层 digest 不符: "
                    f"expected={layer_digest} actual={actual}",
                    image_digest=image_digest, layer_digest=layer_digest)])
            try:
                members = parse_layer_archive(raw, media_type, image_digest,
                                              layer_digest)
                merge.apply_layer(layer_digest, members)
            except LayerIngestError as exc:
                return self._record_failure(image_digest, exc.diagnostics)
            used_archives.append((layer_digest, media_type, archive_path))

        return self._commit_view(image_digest, merge, used_archives)

    def _commit_view(self, image_digest: str, merge: TreeMerge,
                     used_archives: list[tuple[str, str, str]]) -> BuildResult:
        """单事务落库：替换旧视图（如有），写入层序、条目与内容。"""
        status = BUILT
        try:
            self.conn.execute("BEGIN")
            existing = self.conn.execute(
                "SELECT view_id FROM image_views WHERE image_digest = ?",
                (image_digest,)).fetchone()
            if existing is not None:
                self.conn.execute("DELETE FROM image_views WHERE view_id = ?",
                                  (existing["view_id"],))
                status = REPLACED
            cur = self.conn.execute(
                "INSERT INTO image_views (image_digest, layer_count, "
                "entry_count, built_at) VALUES (?, ?, ?, ?)",
                (image_digest, len(used_archives), len(merge.entries),
                 _utcnow()))
            view_id = cur.lastrowid
            for position, (layer_digest, media_type, archive_path) in \
                    enumerate(used_archives):
                self.conn.execute(
                    "INSERT INTO view_layers (view_id, position, layer_digest,"
                    " media_type, archive_path) VALUES (?, ?, ?, ?, ?)",
                    (view_id, position, layer_digest, media_type,
                     archive_path))
            for path in sorted(merge.entries):
                entry = merge.entries[path]
                content_id = None
                if entry.content is not None:
                    content_id = self._intern_content(entry.content)
                self.conn.execute(
                    "INSERT INTO entries (view_id, path, entry_type, size, "
                    "mode, layer_digest, member_name, member_index, "
                    "link_target, content_id, implicit) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (view_id, entry.path, entry.entry_type, entry.size,
                     entry.mode, entry.layer_digest, entry.member_name,
                     entry.member_index, entry.link_target, content_id,
                     1 if entry.implicit else 0))
            # 内容表垃圾回收：只保留仍被条目引用的内容
            self.conn.execute(
                "DELETE FROM contents WHERE content_id NOT IN "
                "(SELECT DISTINCT content_id FROM entries "
                " WHERE content_id IS NOT NULL)")
            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise
        return BuildResult(image_digest=image_digest, status=status,
                           view_id=view_id, layer_count=len(used_archives),
                           entry_count=len(merge.entries))

    def _intern_content(self, data: bytes) -> int:
        """按 sha256 内容寻址写入（已存在则复用），返回 content_id。"""
        digest = sha256_digest(data)
        row = self.conn.execute(
            "SELECT content_id FROM contents WHERE sha256 = ?",
            (digest,)).fetchone()
        if row is not None:
            return row["content_id"]
        cur = self.conn.execute(
            "INSERT INTO contents (sha256, size, data) VALUES (?, ?, ?)",
            (digest, len(data), data))
        return cur.lastrowid

    def _record_failure(self, image_digest: str,
                        diagnostics: list[ViewDiagnostic]) -> BuildResult:
        self.conn.execute(
            "INSERT INTO view_failures (image_digest, failed_at, "
            "diagnostics_json) VALUES (?, ?, ?)",
            (image_digest, _utcnow(),
             json.dumps([d.to_dict() for d in diagnostics],
                        ensure_ascii=False)))
        self.conn.commit()
        return BuildResult(image_digest=image_digest, status=FAILED,
                           diagnostics=diagnostics)

    # ------------------------------------------------------------------
    # 辅助查询
    # ------------------------------------------------------------------
    def get_view(self, image_digest: str) -> Optional[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM image_views WHERE image_digest = ?",
            (image_digest,)).fetchone()

    def list_views(self) -> list[sqlite3.Row]:
        return list(self.conn.execute(
            "SELECT * FROM image_views ORDER BY image_digest"))

    def list_view_layers(self, view_id: int) -> list[sqlite3.Row]:
        return list(self.conn.execute(
            "SELECT * FROM view_layers WHERE view_id = ? ORDER BY position",
            (view_id,)))

    def list_failures(self) -> list[sqlite3.Row]:
        return list(self.conn.execute(
            "SELECT * FROM view_failures ORDER BY failure_id"))
