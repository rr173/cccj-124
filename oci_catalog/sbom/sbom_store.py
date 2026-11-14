"""SBOM 独立 SQLite 库：镜像绑定校验、单文件事务导入与幂等处理。

与镜像目录库的关系：

* **独立数据库文件**：SBOM 数据写入本库，目录库（:class:`CatalogStore` 的
  SQLite 文件）只以只读方式打开，用于校验绑定并带出平台上下文；导入过程
  不写目录库，因此不会产生任何 tag 事件。
* 绑定目标必须是目录中已收录的**单平台 image manifest**（``kind='image'``）：
  tag、index digest、unknown manifest、未收录摘要一律拒绝。

事务与失败语义：

* 每个文件一个事务。解析诊断或绑定校验失败时，本文件不写入任何
  components/occurrences/edges，仅在 ``import_failures`` 留一条带诊断的记录，
  失败文件不可能被查询成一份完整清单。
* 不同文件互不影响，批量导入逐文件返回成功/失败。

重复文件语义（内容按 sha256 寻址，源路径由调用者给出）：

* 同 ``source_path`` 再次导入：替换旧文件及其全部出现/边（``replaced``），
  不保留修订历史；
* 不同 ``source_path`` 但内容 sha256 与绑定 digest 都相同：跳过
  （``duplicate_skipped``），报告实际跳过；
* 同内容绑定到**不同**镜像 digest：视为独立文件正常导入（``imported``），
  因为绑定上下文不同。
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from ..digest import DigestError, parse_digest
from .sbom_parser import Diagnostic, ParsedDocument, parse_document

SCHEMA = """
CREATE TABLE IF NOT EXISTS components (
    component_id    INTEGER PRIMARY KEY AUTOINCREMENT,
    canonical_purl  TEXT NOT NULL UNIQUE,
    purl_type       TEXT NOT NULL,
    name            TEXT NOT NULL,
    version         TEXT
);

CREATE TABLE IF NOT EXISTS sbom_files (
    file_id         INTEGER PRIMARY KEY AUTOINCREMENT,
    source_path     TEXT NOT NULL UNIQUE,
    content_sha256  TEXT NOT NULL,
    doc_format      TEXT NOT NULL,
    image_digest    TEXT NOT NULL,
    imported_at     TEXT NOT NULL,
    UNIQUE (content_sha256, image_digest)
);

CREATE TABLE IF NOT EXISTS occurrences (
    occurrence_id   INTEGER PRIMARY KEY AUTOINCREMENT,
    file_id         INTEGER NOT NULL REFERENCES sbom_files(file_id) ON DELETE CASCADE,
    component_id    INTEGER REFERENCES components(component_id),
    file_ref        TEXT NOT NULL,
    name            TEXT NOT NULL,
    version         TEXT NOT NULL DEFAULT '',
    supplier        TEXT NOT NULL DEFAULT '',
    license_raw     TEXT NOT NULL DEFAULT '',
    location        TEXT NOT NULL,
    purl_raw        TEXT NOT NULL DEFAULT '',
    UNIQUE (file_id, file_ref)
);

CREATE TABLE IF NOT EXISTS dependency_edges (
    edge_id         INTEGER PRIMARY KEY AUTOINCREMENT,
    file_id         INTEGER NOT NULL REFERENCES sbom_files(file_id) ON DELETE CASCADE,
    from_ref        TEXT NOT NULL,
    to_ref          TEXT NOT NULL,
    edge_location   TEXT NOT NULL,
    UNIQUE (file_id, from_ref, to_ref)
);

CREATE TABLE IF NOT EXISTS import_failures (
    failure_id      INTEGER PRIMARY KEY AUTOINCREMENT,
    source_path     TEXT NOT NULL,
    content_sha256  TEXT,
    image_digest    TEXT,
    failed_at       TEXT NOT NULL,
    diagnostics_json TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_occurrences_component
    ON occurrences(component_id);
CREATE INDEX IF NOT EXISTS idx_occurrences_file ON occurrences(file_id);
CREATE INDEX IF NOT EXISTS idx_edges_file ON dependency_edges(file_id);
CREATE INDEX IF NOT EXISTS idx_sbom_image ON sbom_files(image_digest);
"""

# 导入结果状态
IMPORTED = "imported"
REPLACED = "replaced"
DUPLICATE_SKIPPED = "duplicate_skipped"
FAILED = "failed"

# 绑定类诊断码
BINDING_NOT_DIGEST = "binding_not_digest"
BINDING_UNKNOWN_DIGEST = "binding_unknown_digest"
BINDING_NOT_IMAGE = "binding_not_image"


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class ImportResult:
    """单文件导入结果。"""

    source_path: str
    image_digest: Optional[str]
    status: str
    file_id: Optional[int] = None
    components: int = 0
    edges: int = 0
    diagnostics: list[Diagnostic] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.status != FAILED

    def to_dict(self) -> dict:
        return {
            "source_path": self.source_path,
            "image_digest": self.image_digest,
            "status": self.status,
            "file_id": self.file_id,
            "components": self.components,
            "edges": self.edges,
            "diagnostics": [d.to_dict() for d in self.diagnostics],
        }


class SBOMStore:
    """SBOM 清单的独立 SQLite 存储。"""

    def __init__(self, sbom_db_path: str, catalog_db_path: str):
        """:param catalog_db_path: 既有镜像目录库文件，只读访问。"""
        self.sbom_db_path = sbom_db_path
        self.catalog_db_path = catalog_db_path
        self.conn = sqlite3.connect(sbom_db_path)
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
        # 三斜杠：file:// + 绝对路径（以 / 开头）
        uri = "file://" + quote(absolute, safe="/")
        try:
            conn = sqlite3.connect(uri + "?mode=ro", uri=True)
        except sqlite3.OperationalError:
            # 极端环境（内存库、特殊挂载）回退普通连接；本工具仍只执行 SELECT
            conn = sqlite3.connect(path)
        conn.row_factory = sqlite3.Row
        return conn

    # ------------------------------------------------------------------
    # 镜像绑定校验（只读目录库）
    # ------------------------------------------------------------------
    def validate_binding(self, image_digest: str) -> list[Diagnostic]:
        """校验绑定目标是目录中已收录的单平台 image manifest。"""
        diagnostics: list[Diagnostic] = []
        try:
            algorithm, _ = parse_digest(image_digest)
            if algorithm != "sha256":
                raise DigestError("只支持 sha256")
        except DigestError as exc:
            diagnostics.append(Diagnostic(
                BINDING_NOT_DIGEST,
                f"绑定目标不是合法 sha256 digest（tag/索引名不可作为绑定）: {exc}",
                "$.binding"))
            return diagnostics

        if self._catalog_conn is None:
            diagnostics.append(Diagnostic(
                BINDING_UNKNOWN_DIGEST,
                f"目录库不可用或未收录该 digest: {image_digest}", "$.binding"))
            return diagnostics
        row = self._catalog_conn.execute(
            "SELECT digest, kind, media_type FROM manifests WHERE digest = ?",
            (image_digest,)).fetchone()
        if row is None:
            diagnostics.append(Diagnostic(
                BINDING_UNKNOWN_DIGEST,
                f"目录中未收录该 digest: {image_digest}", "$.binding"))
            return diagnostics
        if row["kind"] != "image":
            diagnostics.append(Diagnostic(
                BINDING_NOT_IMAGE,
                f"绑定目标 kind={row['kind']!r} 不是单平台 image manifest "
                f"（index/unknown 不可绑定）: {image_digest}",
                "$.binding"))
        return diagnostics

    def lookup_image_platform(self, image_digest: str) -> Optional[dict]:
        """从目录库带出镜像的平台上下文（引用该 image 的 descriptor 平台）。

        同一 image digest 可能被多个 index 引用，平台描述以各 descriptor
        自带的 ``platform`` 为准；这里取字典序最小的一份，保证结果确定。
        无索引引用（直接 push 的单平台镜像）时返回 None。
        """
        if self._catalog_conn is None:
            return None
        rows = self._catalog_conn.execute(
            "SELECT platform_json FROM manifest_children "
            "WHERE child_digest = ? AND platform_json IS NOT NULL "
            "ORDER BY platform_json", (image_digest,)).fetchall()
        if not rows:
            return None
        return json.loads(rows[0]["platform_json"])

    # ------------------------------------------------------------------
    # 导入
    # ------------------------------------------------------------------
    def import_file(self, source_path: str, image_digest: str,
                    raw_bytes: bytes) -> ImportResult:
        """导入单个清单文件；单文件事务，失败不留任何可查询清单数据。"""
        content_sha = "sha256:" + hashlib.sha256(raw_bytes).hexdigest()

        # 1. 先做全部只读校验，任何失败都不进入写事务
        parsed = parse_document(raw_bytes)
        diagnostics = list(parsed.diagnostics)
        diagnostics.extend(self.validate_binding(image_digest))
        if diagnostics:
            return self._record_failure(source_path, image_digest,
                                        content_sha, diagnostics)

        # 2. 幂等判定
        existing_path = self.conn.execute(
            "SELECT file_id FROM sbom_files WHERE source_path = ?",
            (source_path,)).fetchone()
        existing_content = self.conn.execute(
            "SELECT file_id, source_path FROM sbom_files "
            "WHERE content_sha256 = ? AND image_digest = ?",
            (content_sha, image_digest)).fetchone()
        if existing_path is None and existing_content is not None:
            return ImportResult(
                source_path=source_path, image_digest=image_digest,
                status=DUPLICATE_SKIPPED,
                file_id=existing_content["file_id"],
                components=0, edges=0)

        try:
            self.conn.execute("BEGIN")
            status = IMPORTED
            if existing_path is not None:
                # 同路径重导：级联清除旧出现/边，文件行原地替换
                self.conn.execute(
                    "DELETE FROM sbom_files WHERE file_id = ?",
                    (existing_path["file_id"],))
                status = REPLACED
            cur = self.conn.execute(
                "INSERT INTO sbom_files (source_path, content_sha256, doc_format, "
                "image_digest, imported_at) VALUES (?, ?, ?, ?, ?)",
                (source_path, content_sha, parsed.doc_format,
                 image_digest, _utcnow()))
            file_id = cur.lastrowid

            self._insert_components(file_id, parsed)
            edge_count = self._insert_edges(file_id, parsed)
            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise

        return ImportResult(
            source_path=source_path, image_digest=image_digest,
            status=status, file_id=file_id,
            components=len(parsed.components), edges=edge_count)

    def import_paths(self, items: list[tuple[str, str]]) -> list[ImportResult]:
        """批量导入：``items`` 为 [(源文件路径, 绑定 image digest), ...]。

        每个文件独立成功/失败；文件不可读也按单文件失败报告，不影响其余文件。
        """
        results: list[ImportResult] = []
        for source_path, image_digest in items:
            try:
                with open(source_path, "rb") as fh:
                    raw_bytes = fh.read()
            except OSError as exc:
                diag = Diagnostic("unreadable_file",
                                  f"无法读取清单文件: {exc}", "$.source")
                results.append(self._record_failure(
                    source_path, image_digest, None, [diag]))
                continue
            results.append(self.import_file(source_path, image_digest, raw_bytes))
        return results

    def _record_failure(self, source_path: str, image_digest: Optional[str],
                        content_sha: Optional[str],
                        diagnostics: list[Diagnostic]) -> ImportResult:
        self.conn.execute(
            "INSERT INTO import_failures (source_path, content_sha256, "
            "image_digest, failed_at, diagnostics_json) VALUES (?, ?, ?, ?, ?)",
            (source_path, content_sha, image_digest, _utcnow(),
             json.dumps([d.to_dict() for d in diagnostics],
                        ensure_ascii=False)))
        self.conn.commit()
        return ImportResult(
            source_path=source_path, image_digest=image_digest,
            status=FAILED, diagnostics=diagnostics)

    def _insert_components(self, file_id: int, parsed: ParsedDocument) -> None:
        for raw in parsed.components:
            component_id = None
            if raw.purl is not None:
                canonical = raw.purl.canonical
                row = self.conn.execute(
                    "SELECT component_id FROM components WHERE canonical_purl = ?",
                    (canonical,)).fetchone()
                if row is None:
                    cur = self.conn.execute(
                        "INSERT INTO components (canonical_purl, purl_type, "
                        "name, version) VALUES (?, ?, ?, ?)",
                        (canonical, raw.purl.type, raw.purl.name,
                         raw.purl.version))
                    component_id = cur.lastrowid
                else:
                    component_id = row["component_id"]
            self.conn.execute(
                "INSERT INTO occurrences (file_id, component_id, file_ref, "
                "name, version, supplier, license_raw, location, purl_raw) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (file_id, component_id, raw.ref, raw.name, raw.version,
                 raw.supplier, raw.license_raw, raw.location, raw.purl_raw))

    def _insert_edges(self, file_id: int, parsed: ParsedDocument) -> int:
        for from_ref, to_ref, edge_location in parsed.edges:
            self.conn.execute(
                "INSERT INTO dependency_edges (file_id, from_ref, to_ref, "
                "edge_location) VALUES (?, ?, ?, ?)",
                (file_id, from_ref, to_ref, edge_location))
        return len(parsed.edges)

    # ------------------------------------------------------------------
    # 辅助查询
    # ------------------------------------------------------------------
    def list_files_for_image(self, image_digest: str) -> list[sqlite3.Row]:
        return list(self.conn.execute(
            "SELECT * FROM sbom_files WHERE image_digest = ? "
            "ORDER BY file_id", (image_digest,)))

    def list_failures(self) -> list[sqlite3.Row]:
        return list(self.conn.execute(
            "SELECT * FROM import_failures ORDER BY failure_id"))
