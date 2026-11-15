"""构建证明证据的独立 SQLite 库：原始证据登记、绑定校验与幂等导入。

与其他库的关系：

* **独立数据库文件**：证明证据写入本库；目录库只读打开（校验绑定、带出
  平台上下文），SBOM/文件视图/关系库完全不接触；
* 证据与可信投影分离：本库登记**原始证据**（信封原字节、payload 原字节、
  材料出现位置），“是否可信”是查询时按当前策略对原始证据的即时评价，
  评价历史（策略摘要 + 结论）只追加在 ``evaluations``，旧策略的通过标志
  不会被新评价沿用。

导入语义：

* 每个文件一个事务；结构诊断或绑定校验失败时，不写任何证据行，只在
  ``import_failures`` 留带位置的诊断，失败文件不可能被查成完整构建来源；
* 结构合法但暂不被策略信任的证明**正常入库**——是否可信由查询时的策略
  评价决定，导入不做策略判断；
* 证据身份 = ``(信封字节 sha256, 绑定镜像 digest)``：重复导入相同信封与
  绑定复用既有证据身份（``duplicate_skipped``），换本地文件名不会多算
  证明；同一 payload 不同签名组合是不同的信封字节，因而是不同证据；
* 同一信封绑定到不同镜像（subject 列表含多项）是不同证据行，各自记录
  命中的 subject 位置。
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
from .dsse import ParsedEnvelope, parse_envelope
from .intoto import ParsedStatement, parse_statement
from .jsonutil import Diagnostic

SCHEMA = """
CREATE TABLE IF NOT EXISTS evidence (
    evidence_id     INTEGER PRIMARY KEY AUTOINCREMENT,
    envelope_sha256 TEXT NOT NULL,
    payload_sha256  TEXT NOT NULL,
    payload_type    TEXT NOT NULL,
    image_digest    TEXT NOT NULL,
    envelope_bytes  BLOB NOT NULL,
    payload_bytes   BLOB NOT NULL,
    source_path     TEXT NOT NULL,
    imported_at     TEXT NOT NULL,
    builder_id      TEXT NOT NULL,
    build_type      TEXT NOT NULL,
    invocation_id   TEXT,
    UNIQUE (envelope_sha256, image_digest)
);

CREATE TABLE IF NOT EXISTS evidence_subjects (
    evidence_id     INTEGER NOT NULL
                    REFERENCES evidence(evidence_id) ON DELETE CASCADE,
    subject_index   INTEGER NOT NULL,
    name            TEXT NOT NULL,
    sha256          TEXT NOT NULL,
    matched         INTEGER NOT NULL,
    UNIQUE (evidence_id, subject_index)
);

CREATE TABLE IF NOT EXISTS evidence_materials (
    evidence_id     INTEGER NOT NULL
                    REFERENCES evidence(evidence_id) ON DELETE CASCADE,
    material_index  INTEGER NOT NULL,
    uri             TEXT NOT NULL,
    sha256          TEXT NOT NULL,
    UNIQUE (evidence_id, material_index)
);

CREATE TABLE IF NOT EXISTS evidence_signatures (
    evidence_id     INTEGER NOT NULL
                    REFERENCES evidence(evidence_id) ON DELETE CASCADE,
    sig_index       INTEGER NOT NULL,
    keyid           TEXT,
    sig_hex         TEXT NOT NULL,
    UNIQUE (evidence_id, sig_index)
);

CREATE TABLE IF NOT EXISTS import_failures (
    failure_id      INTEGER PRIMARY KEY AUTOINCREMENT,
    source_path     TEXT NOT NULL,
    content_sha256  TEXT,
    image_digest    TEXT,
    failed_at       TEXT NOT NULL,
    diagnostics_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS evaluations (
    evaluation_id   INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_id     INTEGER NOT NULL
                    REFERENCES evidence(evidence_id) ON DELETE CASCADE,
    policy_sha256   TEXT NOT NULL,
    evaluated_at    TEXT NOT NULL,
    verdict         TEXT NOT NULL,
    reason          TEXT NOT NULL,
    counted_fingerprints_json TEXT NOT NULL,
    signature_reports_json    TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_evidence_image ON evidence(image_digest);
CREATE INDEX IF NOT EXISTS idx_materials_lookup
    ON evidence_materials(uri, sha256);
CREATE INDEX IF NOT EXISTS idx_evaluations_evidence
    ON evaluations(evidence_id);
"""

# 导入结果状态
IMPORTED = "imported"
DUPLICATE_SKIPPED = "duplicate_skipped"
FAILED = "failed"

# 绑定类诊断码
BINDING_NOT_DIGEST = "binding_not_digest"
BINDING_UNKNOWN_DIGEST = "binding_unknown_digest"
BINDING_NOT_IMAGE = "binding_not_image"
BINDING_SUBJECT_MISMATCH = "binding_subject_mismatch"


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class ImportResult:
    """单文件导入结果。"""

    source_path: str
    image_digest: Optional[str]
    status: str
    evidence_id: Optional[int] = None
    envelope_sha256: Optional[str] = None
    payload_sha256: Optional[str] = None
    matched_subjects: list[int] = field(default_factory=list)
    materials: int = 0
    signatures: int = 0
    diagnostics: list[Diagnostic] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.status != FAILED

    def to_dict(self) -> dict:
        return {
            "source_path": self.source_path,
            "image_digest": self.image_digest,
            "status": self.status,
            "evidence_id": self.evidence_id,
            "envelope_sha256": self.envelope_sha256,
            "payload_sha256": self.payload_sha256,
            "matched_subjects": self.matched_subjects,
            "materials": self.materials,
            "signatures": self.signatures,
            "diagnostics": [d.to_dict() for d in self.diagnostics],
        }


class ProvenanceStore:
    """构建证明证据的独立 SQLite 存储。"""

    def __init__(self, provenance_db_path: str, catalog_db_path: str):
        """:param catalog_db_path: 既有镜像目录库文件，只读访问。"""
        self.provenance_db_path = provenance_db_path
        self.catalog_db_path = catalog_db_path
        self.conn = sqlite3.connect(provenance_db_path)
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
        """以只读模式打开目录库；路径按 file URI 转义。"""
        if not os.path.exists(path):
            return None
        from urllib.parse import quote
        absolute = os.path.abspath(path)
        uri = "file://" + quote(absolute, safe="/")
        try:
            conn = sqlite3.connect(uri + "?mode=ro", uri=True)
        except sqlite3.OperationalError:
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
                f"绑定目标不是合法 sha256 digest（tag/索引名不可作为绑定）: "
                f"{exc}", "$.binding"))
            return diagnostics

        if self._catalog_conn is None:
            diagnostics.append(Diagnostic(
                BINDING_UNKNOWN_DIGEST,
                f"目录库不可用或未收录该 digest: {image_digest}", "$.binding"))
            return diagnostics
        row = self._catalog_conn.execute(
            "SELECT digest, kind FROM manifests WHERE digest = ?",
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
                f"（index/unknown 不可绑定）: {image_digest}", "$.binding"))
        return diagnostics

    def lookup_image_platform(self, image_digest: str) -> Optional[dict]:
        """从目录库带出镜像平台上下文（取字典序最小的一份，结果确定）。"""
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
        """导入单个 DSSE 信封文件；单文件事务，失败不留可查询证据。"""
        envelope_sha = "sha256:" + hashlib.sha256(raw_bytes).hexdigest()

        # 1. 全部只读校验：信封结构 -> payload 结构 -> 绑定
        envelope = parse_envelope(raw_bytes)
        diagnostics = list(envelope.diagnostics)
        statement = ParsedStatement()
        payload_sha: Optional[str] = None
        if envelope.ok:
            assert envelope.payload is not None
            payload_sha = "sha256:" + hashlib.sha256(envelope.payload).hexdigest()
            statement = parse_statement(envelope.payload)
            diagnostics.extend(statement.diagnostics)
        diagnostics.extend(self.validate_binding(image_digest))
        matched: list[int] = []
        if statement.ok and not any(
                d.code.startswith("binding_") for d in diagnostics):
            bound_hex = image_digest.split(":", 1)[1].lower()
            matched = [s.index for s in statement.subjects
                       if s.sha256 == bound_hex]
            if not matched:
                diagnostics.append(Diagnostic(
                    BINDING_SUBJECT_MISMATCH,
                    f"声明的 subject 中没有 sha256 等于绑定镜像 {image_digest} "
                    f"的项（不按 name/tag 猜测绑定）", "payload:$.subject"))

        if diagnostics:
            return self._record_failure(source_path, image_digest,
                                        envelope_sha, diagnostics)

        # 2. 幂等：同信封字节 + 同绑定镜像 -> 复用既有证据身份
        existing = self.conn.execute(
            "SELECT evidence_id FROM evidence "
            "WHERE envelope_sha256 = ? AND image_digest = ?",
            (envelope_sha, image_digest)).fetchone()
        if existing is not None:
            return ImportResult(
                source_path=source_path, image_digest=image_digest,
                status=DUPLICATE_SKIPPED,
                evidence_id=existing["evidence_id"],
                envelope_sha256=envelope_sha, payload_sha256=payload_sha,
                matched_subjects=matched,
                materials=len(statement.materials),
                signatures=len(envelope.signatures))

        # 3. 单事务登记原始证据
        try:
            self.conn.execute("BEGIN")
            cur = self.conn.execute(
                "INSERT INTO evidence (envelope_sha256, payload_sha256, "
                "payload_type, image_digest, envelope_bytes, payload_bytes, "
                "source_path, imported_at, builder_id, build_type, "
                "invocation_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (envelope_sha, payload_sha, envelope.payload_type,
                 image_digest, raw_bytes, envelope.payload, source_path,
                 _utcnow(), statement.builder_id, statement.build_type,
                 statement.invocation_id))
            evidence_id = cur.lastrowid
            for subject in statement.subjects:
                self.conn.execute(
                    "INSERT INTO evidence_subjects (evidence_id, "
                    "subject_index, name, sha256, matched) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (evidence_id, subject.index, subject.name,
                     subject.sha256, 1 if subject.index in matched else 0))
            for material in statement.materials:
                self.conn.execute(
                    "INSERT INTO evidence_materials (evidence_id, "
                    "material_index, uri, sha256) VALUES (?, ?, ?, ?)",
                    (evidence_id, material.index, material.uri,
                     material.sha256))
            for signature in envelope.signatures:
                self.conn.execute(
                    "INSERT INTO evidence_signatures (evidence_id, "
                    "sig_index, keyid, sig_hex) VALUES (?, ?, ?, ?)",
                    (evidence_id, signature.index, signature.keyid,
                     signature.sig.hex()))
            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise

        return ImportResult(
            source_path=source_path, image_digest=image_digest,
            status=IMPORTED, evidence_id=evidence_id,
            envelope_sha256=envelope_sha, payload_sha256=payload_sha,
            matched_subjects=matched,
            materials=len(statement.materials),
            signatures=len(envelope.signatures))

    def import_paths(self, items: list[tuple[str, str]]) -> list[ImportResult]:
        """批量导入：``items`` 为 [(信封路径, 绑定 image digest), ...]。"""
        results: list[ImportResult] = []
        for source_path, image_digest in items:
            try:
                with open(source_path, "rb") as fh:
                    raw_bytes = fh.read()
            except OSError as exc:
                diag = Diagnostic("unreadable_file",
                                  f"无法读取信封文件: {exc}", "$.source")
                results.append(self._record_failure(
                    source_path, image_digest, None, [diag]))
                continue
            results.append(self.import_file(source_path, image_digest,
                                            raw_bytes))
        return results

    def _record_failure(self, source_path: str, image_digest: Optional[str],
                        content_sha: Optional[str],
                        diagnostics: list[Diagnostic]) -> ImportResult:
        self.conn.execute(
            "INSERT INTO import_failures (source_path, content_sha256, "
            "image_digest, failed_at, diagnostics_json) "
            "VALUES (?, ?, ?, ?, ?)",
            (source_path, content_sha, image_digest, _utcnow(),
             json.dumps([d.to_dict() for d in diagnostics],
                        ensure_ascii=False)))
        self.conn.commit()
        return ImportResult(
            source_path=source_path, image_digest=image_digest,
            status=FAILED, diagnostics=diagnostics)

    # ------------------------------------------------------------------
    # 证据读取（评价与查询共用）
    # ------------------------------------------------------------------
    def get_evidence(self, evidence_id: int) -> Optional[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM evidence WHERE evidence_id = ?",
            (evidence_id,)).fetchone()

    def list_evidence_for_image(self, image_digest: str) -> list[sqlite3.Row]:
        return list(self.conn.execute(
            "SELECT * FROM evidence WHERE image_digest = ? "
            "ORDER BY evidence_id", (image_digest,)))

    def list_all_evidence(self) -> list[sqlite3.Row]:
        return list(self.conn.execute(
            "SELECT * FROM evidence ORDER BY evidence_id"))

    def list_subjects(self, evidence_id: int) -> list[sqlite3.Row]:
        return list(self.conn.execute(
            "SELECT * FROM evidence_subjects WHERE evidence_id = ? "
            "ORDER BY subject_index", (evidence_id,)))

    def list_materials(self, evidence_id: int) -> list[sqlite3.Row]:
        return list(self.conn.execute(
            "SELECT * FROM evidence_materials WHERE evidence_id = ? "
            "ORDER BY material_index", (evidence_id,)))

    def list_signatures(self, evidence_id: int) -> list[sqlite3.Row]:
        return list(self.conn.execute(
            "SELECT * FROM evidence_signatures WHERE evidence_id = ? "
            "ORDER BY sig_index", (evidence_id,)))

    def record_evaluation(self, evidence_id: int, policy_sha256: str,
                          verdict: str, reason: str,
                          counted: list[str],
                          signature_reports: list[dict]) -> None:
        """追加一条评价历史（策略摘要 + 结论），供审计说明依据。"""
        self.conn.execute(
            "INSERT INTO evaluations (evidence_id, policy_sha256, "
            "evaluated_at, verdict, reason, counted_fingerprints_json, "
            "signature_reports_json) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (evidence_id, policy_sha256, _utcnow(), verdict, reason,
             json.dumps(counted), json.dumps(signature_reports,
                                             ensure_ascii=False)))
        self.conn.commit()

    def list_evaluations(self, evidence_id: Optional[int] = None
                         ) -> list[sqlite3.Row]:
        if evidence_id is None:
            return list(self.conn.execute(
                "SELECT * FROM evaluations ORDER BY evaluation_id"))
        return list(self.conn.execute(
            "SELECT * FROM evaluations WHERE evidence_id = ? "
            "ORDER BY evaluation_id", (evidence_id,)))

    def list_failures(self) -> list[sqlite3.Row]:
        return list(self.conn.execute(
            "SELECT * FROM import_failures ORDER BY failure_id"))
