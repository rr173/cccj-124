"""SQLite 持久化层。

设计要点：

* **内容与名称分离**：manifest 按 digest 全局唯一存储，多个 tag 引用同一 digest
  时只建立一次内容身份；tag 只是可变名称，其变化写入事件历史。
* **repository 边界事务**：单个 repository 的采集结果在一个事务内提交，任何
  阶段失败（含 digest 不符）整体回滚，保证续办时重新完整采集该仓库。
* **检查点**：记录每个 scan 已完成的 repository，中断后从边界继续。
* **隔离表**：digest 校验失败的仓库被标记隔离，后续扫描直接跳过。
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Iterator, Optional

from .models import (
    ManifestInfo,
    Platform,
    QuarantineReason,
    ScanStatus,
    TagEventType,
)

SCHEMA = """
CREATE TABLE IF NOT EXISTS scan_runs (
    scan_id          INTEGER PRIMARY KEY AUTOINCREMENT,
    registry         TEXT NOT NULL,
    status           TEXT NOT NULL,
    started_at       TEXT NOT NULL,
    finished_at      TEXT,
    interrupt_reason TEXT
);

CREATE TABLE IF NOT EXISTS repo_scan_states (
    scan_id     INTEGER NOT NULL,
    repository  TEXT NOT NULL,
    status      TEXT NOT NULL,
    started_at  TEXT NOT NULL,
    finished_at TEXT,
    PRIMARY KEY (scan_id, repository)
);

-- 每个 registry 下 repository 的最新完成位置（续办检查点）
CREATE TABLE IF NOT EXISTS checkpoints (
    registry        TEXT PRIMARY KEY,
    last_scan_id    INTEGER NOT NULL,
    last_repository TEXT
);

CREATE TABLE IF NOT EXISTS quarantined_repos (
    registry    TEXT NOT NULL,
    repository  TEXT NOT NULL,
    reason      TEXT NOT NULL,
    expected    TEXT,
    actual      TEXT,
    quarantined_at TEXT NOT NULL,
    PRIMARY KEY (registry, repository)
);

-- 内容身份表：digest 全局唯一，天然去重
CREATE TABLE IF NOT EXISTS manifests (
    digest         TEXT PRIMARY KEY,
    media_type     TEXT NOT NULL,
    kind           TEXT NOT NULL,
    size           INTEGER NOT NULL DEFAULT 0,
    config_digest  TEXT,
    config_media   TEXT,
    subject_digest TEXT,
    first_seen_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS manifest_layers (
    manifest_digest TEXT NOT NULL,
    position        INTEGER NOT NULL,
    layer_digest    TEXT NOT NULL,
    media_type      TEXT NOT NULL,
    size            INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (manifest_digest, position)
);

-- 索引型 manifest 的展开关系（子 manifest descriptor 及平台）
CREATE TABLE IF NOT EXISTS manifest_children (
    parent_digest   TEXT NOT NULL,
    position        INTEGER NOT NULL,
    child_digest    TEXT NOT NULL,
    media_type      TEXT NOT NULL,
    size            INTEGER NOT NULL DEFAULT 0,
    platform_json   TEXT,
    annotations_json TEXT,
    PRIMARY KEY (parent_digest, position)
);

-- 每个 repository 内 tag 的当前指向（删 tag 时移除行）
CREATE TABLE IF NOT EXISTS tag_state (
    registry    TEXT NOT NULL,
    repository  TEXT NOT NULL,
    tag         TEXT NOT NULL,
    digest      TEXT NOT NULL,
    media_type  TEXT NOT NULL,
    updated_at  TEXT NOT NULL,
    PRIMARY KEY (registry, repository, tag)
);

-- tag -> digest 的完整历史事件流（只追加）
CREATE TABLE IF NOT EXISTS tag_events (
    event_id    INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     INTEGER NOT NULL,
    registry    TEXT NOT NULL,
    repository  TEXT NOT NULL,
    tag         TEXT NOT NULL,
    event_type  TEXT NOT NULL,
    old_digest  TEXT,
    new_digest  TEXT,
    observed_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tag_events_lookup
    ON tag_events (registry, repository, tag, event_id);

-- 每次扫描观察到的完整 tag 快照，用于两次目录扫描对比
CREATE TABLE IF NOT EXISTS tag_observations (
    scan_id     INTEGER NOT NULL,
    registry    TEXT NOT NULL,
    repository  TEXT NOT NULL,
    tag         TEXT NOT NULL,
    digest      TEXT NOT NULL,
    media_type  TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    PRIMARY KEY (scan_id, registry, repository, tag)
);
CREATE INDEX IF NOT EXISTS idx_observations_ns
    ON tag_observations (registry, scan_id, repository);
"""


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _platform_to_json(platform: Optional[Platform]) -> Optional[str]:
    return json.dumps(platform.to_dict(), separators=(",", ":")) if platform else None


class CatalogStore:
    """采集结果的 SQLite 存储。"""

    def __init__(self, path: str):
        # check_same_thread=False 配合短事务；写入仍由调用方串行化
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.execute("PRAGMA journal_mode = WAL")
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        try:
            yield self.conn
            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise

    # ------------------------------------------------------------------
    # 扫描生命周期
    # ------------------------------------------------------------------
    def start_scan(self, registry: str) -> tuple[int, bool, Optional[str]]:
        """开始一次扫描。

        若该 registry 存在未完成（interrupted）的 scan，则续办它；
        返回 (scan_id, resumed, last_repository)。
        """
        row = self.conn.execute(
            "SELECT scan_id, status FROM scan_runs "
            "WHERE registry = ? AND status = ? ORDER BY scan_id DESC LIMIT 1",
            (registry, ScanStatus.SCAN_INTERRUPTED.value),
        ).fetchone()
        now = _utcnow()
        if row is not None:
            scan_id = row["scan_id"]
            self.conn.execute(
                "UPDATE scan_runs SET status = ? WHERE scan_id = ?",
                (ScanStatus.SCAN_RUNNING.value, scan_id),
            )
            checkpoint = self.get_checkpoint(registry)
            self.conn.commit()
            return scan_id, True, checkpoint
        cur = self.conn.execute(
            "INSERT INTO scan_runs (registry, status, started_at) VALUES (?, ?, ?)",
            (registry, ScanStatus.SCAN_RUNNING.value, now),
        )
        self.conn.commit()
        return cur.lastrowid, False, None

    def interrupt_scan(self, scan_id: int, reason: str) -> None:
        self.conn.execute(
            "UPDATE scan_runs SET status = ?, interrupt_reason = ? WHERE scan_id = ?",
            (ScanStatus.SCAN_INTERRUPTED.value, reason, scan_id),
        )
        self.conn.commit()

    def complete_scan(self, scan_id: int) -> None:
        self.conn.execute(
            "UPDATE scan_runs SET status = ?, finished_at = ? WHERE scan_id = ?",
            (ScanStatus.SCAN_COMPLETED.value, _utcnow(), scan_id),
        )
        self.conn.commit()

    def get_scan_status(self, scan_id: int) -> Optional[str]:
        row = self.conn.execute(
            "SELECT status FROM scan_runs WHERE scan_id = ?", (scan_id,)
        ).fetchone()
        return row["status"] if row else None

    def list_scans(self, registry: Optional[str] = None) -> list[sqlite3.Row]:
        if registry is None:
            return list(self.conn.execute(
                "SELECT * FROM scan_runs ORDER BY scan_id"))
        return list(self.conn.execute(
            "SELECT * FROM scan_runs WHERE registry = ? ORDER BY scan_id",
            (registry,)))

    # ------------------------------------------------------------------
    # 检查点 / 仓库状态 / 隔离
    # ------------------------------------------------------------------
    def get_checkpoint(self, registry: str) -> Optional[str]:
        row = self.conn.execute(
            "SELECT last_repository FROM checkpoints WHERE registry = ?",
            (registry,),
        ).fetchone()
        return row["last_repository"] if row else None

    def is_repo_completed(self, scan_id: int, repository: str) -> bool:
        row = self.conn.execute(
            "SELECT status FROM repo_scan_states WHERE scan_id = ? AND repository = ?",
            (scan_id, repository),
        ).fetchone()
        return row is not None and row["status"] == ScanStatus.SCAN_COMPLETED.value

    def is_quarantined(self, registry: str, repository: str) -> bool:
        row = self.conn.execute(
            "SELECT 1 FROM quarantined_repos WHERE registry = ? AND repository = ?",
            (registry, repository),
        ).fetchone()
        return row is not None

    def quarantine_repo(self, registry: str, repository: str,
                        reason: QuarantineReason, expected: str = "",
                        actual: str = "") -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO quarantined_repos "
            "(registry, repository, reason, expected, actual, quarantined_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (registry, repository, reason.value, expected, actual, _utcnow()),
        )
        self.conn.commit()

    def list_quarantined(self, registry: Optional[str] = None) -> list[sqlite3.Row]:
        if registry is None:
            return list(self.conn.execute(
                "SELECT * FROM quarantined_repos ORDER BY registry, repository"))
        return list(self.conn.execute(
            "SELECT * FROM quarantined_repos WHERE registry = ? "
            "ORDER BY repository", (registry,)))

    # ------------------------------------------------------------------
    # repository 边界事务
    # ------------------------------------------------------------------
    def begin_repo_ingestion(self, scan_id: int, registry: str,
                             repository: str) -> bool:
        """准备采集某 repository。返回 False 表示仓库已隔离，必须跳过。"""
        if self.is_quarantined(registry, repository):
            return False
        now = _utcnow()
        self.conn.execute(
            "INSERT INTO repo_scan_states (scan_id, repository, status, started_at) "
            "VALUES (?, ?, ?, ?) "
            "ON CONFLICT(scan_id, repository) DO UPDATE SET "
            "status = excluded.status, started_at = excluded.started_at",
            (scan_id, repository, ScanStatus.SCAN_RUNNING.value, now),
        )
        return True

    def commit_repo_ingestion(self, scan_id: int, registry: str,
                              repository: str) -> None:
        now = _utcnow()
        self.conn.execute(
            "UPDATE repo_scan_states SET status = ?, finished_at = ? "
            "WHERE scan_id = ? AND repository = ?",
            (ScanStatus.SCAN_COMPLETED.value, now, scan_id, repository),
        )
        self.conn.execute(
            "INSERT INTO checkpoints (registry, last_scan_id, last_repository) "
            "VALUES (?, ?, ?) ON CONFLICT(registry) DO UPDATE SET "
            "last_scan_id = excluded.last_scan_id, "
            "last_repository = excluded.last_repository",
            (registry, scan_id, repository),
        )
        self.conn.commit()

    def rollback_repo_ingestion(self) -> None:
        self.conn.rollback()

    # ------------------------------------------------------------------
    # 内容身份（digest 唯一）
    # ------------------------------------------------------------------
    def has_manifest(self, digest: str) -> bool:
        row = self.conn.execute(
            "SELECT 1 FROM manifests WHERE digest = ?", (digest,)
        ).fetchone()
        return row is not None

    def upsert_manifest(self, info: ManifestInfo) -> bool:
        """登记 manifest 内容身份。已存在则直接返回 False（不重复建立身份）。"""
        if self.has_manifest(info.digest):
            return False
        now = _utcnow()
        self.conn.execute(
            "INSERT INTO manifests "
            "(digest, media_type, kind, size, config_digest, config_media, "
            "subject_digest, first_seen_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                info.digest, info.media_type, info.kind.value, info.size,
                info.config.digest if info.config else None,
                info.config.media_type if info.config else None,
                info.subject.digest if info.subject else None,
                now,
            ),
        )
        for position, layer in enumerate(info.layers):
            self.conn.execute(
                "INSERT OR REPLACE INTO manifest_layers "
                "(manifest_digest, position, layer_digest, media_type, size) "
                "VALUES (?, ?, ?, ?, ?)",
                (info.digest, position, layer.digest, layer.media_type, layer.size),
            )
        for position, child in enumerate(info.manifests):
            self.conn.execute(
                "INSERT OR REPLACE INTO manifest_children "
                "(parent_digest, position, child_digest, media_type, size, "
                "platform_json, annotations_json) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    info.digest, position, child.digest, child.media_type,
                    child.size, _platform_to_json(child.platform),
                    json.dumps(child.annotations, separators=(",", ":"))
                    if child.annotations else None,
                ),
            )
        return True

    # ------------------------------------------------------------------
    # tag 状态与事件
    # ------------------------------------------------------------------
    def record_tag_observation(self, scan_id: int, registry: str,
                               repository: str, tag: str, digest: str,
                               media_type: str) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO tag_observations "
            "(scan_id, registry, repository, tag, digest, media_type, observed_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (scan_id, registry, repository, tag, digest, media_type, _utcnow()),
        )

    def record_tag_event(self, scan_id: int, registry: str, repository: str,
                         tag: str, event_type: TagEventType,
                         old_digest: Optional[str], new_digest: Optional[str]) -> None:
        self.conn.execute(
            "INSERT INTO tag_events "
            "(scan_id, registry, repository, tag, event_type, old_digest, "
            "new_digest, observed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (scan_id, registry, repository, tag, event_type.value,
             old_digest, new_digest, _utcnow()),
        )

    def get_tag_state(self, registry: str, repository: str,
                      tag: str) -> Optional[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM tag_state WHERE registry = ? AND repository = ? AND tag = ?",
            (registry, repository, tag),
        ).fetchone()

    def upsert_tag_state(self, registry: str, repository: str, tag: str,
                         digest: str, media_type: str) -> None:
        self.conn.execute(
            "INSERT INTO tag_state (registry, repository, tag, digest, media_type, "
            "updated_at) VALUES (?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(registry, repository, tag) DO UPDATE SET "
            "digest = excluded.digest, media_type = excluded.media_type, "
            "updated_at = excluded.updated_at",
            (registry, repository, tag, digest, media_type, _utcnow()),
        )

    def delete_tag_state(self, registry: str, repository: str, tag: str) -> None:
        self.conn.execute(
            "DELETE FROM tag_state WHERE registry = ? AND repository = ? AND tag = ?",
            (registry, repository, tag),
        )

    def list_tag_states(self, registry: str, repository: str) -> list[sqlite3.Row]:
        return list(self.conn.execute(
            "SELECT * FROM tag_state WHERE registry = ? AND repository = ? "
            "ORDER BY tag", (registry, repository)))

    # ------------------------------------------------------------------
    # 计数（报告用）
    # ------------------------------------------------------------------
    def count_events(self, scan_id: int, event_type: TagEventType) -> int:
        row = self.conn.execute(
            "SELECT COUNT(*) AS c FROM tag_events WHERE scan_id = ? AND event_type = ?",
            (scan_id, event_type.value),
        ).fetchone()
        return row["c"]

    def count_observations(self, scan_id: int) -> int:
        row = self.conn.execute(
            "SELECT COUNT(*) AS c FROM tag_observations WHERE scan_id = ?",
            (scan_id,),
        ).fetchone()
        return row["c"]

    def count_completed_repos(self, scan_id: int) -> int:
        row = self.conn.execute(
            "SELECT COUNT(*) AS c FROM repo_scan_states "
            "WHERE scan_id = ? AND status = ?",
            (scan_id, ScanStatus.SCAN_COMPLETED.value),
        ).fetchone()
        return row["c"]

    def count_quarantined(self, registry: str) -> int:
        row = self.conn.execute(
            "SELECT COUNT(*) AS c FROM quarantined_repos WHERE registry = ?",
            (registry,),
        ).fetchone()
        return row["c"]
