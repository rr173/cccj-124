"""离线关系加工结果的独立 SQLite 存储与查询。

落库语义（与题面一致）：

* 一次成功落库对应**整份已校验计划的一次 run**，所有节点结果、源记录、
  逐行血缘与拒绝明细在**同一个事务**内提交；执行途中任何错误都回滚，
  数据库里不可能出现只含部分节点、可被当成成功结果查询的 run。
* 失败的 run 不写任何结果表，只在独立事务里留一条 ``run_failures``
  诊断（与结果事务物理分离）。
* 输出库若与任一输入库（目录库 / 视图库）是同一个文件，**写入前**拒绝。
* 结果行 ID 是落库时生成并持久化的整数（``result_rows.row_id``），
  只在“该 run 内”稳定，不依赖任何内存对象；新进程按
  （run_id, 节点名, row_id）即可追溯。
"""

from __future__ import annotations

import csv
import io
import json
import os
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any, Optional

from .engine import RunArtifacts, SourceKey
from .sources import ParsedTable, Rejection, SourceLocation

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    run_id          INTEGER PRIMARY KEY AUTOINCREMENT,
    status          TEXT NOT NULL,              -- success | failure
    plan_json       TEXT NOT NULL,
    created_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS run_failures (
    failure_id      INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id          INTEGER NOT NULL,
    failed_at       TEXT NOT NULL,
    error_code      TEXT NOT NULL,
    error_message   TEXT NOT NULL,
    plan_json       TEXT NOT NULL
);

-- 一次 run 引用到的输入文件（视图 digest + 精确路径）
CREATE TABLE IF NOT EXISTS source_files (
    source_file_id  INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id          INTEGER NOT NULL REFERENCES runs(run_id),
    table_name      TEXT NOT NULL,
    image_digest    TEXT NOT NULL,
    file_path       TEXT NOT NULL,
    file_format     TEXT NOT NULL,
    UNIQUE (run_id, table_name, image_digest, file_path)
);

-- 合格源记录：合约值 + 原始字段值 + 物理坐标
CREATE TABLE IF NOT EXISTS source_records (
    source_record_id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id           INTEGER NOT NULL REFERENCES runs(run_id),
    table_name       TEXT NOT NULL,
    image_digest     TEXT NOT NULL,
    file_path        TEXT NOT NULL,
    record_seq       INTEGER NOT NULL,
    physical_start_line INTEGER NOT NULL,
    physical_end_line   INTEGER NOT NULL,
    values_json      TEXT NOT NULL,
    raw_values_json  TEXT NOT NULL,
    raw_text         TEXT NOT NULL,
    UNIQUE (run_id, table_name, image_digest, file_path, record_seq)
);

-- 记录级拒绝明细（其他合格记录继续加工）
CREATE TABLE IF NOT EXISTS rejections (
    rejection_id     INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id           INTEGER NOT NULL REFERENCES runs(run_id),
    table_name       TEXT NOT NULL,
    image_digest     TEXT NOT NULL,
    file_path        TEXT NOT NULL,
    record_seq       INTEGER NOT NULL,
    physical_start_line INTEGER NOT NULL,
    physical_end_line   INTEGER NOT NULL,
    reason_code      TEXT NOT NULL,
    reason_message   TEXT NOT NULL,
    raw_values_json  TEXT NOT NULL,
    raw_text         TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS result_nodes (
    node_id          INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id           INTEGER NOT NULL REFERENCES runs(run_id),
    node_name        TEXT NOT NULL,
    node_kind        TEXT NOT NULL,
    schema_json      TEXT NOT NULL,
    row_count        INTEGER NOT NULL,
    UNIQUE (run_id, node_name)
);

CREATE TABLE IF NOT EXISTS result_rows (
    row_id           INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id           INTEGER NOT NULL REFERENCES runs(run_id),
    node_id          INTEGER NOT NULL REFERENCES result_nodes(node_id),
    row_index        INTEGER NOT NULL,           -- run+node 内稳定 0 起序号
    values_json      TEXT NOT NULL,
    UNIQUE (run_id, node_id, row_index)
);

-- 逐行血缘：结果行 -> 源记录，多重集贡献次数
CREATE TABLE IF NOT EXISTS row_lineage (
    lineage_id       INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id           INTEGER NOT NULL REFERENCES runs(run_id),
    row_id           INTEGER NOT NULL REFERENCES result_rows(row_id),
    source_record_id INTEGER NOT NULL REFERENCES
                         source_records(source_record_id),
    contribution     INTEGER NOT NULL,           -- 该源在该结果行的贡献次数
    UNIQUE (row_id, source_record_id)
);
CREATE INDEX IF NOT EXISTS idx_rows_run_node
    ON result_rows(run_id, node_id, row_index);
CREATE INDEX IF NOT EXISTS idx_lineage_row ON row_lineage(row_id);
CREATE INDEX IF NOT EXISTS idx_rejections_run ON rejections(run_id);
"""


class OutputConflictError(Exception):
    """输出库路径指向某个输入库，写入前拒绝。"""


class RunNotFoundError(KeyError):
    """指定 run 不存在或不是成功 run。"""


class NodeNotFoundError(KeyError):
    """run 中不存在该结果节点。"""


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _json_default(value: Any) -> Any:
    if isinstance(value, Decimal):
        # 定点数保留原始字面量（Decimal('0.10') -> '0.10'）
        return str(value)
    raise TypeError(f"无法 JSON 序列化类型 {type(value)!r}")


def dumps_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      default=_json_default)


@dataclass
class RunHandle:
    run_id: int
    node_names: list[str]
    rejection_count: int
    source_record_count: int


class RelationalStore:
    """关系加工结果库（独立 SQLite 文件，可被新进程重新打开）。"""

    def __init__(self, db_path: str, input_db_paths:
                 Optional[list[str]] = None, readonly: bool = False):
        self.db_path = os.path.abspath(db_path)
        self.input_db_paths = [os.path.abspath(p)
                               for p in (input_db_paths or [])]
        if readonly:
            from urllib.parse import quote
            uri = "file://" + quote(self.db_path, safe="/")
            self.conn = sqlite3.connect(uri + "?mode=ro", uri=True)
        else:
            self._guard_output_path()
            self.conn = sqlite3.connect(db_path)
            self.conn.execute("PRAGMA journal_mode = WAL")
            self.conn.execute("PRAGMA foreign_keys = ON")
            self.conn.executescript(SCHEMA)
            self.conn.commit()
        self.conn.row_factory = sqlite3.Row

    def _guard_output_path(self) -> None:
        for input_path in self.input_db_paths:
            if self.db_path == input_path:
                raise OutputConflictError(
                    f"输出库 {self.db_path} 与输入库 {input_path} 是同一文件，"
                    f"拒绝写入任何只读输入库")

    def close(self) -> None:
        self.conn.close()

    # ------------------------------------------------------------------
    # 写入
    # ------------------------------------------------------------------
    def save_run(self, artifacts: RunArtifacts, plan_json: str) -> RunHandle:
        """单事务保存整份成功 run；任何异常都回滚，不留半成品。"""
        conn = self.conn
        try:
            conn.execute("BEGIN")
            cur = conn.execute(
                "INSERT INTO runs (status, plan_json, created_at) "
                "VALUES ('success', ?, ?)", (plan_json, _utcnow()))
            run_id = cur.lastrowid
            self._save_sources(run_id, artifacts)
            self._save_rejections(run_id, artifacts)
            node_names = self._save_results(run_id, artifacts)
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        source_count = conn.execute(
            "SELECT COUNT(*) AS c FROM source_records WHERE run_id = ?",
            (run_id,)).fetchone()["c"]
        rejection_count = conn.execute(
            "SELECT COUNT(*) AS c FROM rejections WHERE run_id = ?",
            (run_id,)).fetchone()["c"]
        return RunHandle(run_id=run_id, node_names=node_names,
                         rejection_count=rejection_count,
                         source_record_count=source_count)

    def record_failure(self, error_code: str, error_message: str,
                       plan_json: str) -> int:
        """独立事务记录一次失败 run（不写任何结果表）。"""
        conn = self.conn
        try:
            conn.execute("BEGIN")
            cur = conn.execute(
                "INSERT INTO runs (status, plan_json, created_at) "
                "VALUES ('failure', ?, ?)", (plan_json, _utcnow()))
            run_id = cur.lastrowid
            conn.execute(
                "INSERT INTO run_failures (run_id, failed_at, error_code, "
                "error_message, plan_json) VALUES (?, ?, ?, ?, ?)",
                (run_id, _utcnow(), error_code, error_message, plan_json))
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        return run_id

    def _save_sources(self, run_id: int, artifacts: RunArtifacts) -> None:
        self._source_id: dict[SourceKey, int] = {}
        written_files: set[tuple[str, str, str, str]] = set()
        for key, record in artifacts.source_records():
            file_tuple = (key.table_name, key.image_digest, key.file_path,
                          self.plan_format(artifacts, key.table_name))
            if file_tuple not in written_files:
                self.conn.execute(
                    "INSERT INTO source_files (run_id, table_name, "
                    "image_digest, file_path, file_format) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (run_id, *file_tuple))
                written_files.add(file_tuple)
            loc: SourceLocation = record.location
            cur = self.conn.execute(
                "INSERT INTO source_records (run_id, table_name, "
                "image_digest, file_path, record_seq, physical_start_line, "
                "physical_end_line, values_json, raw_values_json, raw_text) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (run_id, key.table_name, key.image_digest, key.file_path,
                 key.record_seq, loc.physical_start_line,
                 loc.physical_end_line, dumps_json(record.values),
                 dumps_json(record.raw_values), record.raw_text))
            self._source_id[key] = cur.lastrowid

    @staticmethod
    def plan_format(artifacts: RunArtifacts, table_name: str) -> str:
        return artifacts.plan.inputs[table_name].format

    def _save_rejections(self, run_id: int,
                         artifacts: RunArtifacts) -> None:
        for table_name in sorted(artifacts.tables):
            table: ParsedTable = artifacts.tables[table_name]
            for rejection in table.rejections:
                loc: SourceLocation = rejection.location
                self.conn.execute(
                    "INSERT INTO rejections (run_id, table_name, "
                    "image_digest, file_path, record_seq, "
                    "physical_start_line, physical_end_line, reason_code, "
                    "reason_message, raw_values_json, raw_text) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (run_id, table_name, loc.image_digest, loc.file_path,
                     loc.record_seq, loc.physical_start_line,
                     loc.physical_end_line, rejection.reason_code,
                     rejection.reason_message,
                     dumps_json(rejection.raw_values), rejection.raw_text))

    def _save_results(self, run_id: int, artifacts: RunArtifacts) -> list[str]:
        node_names: list[str] = []
        for node_name in artifacts.plan.order:
            result = artifacts.node_results[node_name]
            cur = self.conn.execute(
                "INSERT INTO result_nodes (run_id, node_name, node_kind, "
                "schema_json, row_count) VALUES (?, ?, ?, ?, ?)",
                (run_id, node_name, result.kind,
                 dumps_json(result.schema), len(result.rows)))
            node_id = cur.lastrowid
            node_names.append(node_name)
            for row_index, row in enumerate(result.rows):
                row_cur = self.conn.execute(
                    "INSERT INTO result_rows (run_id, node_id, row_index, "
                    "values_json) VALUES (?, ?, ?, ?)",
                    (run_id, node_id, row_index, dumps_json(row.values)))
                row_id = row_cur.lastrowid
                for source_key in sorted(
                        row.lineage,
                        key=lambda k: (k.table_name, k.image_digest,
                                       k.file_path, k.record_seq)):
                    source_record_id = self._source_id[source_key]
                    self.conn.execute(
                        "INSERT INTO row_lineage (run_id, row_id, "
                        "source_record_id, contribution) "
                        "VALUES (?, ?, ?, ?)",
                        (run_id, row_id, source_record_id,
                         row.lineage[source_key]))
        return node_names

    # ------------------------------------------------------------------
    # 读侧查询（新进程可用）
    # ------------------------------------------------------------------
    def latest_success_run(self) -> int:
        row = self.conn.execute(
            "SELECT run_id FROM runs WHERE status = 'success' "
            "ORDER BY run_id DESC LIMIT 1").fetchone()
        if row is None:
            raise RunNotFoundError("库中没有成功的加工 run")
        return row["run_id"]

    def list_runs(self) -> list[dict]:
        rows = self.conn.execute(
            "SELECT run_id, status, created_at FROM runs "
            "ORDER BY run_id").fetchall()
        return [dict(r) for r in rows]

    def list_nodes(self, run_id: int) -> list[dict]:
        self._require_success(run_id)
        rows = self.conn.execute(
            "SELECT node_name, node_kind, schema_json, row_count "
            "FROM result_nodes WHERE run_id = ? ORDER BY node_id",
            (run_id,)).fetchall()
        return [{"node_name": r["node_name"], "node_kind": r["node_kind"],
                 "schema": json.loads(r["schema_json"]),
                 "row_count": r["row_count"]} for r in rows]

    def _node_id(self, run_id: int, node_name: str) -> int:
        row = self.conn.execute(
            "SELECT node_id FROM result_nodes WHERE run_id = ? AND "
            "node_name = ?", (run_id, node_name)).fetchone()
        if row is None:
            raise NodeNotFoundError(
                f"run {run_id} 中不存在结果节点 {node_name!r}")
        return row["node_id"]

    def _decimal_columns_of_input(self, run_id: int,
                                  table_name: str) -> set[str]:
        """从已存计划 JSON 中取某输入表的 decimal 列名集合。"""
        row = self.conn.execute(
            "SELECT plan_json FROM runs WHERE run_id = ?",
            (run_id,)).fetchone()
        if row is None:
            return set()
        plan = json.loads(row["plan_json"])
        for input_spec in plan.get("inputs", []):
            if input_spec.get("name") == table_name:
                return {f["name"] for f in
                        input_spec.get("contract", {}).get("fields", [])
                        if f.get("type") == "decimal"}
        return set()

    def _require_success(self, run_id: int) -> None:
        row = self.conn.execute(
            "SELECT status FROM runs WHERE run_id = ?",
            (run_id,)).fetchone()
        if row is None:
            raise RunNotFoundError(f"run {run_id} 不存在")
        if row["status"] != "success":
            raise RunNotFoundError(f"run {run_id} 不是成功 run")

    def fetch_rows(self, run_id: int, node_name: str) -> dict:
        """取节点全部结果行（含稳定 row_id），按 row_index 升序。

        decimal 列按节点 schema 还原为 :class:`decimal.Decimal`，
        使精确十进制语义在 Python 读侧同样成立；integer 列为 int，
        其余为字符串/None。
        """
        self._require_success(run_id)
        node_id = self._node_id(run_id, node_name)
        node_row = self.conn.execute(
            "SELECT schema_json FROM result_nodes WHERE node_id = ?",
            (node_id,)).fetchone()
        schema = json.loads(node_row["schema_json"])
        decimal_cols = {col for col, typ in schema.items()
                        if typ == "decimal"}
        rows = self.conn.execute(
            "SELECT row_id, row_index, values_json FROM result_rows "
            "WHERE run_id = ? AND node_id = ? ORDER BY row_index",
            (run_id, node_id)).fetchall()
        return {
            "run_id": run_id,
            "node_name": node_name,
            "schema": schema,
            "rows": [{"row_id": r["row_id"], "row_index": r["row_index"],
                      "values": _loads_values(r["values_json"],
                                              decimal_cols)}
                     for r in rows],
        }

    def list_rejections(self, run_id: int,
                        table_name: Optional[str] = None) -> list[dict]:
        self._require_success(run_id)
        if table_name is None:
            rows = self.conn.execute(
                "SELECT * FROM rejections WHERE run_id = ? "
                "ORDER BY rejection_id", (run_id,)).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT * FROM rejections WHERE run_id = ? AND "
                "table_name = ? ORDER BY rejection_id",
                (run_id, table_name)).fetchall()
        return [self._rejection_dict(r) for r in rows]

    @staticmethod
    def _rejection_dict(row: sqlite3.Row) -> dict:
        return {
            "rejection_id": row["rejection_id"],
            "table_name": row["table_name"],
            "image_digest": row["image_digest"],
            "file_path": row["file_path"],
            "record_seq": row["record_seq"],
            "physical_start_line": row["physical_start_line"],
            "physical_end_line": row["physical_end_line"],
            "reason_code": row["reason_code"],
            "reason_message": row["reason_message"],
            "raw_values": json.loads(row["raw_values_json"]),
            "raw_text": row["raw_text"],
        }

    def trace_row(self, run_id: int, node_name: str,
                  row_id: int) -> dict:
        """按“结果节点 + 结果行 ID”追溯：去重、稳定排序的源记录+贡献次数。"""
        self._require_success(run_id)
        node_id = self._node_id(run_id, node_name)
        owner = self.conn.execute(
            "SELECT row_id FROM result_rows WHERE run_id = ? AND node_id = ?"
            " AND row_id = ?", (run_id, node_id, row_id)).fetchone()
        if owner is None:
            raise NodeNotFoundError(
                f"节点 {node_name!r} 下不存在 row_id={row_id}")
        lineage_rows = self.conn.execute(
            "SELECT l.contribution, s.* FROM row_lineage l "
            "JOIN source_records s ON s.source_record_id = l.source_record_id "
            "WHERE l.row_id = ? "
            "ORDER BY s.table_name, s.image_digest, s.file_path, s.record_seq",
            (row_id,)).fetchall()
        sources = [{
            "table_name": r["table_name"],
            "image_digest": r["image_digest"],
            "file_path": r["file_path"],
            "record_seq": r["record_seq"],
            "physical_start_line": r["physical_start_line"],
            "physical_end_line": r["physical_end_line"],
            # 合约值按输入契约还原 decimal；原始值保持原样以便回看
            "values": _reconstruct_typed_values(
                json.loads(r["values_json"]),
                self._decimal_columns_of_input(run_id, r["table_name"])),
            "raw_values": json.loads(r["raw_values_json"]),
            "raw_text": r["raw_text"],
            "contribution": r["contribution"],
        } for r in lineage_rows]
        return {"run_id": run_id, "node_name": node_name,
                "row_id": row_id, "sources": sources}

    def export_node_csv(self, run_id: int, node_name: str) -> str:
        """把节点结果导出为 UTF-8 CSV 文本（QUOTE_MINIMAL，decimal 保字面量）。"""
        payload = self.fetch_rows(run_id, node_name)
        schema = payload["schema"]
        columns = list(schema)
        buf = io.StringIO()
        writer = csv.writer(buf, lineterminator="\n")
        writer.writerow(columns)
        for row in payload["rows"]:
            writer.writerow([_csv_cell(row["values"].get(col))
                             for col in columns])
        return buf.getvalue()

    def list_failures(self) -> list[dict]:
        rows = self.conn.execute(
            "SELECT f.failure_id, f.run_id, f.failed_at, f.error_code, "
            "f.error_message FROM run_failures f ORDER BY f.failure_id"
        ).fetchall()
        return [dict(r) for r in rows]


def _loads_values(text: str,
                  decimal_cols: Optional[set[str]] = None
                  ) -> dict[str, Any]:
    """读取存储的值；decimal 列还原为 Decimal 以保持精确运算语义。"""
    raw = json.loads(text)
    if not decimal_cols:
        return dict(raw)
    return {key: (Decimal(value) if key in decimal_cols
                  and isinstance(value, str) else value)
            for key, value in raw.items()}


def _reconstruct_typed_values(raw: dict[str, Any],
                              decimal_cols: set[str]) -> dict[str, Any]:
    """按输入契约把 decimal 字面量还原为 Decimal，其余类型保持。"""
    return {key: (Decimal(value) if key in decimal_cols
                  and isinstance(value, str) else value)
            for key, value in raw.items()}


def _csv_cell(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, Decimal):
        return str(value)
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)
