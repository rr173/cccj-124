"""输入源读取：只读文件视图 + UTF-8 CSV / 逐行 JSON 解析。

边界（与题面一致）：

* 文件字节只能通过既有文件视图接口
  （:func:`oci_catalog.fileview.fileview_queries.read_file_bytes`）取得，
  不访问 registry，不把镜像内路径当宿主路径打开；
* 视图库与目录库都以**只读 URI** 打开，本模块没有任何写路径；
* CSV 用标准库 :mod:`csv` 解析，天然支持引号内逗号与引号内换行；
* JSON 每个**非空物理行**是一条对象记录，空物理行跳过。

定位模型（两者不可混为一谈）：

* ``record_seq`` —— 数据记录的 1 起序号（跳过空物理行/CSV 空记录）；
* ``physical_start_line`` / ``physical_end_line`` —— 1 起物理行号；
  CSV 一条记录被引号换行拆成多行时，二者不相等。

致命错误（整次加工拒绝，不产出结果）：

* 视图不存在 / 路径不存在 / 非普通文件 -> :class:`SourceReadError`；
* 字节不是合法 UTF-8 -> ``encoding_error``；
* CSV 结构损坏（表头重复、字段缺失、列宽不符、解析器报错）->
  ``csv_structure_error``。

记录级问题（其他记录继续）通过 :class:`RejectedRecord` 与拒绝清单上报。
"""

from __future__ import annotations

import csv
import io
import json
import os
import sqlite3
from dataclasses import dataclass, field
from typing import Any, Optional

from ..fileview.fileview_queries import (
    UnknownViewError,
    ViewPathError,
    read_file_bytes,
)
from .contract import (
    REASON_JSON_INVALID_LINE,
    REASON_JSON_NOT_OBJECT,
    RejectedRecord,
    TableContract,
    coerce_record,
)

FORMAT_CSV = "csv"
FORMAT_JSONL = "jsonl"


class SourceReadError(Exception):
    """文件级致命错误：无法安全读取/解码/结构化，整次加工必须拒绝。"""

    def __init__(self, code: str, message: str, *, image_digest: str = "",
                 file_path: str = ""):
        super().__init__(message)
        self.code = code
        self.message = message
        self.image_digest = image_digest
        self.file_path = file_path


@dataclass
class SourceLocation:
    """一条源记录的可追溯坐标。"""

    image_digest: str
    file_path: str
    record_seq: int
    physical_start_line: int
    physical_end_line: int

    def to_dict(self) -> dict:
        return {
            "image_digest": self.image_digest,
            "file_path": self.file_path,
            "record_seq": self.record_seq,
            "physical_start_line": self.physical_start_line,
            "physical_end_line": self.physical_end_line,
        }


@dataclass
class ParsedRecord:
    """一条合约记录 + 来源坐标 + 原始值。"""

    values: dict[str, Any]
    location: SourceLocation
    raw_values: dict[str, Any]
    raw_text: str


@dataclass
class Rejection:
    """一条被拒记录：原始值/原文、文件坐标、原因。"""

    location: SourceLocation
    reason_code: str
    reason_message: str
    raw_values: dict[str, Any]
    raw_text: str


@dataclass
class ParsedTable:
    """一个输入表（可由多个精确路径拼接）的解析结果。"""

    table_name: str
    records: list[ParsedRecord] = field(default_factory=list)
    rejections: list[Rejection] = field(default_factory=list)


class ReadOnlyViewReader:
    """以只读方式打开视图库（+ 目录库），只暴露取文件字节一个能力。

    两个 SQLite 文件都用 ``mode=ro`` URI 打开；不实例化
    :class:`~oci_catalog.fileview.fileview_store.FileViewStore`（它会执行
    建表/PRAGMA 写动作），而是手动建只读连接，复用其纯查询函数。
    """

    def __init__(self, views_db_path: str, catalog_db_path: str):
        self.views_db_path = os.path.abspath(views_db_path)
        self.catalog_db_path = os.path.abspath(catalog_db_path)
        if not os.path.exists(views_db_path):
            raise SourceReadError(
                "view_db_missing",
                f"文件视图库不存在: {views_db_path}")
        self._conn = self._open_ro(views_db_path)
        self._catalog_conn = self._open_ro(catalog_db_path)
        self._shim = _ReadOnlyStoreShim(self._conn)

    @staticmethod
    def _open_ro(path: str) -> sqlite3.Connection:
        if not os.path.exists(path):
            raise SourceReadError(
                "db_missing", f"只读数据库文件不存在: {path}")
        from urllib.parse import quote
        uri = "file://" + quote(os.path.abspath(path), safe="/")
        try:
            conn = sqlite3.connect(uri + "?mode=ro", uri=True)
        except sqlite3.OperationalError as exc:
            raise SourceReadError(
                "db_open_failed", f"无法只读打开数据库 {path}: {exc}")
        conn.row_factory = sqlite3.Row
        return conn

    def fetch_bytes(self, image_digest: str, path: str) -> bytes:
        """经既有文件视图查询接口取原始字节（不跟随符号链接）。"""
        try:
            return read_file_bytes(self._shim, image_digest, path)
        except UnknownViewError as exc:
            raise SourceReadError(
                "unknown_view", str(exc),
                image_digest=image_digest, file_path=path)
        except ViewPathError as exc:
            raise SourceReadError(
                "view_path_error", str(exc),
                image_digest=image_digest, file_path=path)

    def close(self) -> None:
        self._conn.close()
        self._catalog_conn.close()


class _ReadOnlyStoreShim:
    """只实现 read_file_bytes 所需 ``get_view``/``conn`` 的只读替身。"""

    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn

    def get_view(self, image_digest: str):
        return self.conn.execute(
            "SELECT * FROM image_views WHERE image_digest = ?",
            (image_digest,)).fetchone()


def _decode_utf8(data: bytes, image_digest: str, path: str) -> str:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SourceReadError(
            "encoding_error",
            f"文件不是合法 UTF-8 文本: {exc}",
            image_digest=image_digest, file_path=path)


# ---------------------------------------------------------------------------
# CSV
# ---------------------------------------------------------------------------
def parse_csv_table(table_name: str, contract: TableContract,
                    sources: list[tuple[str, str, bytes]]) -> ParsedTable:
    """解析一个 CSV 输入表（多文件按声明顺序拼接，序号连续）。

    :param sources: [(image_digest, file_path, raw_bytes), ...]
    """
    parsed = ParsedTable(table_name=table_name)
    running_seq = 0
    for image_digest, file_path, raw in sources:
        text = _decode_utf8(raw, image_digest, file_path)
        running_seq = _parse_one_csv(parsed, contract, image_digest,
                                     file_path, text, running_seq)
    return parsed


def _parse_one_csv(parsed: ParsedTable, contract: TableContract,
                   image_digest: str, file_path: str, text: str,
                   running_seq: int) -> int:
    # csv.reader.line_num 统计已从迭代器拉取的物理行数：引号内换行使一条
    # 逻辑记录跨多行时 line_num 连续推进；被跳过的空白物理行也计入。
    # 每条逻辑记录的物理区间 = 上一条结束行 + 1 .. 当前 line_num。
    reader = csv.reader(text.splitlines(keepends=True))
    try:
        header = next(reader)
    except StopIteration:
        raise SourceReadError(
            "csv_structure_error", "CSV 文件为空，缺少表头",
            image_digest=image_digest, file_path=file_path)
    except csv.Error as exc:
        raise SourceReadError(
            "csv_structure_error", f"CSV 表头解析失败: {exc}",
            image_digest=image_digest, file_path=file_path)
    header_end = reader.line_num

    if any(col == "" for col in header):
        raise SourceReadError(
            "csv_structure_error", "CSV 表头存在空列名",
            image_digest=image_digest, file_path=file_path)
    if len(set(header)) != len(header):
        dupes = sorted({c for c in header if header.count(c) > 1})
        raise SourceReadError(
            "csv_structure_error",
            f"CSV 表头存在重复列名 {dupes}（结构损坏，整文件拒绝）",
            image_digest=image_digest, file_path=file_path)
    missing_contract = [c for c in contract.column_names if c not in header]
    if missing_contract:
        raise SourceReadError(
            "csv_structure_error",
            f"CSV 表头缺少契约字段 {missing_contract}（表头占物理行 "
            f"1-{header_end}）",
            image_digest=image_digest, file_path=file_path)

    width = len(header)
    prev_line = header_end
    try:
        for row in reader:
            end_line = reader.line_num
            start_line = prev_line + 1
            prev_line = end_line
            if not row:  # 完全空白物理行：csv 已跳过，防御性兜底
                continue
            if len(row) != width:
                raise SourceReadError(
                    "csv_structure_error",
                    f"第 {start_line} 物理行起的记录列数 {len(row)} 与表头 "
                    f"{width} 不一致",
                    image_digest=image_digest, file_path=file_path)
            running_seq += 1
            raw_values = {header[i]: row[i] for i in range(width)}
            raw_text = _csv_reconstruct(row)
            presence = _csv_presence(contract, header, row)
            loc = SourceLocation(image_digest, file_path, running_seq,
                                 start_line, end_line)
            _ingest_record(parsed, contract, raw_values, presence, loc,
                           raw_text)
    except csv.Error as exc:
        raise SourceReadError(
            "csv_structure_error", f"CSV 解析失败: {exc}",
            image_digest=image_digest, file_path=file_path)
    return running_seq


def _csv_reconstruct(row: list[str]) -> str:
    """重建该数据记录的原始 CSV 文本（用于拒绝明细留证）。"""
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(row)
    return buf.getvalue().rstrip("\n")


def _csv_presence(contract: TableContract, header: list[str],
                  row: list[str]) -> dict[str, str]:
    presence: dict[str, str] = {}
    for spec in contract.fields:
        idx = header.index(spec.name)
        value = row[idx]
        presence[spec.name] = ("empty_string" if value == "" else "present")
    return presence


# ---------------------------------------------------------------------------
# JSON Lines
# ---------------------------------------------------------------------------
def parse_jsonl_table(table_name: str, contract: TableContract,
                      sources: list[tuple[str, str, bytes]]) -> ParsedTable:
    """解析一个逐行 JSON 输入表（每个非空物理行一条对象记录）。"""
    parsed = ParsedTable(table_name=table_name)
    running_seq = 0
    for image_digest, file_path, raw in sources:
        text = _decode_utf8(raw, image_digest, file_path)
        running_seq = _parse_one_jsonl(parsed, contract, image_digest,
                                       file_path, text, running_seq)
    return parsed


def _parse_one_jsonl(parsed: ParsedTable, contract: TableContract,
                     image_digest: str, file_path: str, text: str,
                     running_seq: int) -> int:
    for physical_line, line in enumerate(text.splitlines(), start=1):
        if line.strip() == "":
            continue  # 空物理行：不是记录，不占序号
        running_seq += 1
        loc = SourceLocation(image_digest, file_path, running_seq,
                             physical_line, physical_line)
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as exc:
            parsed.rejections.append(Rejection(
                loc, REASON_JSON_INVALID_LINE,
                f"物理行不是合法 JSON: {exc.msg} (col {exc.colno})",
                {}, line))
            continue
        if not isinstance(obj, dict):
            parsed.rejections.append(Rejection(
                loc, REASON_JSON_NOT_OBJECT,
                f"JSON 行不是对象记录，实际类型 {type(obj).__name__}",
                {"_json_value": _json_safe(obj)}, line))
            continue
        raw_values = dict(obj)
        presence = _json_presence(contract, obj)
        _ingest_record(parsed, contract, raw_values, presence, loc, line)
    return running_seq


def _json_presence(contract: TableContract, obj: dict) -> dict[str, str]:
    presence: dict[str, str] = {}
    for spec in contract.fields:
        if spec.name not in obj:
            presence[spec.name] = "missing"
        elif obj[spec.name] is None:
            presence[spec.name] = "explicit_null"
        elif isinstance(obj[spec.name], str) and obj[spec.name] == "":
            presence[spec.name] = "empty_string"
        else:
            presence[spec.name] = "present"
    return presence


def _ingest_record(parsed: ParsedTable, contract: TableContract,
                   raw_values: dict[str, Any], presence: dict[str, str],
                   loc: SourceLocation, raw_text: str) -> None:
    try:
        values = coerce_record(contract, raw_values, presence)
    except RejectedRecord as exc:
        parsed.rejections.append(Rejection(
            loc, exc.reason_code, exc.reason_message,
            {k: _json_safe(v) for k, v in raw_values.items()}, raw_text))
        return
    parsed.records.append(ParsedRecord(
        values=values, location=loc,
        raw_values={k: _json_safe(v) for k, v in raw_values.items()},
        raw_text=raw_text))


def _json_safe(value: Any) -> Any:
    """把原始 JSON/CSV 标量整理成可 JSON 序列化的留证值。"""
    if isinstance(value, (str, int, bool, type(None))):
        return value
    if isinstance(value, float):
        # 保留原始外观的字符串形式，避免展示时二进制浮点误差
        return repr(value)
    if isinstance(value, (list, dict)):
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    return str(value)
