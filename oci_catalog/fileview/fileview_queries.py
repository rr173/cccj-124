"""文件视图图的只读查询：列树、路径溯源、取文件原始字节。

* :func:`list_tree` —— 按目录前缀列出归并后的文件树（前缀按路径段
  边界匹配，``/data`` 不会混进 ``/database``）；
* :func:`stat_path` —— 按精确路径查看条目类型与来源（哪一层、哪个
  tar 成员）；
* :func:`read_file_bytes` —— 按精确路径取普通文件/硬链接的原始字节
  （bytes 原样返回，不做任何文本解码）。

符号链接安全约定：符号链接只作为链接信息查询；列树与取文件都不跟随
符号链接——穿越符号链接的查询路径会被明确拒绝，绝不可能经由此处
读到宿主文件。
"""

from __future__ import annotations

from .fileview_store import FileViewStore
from .layer_archive import ENTRY_DIR, ENTRY_FILE, ENTRY_HARDLINK, ENTRY_SYMLINK


class UnknownViewError(KeyError):
    """该镜像没有（成功构建的）文件视图。"""


class ViewPathError(ValueError):
    """查询路径无法安全表示、不存在、类型不符或穿越符号链接。"""


def normalize_query_path(path: str) -> str:
    """归一化查询路径：必须以 ``/`` 开头，拒绝 ``..`` 段。

    查询路径是视图内的绝对路径；``/`` 表示根。``..``、空段、``.`` 段
    与重复斜杠按成员路径同一套规则处理，保证查询语义与构建语义一致。
    """
    if not path:
        raise ViewPathError("查询路径为空")
    if not path.startswith("/"):
        raise ViewPathError(f"查询路径必须以 '/' 开头: {path!r}")
    parts: list[str] = []
    for segment in path.split("/"):
        if segment in ("", "."):
            continue
        if segment == "..":
            raise ViewPathError(f"查询路径含 '..' 段: {path!r}")
        parts.append(segment)
    return "/" + "/".join(parts) if parts else "/"


def _require_view(store: FileViewStore, image_digest: str):
    view = store.get_view(image_digest)
    if view is None:
        raise UnknownViewError(
            f"镜像没有可查询的文件视图（未构建或构建失败）: {image_digest}")
    return view


def _row_to_dict(row) -> dict:
    return {
        "path": row["path"],
        "entry_type": row["entry_type"],
        "size": row["size"],
        "mode": row["mode"],
        "layer_digest": row["layer_digest"],
        "member_name": row["member_name"],
        "member_index": row["member_index"],
        "link_target": row["link_target"],
        "implicit": bool(row["implicit"]),
    }


def list_tree(store: FileViewStore, image_digest: str,
              prefix: str = "/") -> dict:
    """按目录前缀列出文件树（递归，按路径字典序）。

    前缀按路径段边界匹配：``/data`` 命中自身与 ``/data/...``，
    不会命中 ``/database``。符号链接原样作为条目返回（含链接目标），
    不跟随。
    """
    view = _require_view(store, image_digest)
    prefix = normalize_query_path(prefix)
    if prefix == "/":
        rows = list(store.conn.execute(
            "SELECT * FROM entries WHERE view_id = ? ORDER BY path",
            (view["view_id"],)))
    else:
        # substr 比较避免 LIKE 通配符转义问题；边界是 prefix 本身或 prefix+'/'
        rows = list(store.conn.execute(
            "SELECT * FROM entries WHERE view_id = ? AND "
            "(path = ? OR substr(path, 1, ?) = ?) ORDER BY path",
            (view["view_id"], prefix, len(prefix) + 1, prefix + "/")))
    if not rows:
        raise ViewPathError(f"前缀在视图中不存在: {prefix}")
    return {
        "image_digest": image_digest,
        "prefix": prefix,
        "entries": [_row_to_dict(r) for r in rows],
    }


def stat_path(store: FileViewStore, image_digest: str, path: str) -> dict:
    """按精确路径查看条目：类型、大小、模式、来源层与 tar 成员。"""
    view = _require_view(store, image_digest)
    path = normalize_query_path(path)
    if path == "/":
        return {"image_digest": image_digest,
                "entry": {"path": "/", "entry_type": ENTRY_DIR, "size": 0,
                          "mode": 0o755, "layer_digest": "",
                          "member_name": "", "member_index": -1,
                          "link_target": "", "implicit": True}}
    row = store.conn.execute(
        "SELECT * FROM entries WHERE view_id = ? AND path = ?",
        (view["view_id"], path)).fetchone()
    if row is None:
        raise ViewPathError(f"路径在视图中不存在: {path}")
    return {"image_digest": image_digest, "entry": _row_to_dict(row)}


def read_file_bytes(store: FileViewStore, image_digest: str,
                    path: str) -> bytes:
    """按精确路径取普通文件/硬链接的原始字节。

    * 符号链接：拒绝跟随，只可通过 :func:`stat_path` 查链接信息；
    * 目录：无字节可取；
    * 路径不存在但其某个祖先符号链接：明确报“穿越符号链接”，
      绝不跟随到宿主文件。
    """
    view = _require_view(store, image_digest)
    path = normalize_query_path(path)
    if path == "/":
        raise ViewPathError("根是目录，没有可读取的文件字节")
    row = store.conn.execute(
        "SELECT * FROM entries WHERE view_id = ? AND path = ?",
        (view["view_id"], path)).fetchone()
    if row is None:
        _raise_with_symlink_context(store, view["view_id"], path)
        raise ViewPathError(f"路径在视图中不存在: {path}")
    entry_type = row["entry_type"]
    if entry_type == ENTRY_SYMLINK:
        raise ViewPathError(
            f"路径是符号链接 (-> {row['link_target']})，只提供链接信息，"
            f"不跟随读取: {path}")
    if entry_type == ENTRY_DIR:
        raise ViewPathError(f"路径是目录，没有可读取的文件字节: {path}")
    if entry_type not in (ENTRY_FILE, ENTRY_HARDLINK):
        raise ViewPathError(f"条目类型 {entry_type!r} 不可读取: {path}")
    content = store.conn.execute(
        "SELECT data FROM contents WHERE content_id = ?",
        (row["content_id"],)).fetchone()
    if content is None:
        raise ViewPathError(f"条目缺少内容记录: {path}")
    return bytes(content["data"])


def _raise_with_symlink_context(store: FileViewStore, view_id: int,
                                path: str) -> None:
    """路径不存在时，若其某个严格祖先是符号链接，报穿越错误。"""
    cursor = path
    while True:
        idx = cursor.rfind("/")
        if idx <= 0:
            return
        cursor = cursor[:idx]
        row = store.conn.execute(
            "SELECT entry_type, link_target FROM entries "
            "WHERE view_id = ? AND path = ?",
            (view_id, cursor)).fetchone()
        if row is not None:
            if row["entry_type"] == ENTRY_SYMLINK:
                raise ViewPathError(
                    f"查询路径穿越符号链接 {cursor} (-> {row['link_target']})"
                    f"，不跟随: {path}")
            return
