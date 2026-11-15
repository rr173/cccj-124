"""对象仓只读查询：名称解析、闭包清单、对象描述符与字节导出。

读取必须经过 :class:`~oci_catalog.blobstore.store.BlobReader` 上下文：
本模块的 ``export_object`` 在给定读者上下文中把对象原始字节分块写到
文件或文件流，不把整层读入内存；没有打开上下文时不允许直接读对象。
"""

from __future__ import annotations

import hashlib
import json
import os
from typing import Optional

from .store import BlobReader, BlobStore, StoreError


def list_refs(store: BlobStore) -> list[dict]:
    info = []
    for ref in store.list_refs():
        info.append({
            "name": ref.name,
            "root": ref.root.to_dict(),
            "updated_at": ref.updated_at,
        })
    return info


def resolve_ref(store: BlobStore, name: str) -> dict:
    ref = store.get_ref(name)
    closure_id = store.conn.execute(
        "SELECT closure_id FROM closures WHERE root_digest = ?",
        (ref.root.digest,)).fetchone()["closure_id"]
    objects = store.conn.execute(
        "SELECT co.digest, co.role, o.size FROM closure_objects co "
        "JOIN objects o ON o.digest = co.digest "
        "WHERE co.closure_id = ? ORDER BY co.digest",
        (closure_id,)).fetchall()
    return {"name": ref.name, "root": ref.root.to_dict(),
            "updated_at": ref.updated_at,
            "closure_objects": [
                {"digest": row["digest"], "role": row["role"],
                 "size": row["size"]} for row in objects],
            "unique_bytes": sum(row["size"] for row in objects)}


def reader_manifest(reader: BlobReader) -> dict:
    """固定闭包的完整描述：根、逐对象 role 与 size、唯一字节总数。"""
    roles = reader.roles()
    objects = reader.objects()
    return {
        "reader_id": reader.reader_id,
        "root": reader.root.to_dict(),
        "objects": [
            {"digest": desc.digest, "media_type": desc.media_type,
             "size": desc.size, "role": roles.get(desc.digest, "")}
            for desc in objects],
        "unique_bytes": sum(desc.size for desc in objects),
    }


def closure_manifest(store: BlobStore, root_digest: str) -> dict:
    row = store.conn.execute(
        "SELECT closure_id FROM closures WHERE root_digest = ?",
        (root_digest,)).fetchone()
    if row is None:
        raise StoreError(f"本仓没有 {root_digest} 的闭包")
    objects = store.conn.execute(
        "SELECT co.digest, co.role, o.size, "
        "COALESCE(m.media_type, '') AS media_type, "
        "COALESCE(e.media_type, '') AS edge_media "
        "FROM closure_objects co JOIN objects o ON o.digest = co.digest "
        "LEFT JOIN manifests m ON m.digest = co.digest "
        "LEFT JOIN manifest_edges e ON e.child_digest = co.digest "
        "WHERE co.closure_id = ? GROUP BY co.digest ORDER BY co.digest",
        (row["closure_id"],)).fetchall()
    return {
        "root_digest": root_digest,
        "objects": [
            {"digest": r["digest"], "role": r["role"], "size": r["size"],
             "media_type": r["media_type"] or r["edge_media"]}
            for r in objects],
        "unique_bytes": sum(r["size"] for r in objects),
    }


def export_object(reader: BlobReader, digest: str, output_path: str,
                  expected_digest: Optional[str] = None,
                  chunk_size: Optional[int] = None) -> dict:
    """把固定闭包内某对象的原始字节写到指定文件（逐块写，不入内存）。

    写入完成后复核落盘字节的 sha256 与长度；不符则报错并删除半份输出。
    目标文件已存在时拒绝覆盖，避免误伤交付人员已有文件。
    """
    expected = expected_digest or digest
    if expected != digest:
        raise StoreError(
            f"导出目标 {digest} 与期望摘要 {expected} 不一致")
    if os.path.exists(output_path):
        raise StoreError(f"导出目标已存在，拒绝覆盖: {output_path}")
    tmp_path = output_path + ".partial"
    hasher = hashlib.sha256()
    written = 0
    fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    try:
        with os.fdopen(fd, "wb") as fh:
            for chunk in reader.read_chunks(digest, chunk_size):
                hasher.update(chunk)
                written += len(chunk)
                fh.write(chunk)
            fh.flush()
            os.fsync(fh.fileno())
        actual = "sha256:" + hasher.hexdigest()
        if actual != digest:
            raise StoreError(
                f"导出字节摘要 {actual} 与对象 digest {digest} 不符")
        size = reader.describe(digest).size
        if written != size:
            raise StoreError(
                f"导出字节长度 {written} 与对象 size {size} 不符")
        os.replace(tmp_path, output_path)
    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise
    return {"digest": digest, "size": written, "path": output_path,
            "sha256": digest}


def helper_dump(payload: dict) -> str:
    return json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True)
