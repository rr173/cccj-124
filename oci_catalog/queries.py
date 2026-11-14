"""治理查询接口。

提供三类只读查询：

* :func:`query_platform_references` —— 按 digest 查完整平台引用（递归展开 index
  树，返回每个叶子 image 的平台描述及所有引用路径）；
* :func:`query_tag_history` —— 按 tag 查当前指向与完整历史事件；
* :func:`diff_namespace_scans` —— 按 namespace 比较两次目录扫描的差异。
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Optional

from .models import ManifestKind
from .store import CatalogStore


def split_namespace(repository: str) -> tuple[str, str]:
    """``ns/a/b`` -> ("ns/a", "b")；无命名空间的仓库归到 ""。"""
    if "/" not in repository:
        return "", repository
    namespace, _, name = repository.rpartition("/")
    return namespace, name


# ---------------------------------------------------------------------------
# 1. digest -> 完整平台引用
# ---------------------------------------------------------------------------
@dataclass
class PlatformReference:
    """一个叶子平台的引用信息。"""

    manifest_digest: str
    media_type: str
    kind: str
    platform: Optional[dict]
    config_digest: Optional[str]
    layer_digests: list[str] = field(default_factory=list)
    # 从查询起点到该 manifest 的索引展开路径（digest 序列）
    path: list[str] = field(default_factory=list)
    # 路径上每一级 index descriptor 携带的平台描述
    path_platforms: list[Optional[dict]] = field(default_factory=list)


def query_platform_references(store: CatalogStore, digest: str) -> dict:
    """按 digest 返回 manifest 及其递归展开后的全部平台引用。

    返回结构::

        {
          "digest": "...", "media_type": "...", "kind": "index|image|unknown",
          "references": [PlatformReference, ...],
          "referenced_by_tags": [{"registry","repository","tag"}, ...]
        }
    """
    row = store.conn.execute(
        "SELECT * FROM manifests WHERE digest = ?", (digest,)
    ).fetchone()
    if row is None:
        raise KeyError(f"未收录的 digest: {digest}")

    references: list[PlatformReference] = []
    _walk(store, digest, [digest], [None], references)

    tags = [dict(r) for r in store.conn.execute(
        "SELECT registry, repository, tag FROM tag_state WHERE digest = ? "
        "ORDER BY registry, repository, tag", (digest,))]

    return {
        "digest": digest,
        "media_type": row["media_type"],
        "kind": row["kind"],
        "references": [r.__dict__ for r in references],
        "referenced_by_tags": tags,
    }


def _walk(store: CatalogStore, digest: str, path: list[str],
          path_platforms: list[Optional[dict]],
          out: list[PlatformReference]) -> None:
    row = store.conn.execute(
        "SELECT * FROM manifests WHERE digest = ?", (digest,)
    ).fetchone()
    if row is None:
        # 子 manifest 未收录（如采集时被 GC）：记录占位引用
        out.append(PlatformReference(
            manifest_digest=digest, media_type="", kind="missing",
            platform=None, config_digest=None,
            path=list(path), path_platforms=list(path_platforms)))
        return

    if row["kind"] == ManifestKind.INDEX.value:
        children = store.conn.execute(
            "SELECT * FROM manifest_children WHERE parent_digest = ? "
            "ORDER BY position", (digest,)).fetchall()
        if not children:
            # 空索引：自身作为一个引用输出
            out.append(_leaf(store, row, path, path_platforms))
            return
        for child in children:
            platform = json.loads(child["platform_json"]) if child["platform_json"] else None
            _walk(store, child["child_digest"],
                  path + [child["child_digest"]],
                  path_platforms + [platform], out)
    else:
        out.append(_leaf(store, row, path, path_platforms))


def _leaf(store: CatalogStore, row, path: list[str],
          path_platforms: list[Optional[dict]]) -> PlatformReference:
    layers = [r["layer_digest"] for r in store.conn.execute(
        "SELECT layer_digest FROM manifest_layers WHERE manifest_digest = ? "
        "ORDER BY position", (row["digest"],))]
    return PlatformReference(
        manifest_digest=row["digest"],
        media_type=row["media_type"],
        kind=row["kind"],
        # 叶子自身的平台描述来自父索引 descriptor（路径最后一个平台）
        platform=next((p for p in reversed(path_platforms) if p), None),
        config_digest=row["config_digest"],
        layer_digests=layers,
        path=list(path),
        path_platforms=list(path_platforms),
    )


# ---------------------------------------------------------------------------
# 2. tag -> 当前指向 + 历史
# ---------------------------------------------------------------------------
def query_tag_history(store: CatalogStore, registry: str, repository: str,
                      tag: str) -> dict:
    """返回 tag 的当前指向与完整事件历史（按时间顺序）。"""
    current = store.conn.execute(
        "SELECT * FROM tag_state WHERE registry = ? AND repository = ? AND tag = ?",
        (registry, repository, tag),
    ).fetchone()
    events = [dict(r) for r in store.conn.execute(
        "SELECT event_id, scan_id, event_type, old_digest, new_digest, observed_at "
        "FROM tag_events WHERE registry = ? AND repository = ? AND tag = ? "
        "ORDER BY event_id",
        (registry, repository, tag))]
    return {
        "registry": registry,
        "repository": repository,
        "tag": tag,
        "exists": current is not None,
        "current": dict(current) if current else None,
        "history": events,
    }


# ---------------------------------------------------------------------------
# 3. namespace 两次扫描对比
# ---------------------------------------------------------------------------
@dataclass
class NamespaceDiff:
    registry: str
    namespace: str
    scan_a: int
    scan_b: int
    tags_added: list[dict] = field(default_factory=list)
    tags_removed: list[dict] = field(default_factory=list)
    tags_moved: list[dict] = field(default_factory=list)
    repositories_added: list[str] = field(default_factory=list)
    repositories_removed: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "registry": self.registry,
            "namespace": self.namespace,
            "scan_a": self.scan_a,
            "scan_b": self.scan_b,
            "tags_added": self.tags_added,
            "tags_removed": self.tags_removed,
            "tags_moved": self.tags_moved,
            "repositories_added": self.repositories_added,
            "repositories_removed": self.repositories_removed,
        }


def _namespace_snapshot(store: CatalogStore, registry: str, scan_id: int,
                        namespace: str) -> dict[str, dict[str, str]]:
    """取某次扫描中该 namespace 下 {repository: {tag: digest}} 快照。"""
    like = f"{namespace}/%" if namespace else "%"
    rows = store.conn.execute(
        "SELECT repository, tag, digest FROM tag_observations "
        "WHERE registry = ? AND scan_id = ? AND repository LIKE ? "
        "ORDER BY repository, tag",
        (registry, scan_id, like)).fetchall()
    snapshot: dict[str, dict[str, str]] = {}
    for r in rows:
        repo = r["repository"]
        if namespace:
            ns, _ = split_namespace(repo)
            if ns != namespace:
                continue
        elif "/" in repo:
            # namespace="" 只包含根级仓库
            continue
        snapshot.setdefault(repo, {})[r["tag"]] = r["digest"]
    return snapshot


def diff_namespace_scans(store: CatalogStore, registry: str, namespace: str,
                         scan_a: int, scan_b: int) -> dict:
    """比较同一 namespace 下两次扫描的目录差异。

    * tags_added / tags_removed：tag 集合变化；
    * tags_moved：同名 tag 指向的 digest 变化（含覆盖与删除后重建）；
    * repositories_added / removed：namespace 内仓库集合变化。
    """
    snap_a = _namespace_snapshot(store, registry, scan_a, namespace)
    snap_b = _namespace_snapshot(store, registry, scan_b, namespace)
    diff = NamespaceDiff(registry=registry, namespace=namespace,
                         scan_a=scan_a, scan_b=scan_b)

    repos_a, repos_b = set(snap_a), set(snap_b)
    diff.repositories_added = sorted(repos_b - repos_a)
    diff.repositories_removed = sorted(repos_a - repos_b)

    for repo in sorted(repos_a & repos_b):
        tags_a, tags_b = snap_a[repo], snap_b[repo]
        for tag in sorted(set(tags_b) - set(tags_a)):
            diff.tags_added.append(
                {"repository": repo, "tag": tag, "digest": tags_b[tag]})
        for tag in sorted(set(tags_a) - set(tags_b)):
            diff.tags_removed.append(
                {"repository": repo, "tag": tag, "digest": tags_a[tag]})
        for tag in sorted(set(tags_a) & set(tags_b)):
            if tags_a[tag] != tags_b[tag]:
                diff.tags_moved.append({
                    "repository": repo, "tag": tag,
                    "old_digest": tags_a[tag], "new_digest": tags_b[tag],
                })
    return diff.to_dict()


def latest_completed_scans(store: CatalogStore, registry: str,
                           limit: int = 10) -> list[dict]:
    """辅助：列出最近完成的 scan，供选择对比基线。"""
    rows = store.conn.execute(
        "SELECT scan_id, registry, status, started_at, finished_at "
        "FROM scan_runs WHERE registry = ? AND status = 'completed' "
        "ORDER BY scan_id DESC LIMIT ?", (registry, limit)).fetchall()
    return [dict(r) for r in rows]
