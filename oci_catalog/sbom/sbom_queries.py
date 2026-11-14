"""两类依赖血缘查询（在新进程中只读 SBOM 库即可运行）。

1. :func:`query_image_components` —— 镜像 digest 导出该镜像每份清单的
   组件出现明细、归一化坐标与直接依赖；
2. :func:`query_component_images` —— 组件坐标反查包含它的镜像，并给出
   **每份清单内**通向该组件的最短依赖路径。

路径算法性质：

* 依赖图允许菱形（一个节点经多条同长路径可达）与环；算法基于 BFS 距离，
  环不会导致不终止，也不会让整份清单失效。
* 多条相同长度路径按**文件内引用名**稳定选择：邻居按 ref 字典序展开，
  枚举结果按引用名序列字典序排列，相同输入永远得到相同顺序。
* 路径搜索严格限定在单个 ``file_id`` 内。一个镜像绑定多份来源清单时，
  来源之间绝不拼接依赖边，不会产生跨文件的虚构路径。
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .purl import PurlError, parse_purl
from .sbom_store import SBOMStore

# 路径枚举的安全上限：防止超图产生组合爆炸；超出时 truncated=True
DEFAULT_MAX_PATHS = 50


# ---------------------------------------------------------------------------
# 图与最短路径
# ---------------------------------------------------------------------------
def _load_graph(store: SBOMStore, file_id: int) -> dict[str, set[str]]:
    """加载单份清单的有向邻接表（from -> {to}）。

    没有任何边的节点（叶子/孤立组件）也以空邻接集进入图，保证它们
    能作为路径终点被查到。
    """
    graph: dict[str, set[str]] = {}
    for row in store.conn.execute(
            "SELECT file_ref FROM occurrences WHERE file_id = ?",
            (file_id,)):
        graph.setdefault(row["file_ref"], set())
    for row in store.conn.execute(
            "SELECT from_ref, to_ref FROM dependency_edges WHERE file_id = ?",
            (file_id,)):
        graph.setdefault(row["from_ref"], set()).add(row["to_ref"])
        graph.setdefault(row["to_ref"], set())
    return graph


def _roots(graph: dict[str, set[str]]) -> list[str]:
    """根 = 有出边且无入边的节点；孤立节点（无边）不作为路径根。"""
    targets = {to for outs in graph.values() for to in outs}
    return sorted(node for node, outs in graph.items() if outs and node not in targets)


def _bfs_distances(graph: dict[str, set[str]], sources: list[str]) -> dict[str, int]:
    """从一组源点做 BFS，返回每个可达节点到**最近源点**的距离。"""
    dist: dict[str, int] = {source: 0 for source in sources}
    frontier = list(sources)
    while frontier:
        next_frontier: list[str] = []
        for node in frontier:
            for nxt in sorted(graph.get(node, ())):
                if nxt not in dist:
                    dist[nxt] = dist[node] + 1
                    next_frontier.append(nxt)
        frontier = next_frontier
    return dist


def shortest_paths(graph: dict[str, set[str]], target: str,
                   max_paths: int = DEFAULT_MAX_PATHS
                   ) -> tuple[list[list[str]], bool, bool]:
    """枚举 ``target`` 的全部最短依赖路径（根 -> ... -> target）。

    返回 (按引用名字典序排序的路径列表, 是否因上限截断, 是否使用了
    环岛屿锚点)。环通过 BFS 距离层自然终止，不会无限循环；若 target
    只存在于与根不连通的分量（环岛屿）中，则以该分量内字典序最小
    节点为锚点返回环上路径。
    """
    if target not in graph:
        return [], False, False

    roots = _roots(graph)
    dist = _bfs_distances(graph, roots) if roots else {}
    anchored = False

    if target not in dist:
        # 与根不连通（纯环岛屿或无根管状图）：分量内最小引用名作为锚点
        anchor = min(_component_of(graph, target))
        dist = _bfs_distances(graph, [anchor])
        anchored = True
        if target not in dist:
            return [], False, anchored

    # 沿距离递减层 DFS 枚举全部最短路径。从 target 向根回溯，需要入边表；
    # 入边邻居按 ref 字典序展开，得到的路径按引用名序列字典序排列。
    predecessors: dict[str, list[str]] = {}
    for node, outs in graph.items():
        for to in outs:
            predecessors.setdefault(to, []).append(node)
    paths: list[list[str]] = []
    truncated = False

    def dfs(node: str, trail: list[str]) -> None:
        nonlocal truncated
        if len(paths) >= max_paths:
            truncated = True
            return
        if dist[node] == 0:
            paths.append(list(reversed(trail)))
            return
        for prev in sorted(predecessors.get(node, ())):
            if dist.get(prev) == dist[node] - 1:
                dfs(prev, trail + [prev])
                if truncated:
                    return

    dfs(target, [target])
    return paths, truncated, anchored


def _component_of(graph: dict[str, set[str]], start: str) -> set[str]:
    """弱连通分量（忽略边方向），用于环岛屿锚点选择。"""
    undirected: dict[str, set[str]] = {}
    for node, outs in graph.items():
        undirected.setdefault(node, set())
        for to in outs:
            undirected.setdefault(to, set()).add(node)
            undirected[node].add(to)
    seen = {start}
    stack = [start]
    while stack:
        node = stack.pop()
        for nxt in undirected.get(node, ()):
            if nxt not in seen:
                seen.add(nxt)
                stack.append(nxt)
    return seen


# ---------------------------------------------------------------------------
# 出现记录装配
# ---------------------------------------------------------------------------
def _occurrence_dicts(store: SBOMStore, file_id: int) -> list[dict]:
    rows = store.conn.execute(
        "SELECT o.*, c.canonical_purl FROM occurrences o "
        "LEFT JOIN components c ON c.component_id = o.component_id "
        "WHERE o.file_id = ? ORDER BY o.occurrence_id", (file_id,)).fetchall()
    return [dict(r) for r in rows]


def _direct_dependencies(store: SBOMStore, file_id: int) -> dict[str, list[dict]]:
    """每个 ref 的直接依赖（含边在源文件中的位置），按 to_ref 排序。"""
    result: dict[str, list[dict]] = {}
    rows = store.conn.execute(
        "SELECT from_ref, to_ref, edge_location FROM dependency_edges "
        "WHERE file_id = ? ORDER BY to_ref", (file_id,)).fetchall()
    for row in rows:
        result.setdefault(row["from_ref"], []).append({
            "ref": row["to_ref"], "edge_location": row["edge_location"]})
    return result


# ---------------------------------------------------------------------------
# 查询 1：镜像 -> 组件出现明细
# ---------------------------------------------------------------------------
@dataclass
class ImageComponentReport:
    image_digest: str
    platform: dict | None
    files: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"image_digest": self.image_digest,
                "platform": self.platform, "files": self.files}


def query_image_components(store: SBOMStore, image_digest: str) -> dict:
    """导出某镜像绑定的每份清单的组件明细、归一化坐标与直接依赖。"""
    files = store.list_files_for_image(image_digest)
    if not files:
        raise KeyError(f"该镜像没有绑定任何已导入清单: {image_digest}")
    report = ImageComponentReport(
        image_digest=image_digest,
        platform=store.lookup_image_platform(image_digest))
    for f in files:
        occurrences = _occurrence_dicts(store, f["file_id"])
        direct = _direct_dependencies(store, f["file_id"])
        for occ in occurrences:
            occ["direct_dependencies"] = direct.get(occ["file_ref"], [])
        report.files.append({
            "file_id": f["file_id"],
            "source_path": f["source_path"],
            "doc_format": f["doc_format"],
            "content_sha256": f["content_sha256"],
            "imported_at": f["imported_at"],
            "occurrences": occurrences,
        })
    return report.to_dict()


# ---------------------------------------------------------------------------
# 查询 2：组件坐标 -> 包含它的镜像 + 依赖路径
# ---------------------------------------------------------------------------
def _resolve_component(store: SBOMStore, coordinate: str) -> dict:
    """接受 canonical purl 或其等价写法；返回 components 行。"""
    try:
        canonical = parse_purl(coordinate).canonical
    except PurlError as exc:
        raise ValueError(f"查询坐标不是合法 purl: {exc}") from exc
    row = store.conn.execute(
        "SELECT * FROM components WHERE canonical_purl = ?",
        (canonical,)).fetchone()
    if row is None:
        raise KeyError(f"没有任何已导入清单包含该坐标: {canonical}")
    return dict(row)


def query_component_images(store: SBOMStore, coordinate: str,
                           max_paths: int = DEFAULT_MAX_PATHS) -> dict:
    """按组件 purl 坐标反查包含它的镜像及每份清单中的依赖路径。

    路径按 ``file_id`` 分组计算，绝不跨文件拼边；同一镜像的多份清单分别
    给出各自的路径，平台上下文随镜像返回。
    """
    component = _resolve_component(store, coordinate)
    component_id = component["component_id"]

    # 该组件在哪些清单的哪些出现中存在
    occ_rows = store.conn.execute(
        "SELECT o.*, f.image_digest, f.source_path, f.doc_format, f.content_sha256 "
        "FROM occurrences o JOIN sbom_files f ON f.file_id = o.file_id "
        "WHERE o.component_id = ? ORDER BY f.image_digest, f.file_id, o.occurrence_id",
        (component_id,)).fetchall()

    images: dict[str, dict] = {}
    # 同一文件内同一组件可能有多个出现（两个 bom-ref 指向同一 purl）：
    # 按 (image, file) 合并，每个出现分别给路径，出现记录各自保留
    source_index: dict[tuple[str, int], dict] = {}
    for occ in occ_rows:
        file_id = occ["file_id"]
        image_digest = occ["image_digest"]
        image_entry = images.setdefault(image_digest, {
            "image_digest": image_digest,
            "platform": store.lookup_image_platform(image_digest),
            "sources": [],
        })
        key = (image_digest, file_id)
        source = source_index.get(key)
        if source is None:
            source = {
                "file_id": file_id,
                "source_path": occ["source_path"],
                "doc_format": occ["doc_format"],
                "content_sha256": occ["content_sha256"],
                "matches": [],
            }
            image_entry["sources"].append(source)
            source_index[key] = source

        graph = _load_graph(store, file_id)
        paths, truncated, anchored = shortest_paths(graph, occ["file_ref"],
                                                     max_paths)
        source["matches"].append({
            "file_ref": occ["file_ref"],
            "name": occ["name"],
            "version": occ["version"],
            "location": occ["location"],
            "purl_raw": occ["purl_raw"],
            "paths": paths,
            "paths_truncated": truncated,
            "anchor_note": "target_not_root_reachable" if anchored else None,
        })

    return {
        "canonical_purl": component["canonical_purl"],
        "purl_type": component["purl_type"],
        "name": component["name"],
        "version": component["version"],
        "images": [images[d] for d in sorted(images)],
    }
