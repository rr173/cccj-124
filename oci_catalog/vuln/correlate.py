"""公告 ↔ SBOM 安装坐标关联：为指定镜像生成逐组件出现项的版本判定报告。

输入只读：公告目录（经 :mod:`advisory` 校验）、既有 SBOM 库与目录库都以
只读方式打开，不重新导入 SBOM、不写任何输入库；唯一输出是 JSON 报告。

判定口径（详见 ``oci_catalog/vuln/README.md``）：

* 安装坐标来自 SBOM 库中已归一的 purl：生态、包名、版本都取自 purl，
  不用组件显示名替代缺失 purl，也不拿其他字段的版本补齐无版本 purl；
* 有 qualifiers/subpath 的安装项仍按其生态与包名匹配公告，qualifiers
  随 canonical purl 原样带回报告；
* 每个组件出现项 × 相关公告组给出 命中/不命中/无法判断，再汇成出现项
  状态：affected / unknown / not_affected_in_feed / uncovered；
* 报告按出现项展示（同一组件在两份清单出现就是两条记录），同一漏洞的
  多个编号经等价组合并为一个组，不会被报成几个不同漏洞。
"""

from __future__ import annotations

import json
import os
import sqlite3
from dataclasses import dataclass
from urllib.parse import quote

from ..digest import DigestError, parse_digest
from ..sbom.purl import normalize_pypi_name, parse_purl
from .advisory import AdvisorySet, Group
from .versions import VersionParseError, parse_ecosystem_version

# 出现项状态
AFFECTED = "affected"
UNKNOWN = "unknown"
NOT_AFFECTED = "not_affected_in_feed"
UNCOVERED = "uncovered"

# 无法判断原因码
MISSING_PURL = "missing_purl"
UNSUPPORTED_ECOSYSTEM = "unsupported_ecosystem"
MISSING_VERSION = "missing_version"
UNPARSEABLE_VERSION = "unparseable_version"
UNSUPPORTED_RANGE_TYPE = "unsupported_range_type"
NO_VERSION_SET = "no_version_set"

# purl 类型 -> 公告生态名
_ECOSYSTEM_BY_PURL_TYPE = {"pypi": "PyPI", "npm": "npm"}

REPORT_KIND = "vuln-correlation/v1"

# 报告与文档都必须保留的限制声明：没有找到命中只代表这批输入的覆盖情况
LIMITATIONS = [
    "本报告只覆盖所给本地公告目录与已导入 SBOM 的交集；没有找到命中不代表"
    "镜像没有漏洞。",
    "not_affected_in_feed 仅表示相关公告声明都能判定且安装版本均不命中；"
    "uncovered 仅表示这批公告中没有该包的有效（未撤回）声明。",
    "本作业不做运行时漏洞检测，也不判断代码路径能否触发漏洞。",
    "只有 PyPI（ECOSYSTEM 区间）与 npm（SEMVER 区间）参与确定版本判定；"
    "其他生态与区间类型保留为无法判断（unknown），绝不写成不受影响。",
]


class NoSBOMError(KeyError):
    """指定镜像没有任何已导入 SBOM 清单，不能给出“零漏洞”结论。"""


class UnknownAdvisoryId(KeyError):
    """查询的公告编号不在任何等价组中。"""


def _connect_readonly(path: str) -> sqlite3.Connection:
    """以只读模式打开 SQLite 库（file URI 转义，特殊字符路径安全）。"""
    absolute = os.path.abspath(path)
    uri = "file://" + quote(absolute, safe="/") + "?mode=ro"
    return sqlite3.connect(uri, uri=True)


def _table_exists(conn: sqlite3.Connection, table: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
        (table,)).fetchone()
    return row is not None


@dataclass
class ImageScope:
    """指定镜像的只读输入：出现项明细 + 平台上下文。"""

    image_digest: str
    platform: dict | None
    occurrences: list           # 每份清单的每个出现项一行
    files: list                 # 该镜像的 SBOM 文件行


def load_image_scope(sbom_db: str, catalog_db: str,
                     image_digest: str) -> ImageScope:
    """只读打开 SBOM 库与目录库，取出镜像的出现项与平台上下文。

    镜像没有任何已导入清单时抛 :class:`NoSBOMError`——调用方必须单独
    说明，不能据此输出“零漏洞”的成功结论。
    """
    try:
        algorithm, _ = parse_digest(image_digest)
        if algorithm != "sha256":
            raise DigestError("只支持 sha256")
    except DigestError as exc:
        raise ValueError(f"镜像摘要不是合法 sha256 digest: {exc}") from exc

    if not os.path.exists(sbom_db):
        raise NoSBOMError(
            f"SBOM 库不存在: {sbom_db}；无法评估，不能给出零漏洞结论")
    sbom = _connect_readonly(sbom_db)
    sbom.row_factory = sqlite3.Row
    try:
        if not _table_exists(sbom, "sbom_files"):
            raise NoSBOMError(
                f"SBOM 库 {sbom_db} 不含清单数据；"
                f"无法评估，不能给出零漏洞结论")
        files = [dict(r) for r in sbom.execute(
            "SELECT file_id, source_path, doc_format, content_sha256, "
            "image_digest, imported_at FROM sbom_files "
            "WHERE image_digest = ? ORDER BY file_id", (image_digest,))]
        if not files:
            raise NoSBOMError(
                f"镜像 {image_digest} 没有任何已导入 SBOM 清单；"
                f"无法评估，不能给出零漏洞结论")
        occurrences = [dict(r) for r in sbom.execute(
            "SELECT o.occurrence_id, o.file_id, o.file_ref, o.name, "
            "o.location, o.purl_raw, "
            "c.canonical_purl, c.purl_type "
            "FROM occurrences o "
            "LEFT JOIN components c ON c.component_id = o.component_id "
            "WHERE o.file_id IN (SELECT file_id FROM sbom_files "
            "                    WHERE image_digest = ?) "
            "ORDER BY o.file_id, o.occurrence_id", (image_digest,))]
    finally:
        sbom.close()

    platform = None
    if os.path.exists(catalog_db):
        catalog = _connect_readonly(catalog_db)
        catalog.row_factory = sqlite3.Row
        try:
            if _table_exists(catalog, "manifest_children"):
                rows = catalog.execute(
                    "SELECT platform_json FROM manifest_children "
                    "WHERE child_digest = ? AND platform_json IS NOT NULL "
                    "ORDER BY platform_json", (image_digest,)).fetchall()
                if rows:
                    platform = json.loads(rows[0]["platform_json"])
        finally:
            catalog.close()

    return ImageScope(
        image_digest=image_digest, platform=platform,
        occurrences=occurrences, files=files)


# ---------------------------------------------------------------------------
# 包名匹配
# ---------------------------------------------------------------------------
def _npm_advisory_key(name: str) -> str:
    """公告侧 npm 名的比较键：scope 转小写，包名本体保留大小写。"""
    if name.startswith("@") and "/" in name:
        scope, _, rest = name.partition("/")
        return scope.lower() + "/" + rest
    return name


def _npm_purl_key(namespace: tuple, name: str) -> str:
    """purl 侧 npm 名的比较键（namespace 各段已在 purl 归一时转小写）。"""
    if namespace:
        return "/".join(namespace) + "/" + name
    return name


def _package_matches(ecosystem: str, advisory_name: str,
                     purl_namespace: tuple, purl_name: str) -> bool:
    if ecosystem == "PyPI":
        return normalize_pypi_name(advisory_name) == purl_name
    if ecosystem == "npm":
        return _npm_advisory_key(advisory_name) == _npm_purl_key(
            purl_namespace, purl_name)
    return False


# ---------------------------------------------------------------------------
# 单条声明 / 单个出现项求值
# ---------------------------------------------------------------------------
def _evaluate_claim(claim, ecosystem: str, version_str: str, parsed_version,
                    advisory_id: str) -> dict:
    """对单条 affected 声明求值，返回 {verdict, evidence, reasons}。"""
    evidence = []
    reasons = []
    has_versions = claim.versions is not None and len(claim.versions) > 0
    has_ranges = len(claim.ranges) > 0
    if not has_versions and not has_ranges:
        reasons.append({
            "code": NO_VERSION_SET,
            "advisory_id": advisory_id,
            "affected_index": claim.index,
            "message": "该声明既没有 versions 精确列表也没有 ranges，"
                       "缺少可用版本集合（空 versions 不能证明不受影响）",
        })
        return {"verdict": "unknown", "evidence": [], "reasons": reasons}

    if has_versions:
        # versions 按解码后的原版本字符串精确匹配：文本不同但排序相等的
        # 版本不视作同一个列表项
        for v_index, listed in enumerate(claim.versions):
            if version_str == listed:
                evidence.append({
                    "advisory_id": advisory_id,
                    "affected_index": claim.index,
                    "kind": "versions",
                    "versions_index": v_index,
                    "version": listed,
                })
                break

    for range_obj in claim.ranges:
        if not range_obj.supported:
            reasons.append({
                "code": UNSUPPORTED_RANGE_TYPE,
                "advisory_id": advisory_id,
                "affected_index": claim.index,
                "range_index": range_obj.index,
                "range_type": range_obj.type,
                "message": f"生态 {ecosystem} 不支持区间类型 "
                           f"{range_obj.type!r}，无法判断",
            })
            continue
        for interval in range_obj.intervals:
            if interval.contains(parsed_version):
                evidence.append({
                    "advisory_id": advisory_id,
                    "affected_index": claim.index,
                    "kind": "range",
                    "range_index": range_obj.index,
                    "range_type": range_obj.type,
                    "interval": interval.to_dict(),
                })
                break  # 同一 range 内一个命中区间足够作依据

    if evidence:
        return {"verdict": "hit", "evidence": evidence, "reasons": []}
    if reasons:
        return {"verdict": "unknown", "evidence": [], "reasons": reasons}
    return {"verdict": "miss", "evidence": [], "reasons": []}


def _evaluate_occurrence(occ: dict, advisory_set: AdvisorySet) -> dict:
    """对单个组件出现项求值，返回报告条目。"""
    entry = {
        "file_id": occ["file_id"],
        "file_ref": occ["file_ref"],
        "name": occ["name"],
        "location": occ["location"],
        "purl_raw": occ["purl_raw"],
        "canonical_purl": occ["canonical_purl"],
        "installed_version": None,
        "status": None,
        "reasons": [],
        "groups": [],
    }

    if not occ["canonical_purl"]:
        entry["status"] = UNKNOWN
        entry["reasons"].append({
            "code": MISSING_PURL,
            "message": "该出现项没有 purl，无法建立安装坐标；"
                       "不用显示名臆造坐标，不能写成安全",
        })
        return entry

    purl = parse_purl(occ["canonical_purl"])
    # 安装版本是 purl 中的解码原版本字符串（可能为 None）；即使生态不支持
    # 判定，也如实带回坐标文本
    entry["installed_version"] = purl.version
    ecosystem = _ECOSYSTEM_BY_PURL_TYPE.get(purl.type)
    if ecosystem is None:
        entry["status"] = UNKNOWN
        entry["reasons"].append({
            "code": UNSUPPORTED_ECOSYSTEM,
            "message": f"purl 类型 {purl.type!r} 不在可判定生态"
                       f"（pypi/npm）内，不能写成安全",
        })
        return entry

    # 相关声明：生态一致且包名匹配的有效（未撤回）公告 affected 项
    relevant = []  # (group, advisory_id, claim)
    for group in advisory_set.groups:
        for advisory in group.advisories:
            for claim in advisory.affected:
                if claim.ecosystem != ecosystem:
                    continue
                if _package_matches(ecosystem, claim.name,
                                    purl.namespace, purl.name):
                    relevant.append((group, advisory.id, claim))

    if not relevant:
        entry["status"] = UNCOVERED
        return entry

    if purl.version is None:
        entry["status"] = UNKNOWN
        entry["reasons"].append({
            "code": MISSING_VERSION,
            "message": "purl 缺少版本，且公告目录存在该包的有效声明；"
                       "不拿其他字段的版本补齐，不能写成安全",
        })
        return entry

    version_str = purl.version  # purl 归一后保存的解码原版本字符串
    try:
        parsed_version = parse_ecosystem_version(ecosystem, version_str)
    except VersionParseError as exc:
        entry["status"] = UNKNOWN
        entry["reasons"].append({
            "code": UNPARSEABLE_VERSION,
            "message": f"安装版本无法按 {ecosystem} 解析: {exc}",
        })
        return entry

    # 逐组聚合：组内任一声明命中则组命中；无命中但任一声明无法判断则组未知
    group_verdicts: dict[str, dict] = {}
    for group, advisory_id, claim in relevant:
        slot = group_verdicts.setdefault(group.display_id, {
            "group": group, "hits": [], "unknowns": [], "misses": []})
        result = _evaluate_claim(claim, ecosystem, version_str,
                                 parsed_version, advisory_id)
        if result["verdict"] == "hit":
            slot["hits"].extend(result["evidence"])
        elif result["verdict"] == "unknown":
            slot["unknowns"].extend(result["reasons"])
        else:
            slot["misses"].append(f"{advisory_id}#{claim.index}")

    any_hit = False
    any_unknown = False
    for display_id in sorted(group_verdicts):
        slot = group_verdicts[display_id]
        group: Group = slot["group"]
        if slot["hits"]:
            verdict = "hit"
            any_hit = True
        elif slot["unknowns"]:
            verdict = "unknown"
            any_unknown = True
        else:
            verdict = "miss"
        entry["groups"].append({
            "group_id": display_id,
            "member_ids": list(group.member_ids),
            "verdict": verdict,
            "evidence": slot["hits"],
            "reasons": slot["unknowns"],
            "evaluated_claims": slot["misses"],
        })

    # 命中优先：已有确定命中时，其他未知声明不抹掉已知命中
    if any_hit:
        entry["status"] = AFFECTED
    elif any_unknown:
        entry["status"] = UNKNOWN
    else:
        entry["status"] = NOT_AFFECTED
    return entry


# ---------------------------------------------------------------------------
# 报告与查询
# ---------------------------------------------------------------------------
def _feed_stats(advisory_set: AdvisorySet) -> dict:
    valid = advisory_set.valid_advisories
    claims = [c for a in valid for c in a.affected]

    def _decidable(claim) -> bool:
        if claim.ecosystem not in ("PyPI", "npm"):
            return False
        if claim.versions:
            return True
        return any(r.supported for r in claim.ranges)

    return {
        "files": advisory_set.files,
        "advisories_total": len(advisory_set.advisories),
        "advisories_valid": len(valid),
        "advisories_withdrawn": len(advisory_set.advisories) - len(valid),
        "groups": len(advisory_set.groups),
        "claims_total": len(claims),
        "claims_decidable": sum(1 for c in claims if _decidable(c)),
    }


def build_report(advisory_set: AdvisorySet, sbom_db: str, catalog_db: str,
                 image_digest: str, advisory_dir: str) -> dict:
    """为指定镜像生成逐组件出现项的版本判定报告（dict，可直接写 JSON）。"""
    scope = load_image_scope(sbom_db, catalog_db, image_digest)
    file_meta = {f["file_id"]: f for f in scope.files}

    entries = []
    for occ in scope.occurrences:
        entry = _evaluate_occurrence(occ, advisory_set)
        meta = file_meta[occ["file_id"]]
        entry["source_path"] = meta["source_path"]
        entry["doc_format"] = meta["doc_format"]
        entries.append(entry)

    summary = {"occurrences": len(entries), AFFECTED: 0, UNKNOWN: 0,
               NOT_AFFECTED: 0, UNCOVERED: 0}
    for entry in entries:
        summary[entry["status"]] += 1

    return {
        "report_kind": REPORT_KIND,
        "image_digest": image_digest,
        "platform": scope.platform,
        "sbom_present": True,
        "inputs": {
            "advisory_dir": advisory_dir,
            "sbom_db": sbom_db,
            "catalog_db": catalog_db,
        },
        "feed": _feed_stats(advisory_set),
        "advisory_groups": [g.to_dict() for g in advisory_set.groups],
        "occurrences": entries,
        "summary": summary,
        "limitations": list(LIMITATIONS),
    }


def query_advisory(advisory_set: AdvisorySet, sbom_db: str, catalog_db: str,
                   image_digest: str, query_id: str) -> dict:
    """按任一公告编号查询本次选定镜像范围中的命中安装项与全部来源位置。

    编号可以是组内任意成员（公告 id 或别名，含没有独立文件的编号）；
    返回等价组信息、命中出现项（含镜像、清单来源、文件内引用、原 purl、
    安装版本与命中依据）。组内没有有效公告（全部撤回或无文件）时明确
    说明，命中列表为空不等于“安全”。
    """
    group = advisory_set.group_for(query_id)
    if group is None:
        raise UnknownAdvisoryId(
            f"编号 {query_id!r} 不在任何公告等价组中（含别名）")
    scope = load_image_scope(sbom_db, catalog_db, image_digest)

    hits = []
    for occ in scope.occurrences:
        entry = _evaluate_occurrence(occ, advisory_set)
        for group_entry in entry["groups"]:
            if group_entry["group_id"] != group.display_id:
                continue
            if group_entry["verdict"] != "hit":
                continue
            hits.append({
                "image_digest": image_digest,
                "file_id": entry["file_id"],
                "file_ref": entry["file_ref"],
                "location": entry["location"],
                "purl_raw": entry["purl_raw"],
                "canonical_purl": entry["canonical_purl"],
                "installed_version": entry["installed_version"],
                "evidence": group_entry["evidence"],
            })

    notes = []
    if not group.advisories:
        notes.append("该等价组没有有效（未撤回）公告，不参与命中；"
                     "命中为空不代表安全。")
    if not hits:
        notes.append("本次选定镜像范围中没有命中；这只代表这批输入的覆盖"
                     "情况，不代表镜像没有漏洞。")
    return {
        "query_id": query_id,
        "group": group.to_dict(),
        "image_digest": image_digest,
        "platform": scope.platform,
        "hits": hits,
        "notes": notes,
        "limitations": list(LIMITATIONS),
    }
