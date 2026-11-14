"""CycloneDX / SPDX 清单解析与数据契约校验（纯内存、不访问网络）。

数据契约（明确范围，超出范围即诊断而不是静默猜测）：

CycloneDX JSON
    * 文件内身份：组件的 ``bom-ref`` 字符串；``bom-ref`` 缺失或在全文档
      （含嵌套 components）内重复都是错误。
    * 递归读取顶层 ``components`` 中每个组件及其嵌套 ``components``，
      记录每个节点在源 JSON 中的 JSONPath 位置。
    * ``dependencies``：每项 ``{ref, dependsOn:[...]}`` 表示 ``ref`` 依赖
      ``dependsOn`` 中的引用；顶层 ``metadata.component.dependencies`` 不在
      本工具范围内（metadata.component 不纳入组件集合）。
    * 依赖边两端必须指向已声明的 bom-ref，否则为悬空引用诊断。
    * 组件 ``purl`` 字段按 purl 契约校验；非法 purl 是错误，不保留为坐标。

SPDX JSON
    * 文件内身份：包的 ``SPDXID``；缺失/重复都是错误。
    * 读取 ``packages`` 与每项的 ``externalRefs``（仅 ``referenceType`` 为
      ``purl`` 的条目参与坐标解析；一个包出现多个 purl 引用是错误）。
    * ``relationships`` 中只有两类关系转成**同方向**依赖边
      （``from -> to`` 表示 from 依赖 to）：
      - ``DEPENDS_ON``：``A DEPENDS_ON B`` 直接得到 ``A -> B``；
      - ``DEPENDENCY_OF``：``A DEPENDENCY_OF B`` 反向得到 ``B -> A``。
      其他关系类型（DESCRIBES、CONTAINS、PATCH_OF 等）一律忽略并计数，
      绝不当成依赖边。
    * 依赖关系引用的 SPDXID 必须存在于 packages 中，否则为悬空引用诊断。

共同规则：

* 组件名、版本、供应者、许可证**原始表达**与源文件位置全部随节点保留，
  可追溯回原资料；许可证不做 SPDX 表达式归一化。
* 不靠显示名连接节点；不同文件即使复用相同引用名也互不相干——解析结果
  不带任何跨文件身份，跨文件合并只发生在存储层的 purl 坐标上。
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Optional

from .purl import Purl, PurlError, parse_purl

CYCLONEDX = "cyclonedx"
SPDX = "spdx"

# SPDX 中会被转成依赖边的两类关系；其余关系类型忽略
_SPDX_DEPENDS_ON = "DEPENDS_ON"
_SPDX_DEPENDENCY_OF = "DEPENDENCY_OF"


class SBOMParseError(ValueError):
    """文档整体无法解析（非 JSON、结构不是对象等）。"""


@dataclass(frozen=True)
class Diagnostic:
    """带源文件位置的诊断信息。"""

    code: str            # 机器可读错误码，见各 *_ERROR 常量
    message: str         # 人可读描述
    location: str        # 源文件内 JSONPath（或 "$" 表示文档级）

    def to_dict(self) -> dict:
        return {"code": self.code, "message": self.message,
                "location": self.location}


# 诊断错误码
INVALID_JSON = "invalid_json"
INVALID_STRUCTURE = "invalid_structure"
MISSING_REF = "missing_ref"
DUPLICATE_REF = "duplicate_ref"
DANGLING_REF = "dangling_ref"
INVALID_PURL = "invalid_purl"
DUPLICATE_PURL_REF = "duplicate_purl_ref"
UNKNOWN_FORMAT = "unknown_format"


@dataclass
class RawComponent:
    """一个组件在**某个文件内**的出现记录（文件内身份，非全局身份）。"""

    ref: str                          # 文件内引用：bom-ref 或 SPDXID
    name: str
    version: str
    supplier: str                     # 供应者原始表达（无则 ""）
    license_raw: str                  # 许可证原始表达（JSON 文本，无则 ""）
    location: str                     # 源 JSON 中的 JSONPath 位置
    purl: Optional[Purl] = None       # 合法 purl 才会有；否则为 None
    purl_raw: str = ""                # purl 原始字符串（含非法输入留痕）

    def to_dict(self) -> dict:
        return {
            "ref": self.ref, "name": self.name, "version": self.version,
            "supplier": self.supplier, "license_raw": self.license_raw,
            "location": self.location,
            "purl": self.purl.canonical if self.purl else None,
            "purl_raw": self.purl_raw,
        }


@dataclass
class ParsedDocument:
    """单份清单的解析结果：节点、有向边与诊断。"""

    doc_format: str
    components: list[RawComponent] = field(default_factory=list)
    # 依赖边统一为 (from_ref, to_ref, edge_location)，方向=from 依赖 to
    edges: list[tuple[str, str, str]] = field(default_factory=list)
    diagnostics: list[Diagnostic] = field(default_factory=list)
    # 根节点引用：CycloneDX 顶层 dependencies 中的 ref；SPDX 中有入边的节点之外
    root_refs: list[str] = field(default_factory=list)
    ignored_relationships: int = 0   # SPDX 中非依赖关系被忽略的条数
    duplicate_edges: int = 0         # 去重丢弃的重复边数

    @property
    def ok(self) -> bool:
        return not self.diagnostics


# ---------------------------------------------------------------------------
# 格式探测
# ---------------------------------------------------------------------------
def detect_format(data: dict) -> Optional[str]:
    """按文档特征字段判定格式；无法识别返回 None。"""
    if not isinstance(data, dict):
        return None
    if "bomFormat" in data or "components" in data or "dependencies" in data:
        return CYCLONEDX
    if "spdxVersion" in data or "SPDXID" in data or "packages" in data:
        return SPDX
    return None


def parse_document(raw_bytes: bytes) -> ParsedDocument:
    """解析一份清单字节流，返回带完整诊断的 :class:`ParsedDocument`。

    解析永远不抛业务异常（除了完全不可读的 JSON）：所有契约违反都收集到
    ``diagnostics``，由存储层决定拒绝整份文件。
    """
    try:
        data = json.loads(raw_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        doc = ParsedDocument(doc_format="unknown")
        doc.diagnostics.append(
            Diagnostic(INVALID_JSON, f"文档不是合法 UTF-8 JSON: {exc}", "$"))
        return doc
    if not isinstance(data, dict):
        doc = ParsedDocument(doc_format="unknown")
        doc.diagnostics.append(
            Diagnostic(INVALID_STRUCTURE, "文档顶层必须是 JSON 对象", "$"))
        return doc

    doc_format = detect_format(data)
    if doc_format == CYCLONEDX:
        return _parse_cyclonedx(data)
    if doc_format == SPDX:
        return _parse_spdx(data)
    doc = ParsedDocument(doc_format="unknown")
    doc.diagnostics.append(
        Diagnostic(UNKNOWN_FORMAT,
                   "无法识别清单格式（缺少 bomFormat/spdxVersion 等特征字段）", "$"))
    return doc


# ---------------------------------------------------------------------------
# CycloneDX
# ---------------------------------------------------------------------------
def _license_raw_cdx(component: dict) -> str:
    """保留许可证原始表达：licenses 数组整体序列化，不做表达式归一。"""
    licenses = component.get("licenses")
    if licenses is None:
        return ""
    return json.dumps(licenses, ensure_ascii=False, sort_keys=True)


def _supplier_raw_cdx(component: dict) -> str:
    supplier = component.get("supplier")
    if supplier is None:
        return ""
    if isinstance(supplier, dict):
        # 常见形态 {"name": "..."}；完整对象也保留，避免丢字段
        return str(supplier.get("name") or json.dumps(supplier, ensure_ascii=False))
    return str(supplier)


def _parse_cyclonedx(data: dict) -> ParsedDocument:
    doc = ParsedDocument(doc_format=CYCLONEDX)
    seen_refs: set[str] = set()

    def walk(component: dict, location: str) -> None:
        if not isinstance(component, dict):
            doc.diagnostics.append(Diagnostic(
                INVALID_STRUCTURE, "component 必须是对象", location))
            return
        ref = component.get("bom-ref")
        if not isinstance(ref, str) or not ref:
            doc.diagnostics.append(Diagnostic(
                MISSING_REF, "CycloneDX 组件缺少字符串型 bom-ref", location))
            return
        if ref in seen_refs:
            doc.diagnostics.append(Diagnostic(
                DUPLICATE_REF, f"bom-ref {ref!r} 在文件内重复", location))
            return
        seen_refs.add(ref)

        raw = RawComponent(
            ref=ref,
            name=str(component.get("name", "")),
            version=str(component.get("version", "") or ""),
            supplier=_supplier_raw_cdx(component),
            license_raw=_license_raw_cdx(component),
            location=location,
        )
        purl_raw = component.get("purl")
        if purl_raw is not None:
            raw.purl_raw = str(purl_raw)
            try:
                raw.purl = parse_purl(str(purl_raw))
            except PurlError as exc:
                doc.diagnostics.append(Diagnostic(
                    INVALID_PURL, f"组件 {ref!r} 的 purl 非法: {exc}",
                    f"{location}.purl"))
        doc.components.append(raw)

        nested = component.get("components")
        if nested is not None:
            if not isinstance(nested, list):
                doc.diagnostics.append(Diagnostic(
                    INVALID_STRUCTURE, "components 必须是数组",
                    f"{location}.components"))
                return
            for idx, child in enumerate(nested):
                walk(child, f"{location}.components[{idx}]")

    top = data.get("components")
    if top is not None:
        if not isinstance(top, list):
            doc.diagnostics.append(Diagnostic(
                INVALID_STRUCTURE, "顶层 components 必须是数组", "$.components"))
        else:
            for idx, component in enumerate(top):
                walk(component, f"$.components[{idx}]")

    # dependencies：{ref, dependsOn:[...]}，方向 ref -> each dep
    deps = data.get("dependencies")
    if deps is not None:
        if not isinstance(deps, list):
            doc.diagnostics.append(Diagnostic(
                INVALID_STRUCTURE, "dependencies 必须是数组", "$.dependencies"))
        else:
            edge_keys: set[tuple[str, str]] = set()
            for idx, item in enumerate(deps):
                loc = f"$.dependencies[{idx}]"
                if not isinstance(item, dict):
                    doc.diagnostics.append(Diagnostic(
                        INVALID_STRUCTURE, "dependency 项必须是对象", loc))
                    continue
                ref = item.get("ref")
                if not isinstance(ref, str) or not ref:
                    doc.diagnostics.append(Diagnostic(
                        MISSING_REF, "dependency 项缺少字符串型 ref", loc))
                    continue
                if ref not in seen_refs:
                    doc.diagnostics.append(Diagnostic(
                        DANGLING_REF,
                        f"dependency.ref {ref!r} 不指向任何已声明组件", loc))
                    continue
                doc.root_refs.append(ref)
                depends_on = item.get("dependsOn") or []
                if not isinstance(depends_on, list):
                    doc.diagnostics.append(Diagnostic(
                        INVALID_STRUCTURE, "dependsOn 必须是数组",
                        f"{loc}.dependsOn"))
                    continue
                for dep in depends_on:
                    if not isinstance(dep, str) or dep not in seen_refs:
                        doc.diagnostics.append(Diagnostic(
                            DANGLING_REF,
                            f"dependsOn 引用 {dep!r} 不指向任何已声明组件",
                            f"{loc}.dependsOn"))
                        continue
                    key = (ref, dep)
                    if key in edge_keys:
                        doc.duplicate_edges += 1
                        continue
                    edge_keys.add(key)
                    doc.edges.append((ref, dep, loc))
    return doc


# ---------------------------------------------------------------------------
# SPDX
# ---------------------------------------------------------------------------
def _parse_spdx(data: dict) -> ParsedDocument:
    doc = ParsedDocument(doc_format=SPDX)
    seen_ids: set[str] = set()

    packages = data.get("packages")
    if packages is None:
        doc.diagnostics.append(Diagnostic(
            INVALID_STRUCTURE, "SPDX 文档缺少 packages 数组", "$.packages"))
        packages = []
    elif not isinstance(packages, list):
        doc.diagnostics.append(Diagnostic(
            INVALID_STRUCTURE, "packages 必须是数组", "$.packages"))
        packages = []

    for idx, package in enumerate(packages):
        loc = f"$.packages[{idx}]"
        if not isinstance(package, dict):
            doc.diagnostics.append(Diagnostic(
                INVALID_STRUCTURE, "package 必须是对象", loc))
            continue
        spdx_id = package.get("SPDXID")
        if not isinstance(spdx_id, str) or not spdx_id:
            doc.diagnostics.append(Diagnostic(
                MISSING_REF, "SPDX 包缺少字符串型 SPDXID", loc))
            continue
        if spdx_id in seen_ids:
            doc.diagnostics.append(Diagnostic(
                DUPLICATE_REF, f"SPDXID {spdx_id!r} 在文件内重复", loc))
            continue
        seen_ids.add(spdx_id)

        raw = RawComponent(
            ref=spdx_id,
            name=str(package.get("name", "")),
            version=str(package.get("versionInfo", "") or ""),
            supplier=str(package.get("supplier", "") or ""),
            # 许可证原始表达：声明与结论都保留，不做表达式归一
            license_raw=json.dumps(
                {k: package[k] for k in ("licenseDeclared", "licenseConcluded")
                 if k in package},
                ensure_ascii=False, sort_keys=True),
            location=loc,
        )

        purl_refs: list[str] = []
        refs = package.get("externalRefs")
        if refs is not None:
            if not isinstance(refs, list):
                doc.diagnostics.append(Diagnostic(
                    INVALID_STRUCTURE, "externalRefs 必须是数组",
                    f"{loc}.externalRefs"))
            else:
                for ridx, ref_item in enumerate(refs):
                    if not isinstance(ref_item, dict):
                        continue
                    if ref_item.get("referenceType") != "purl":
                        continue
                    purl_refs.append(str(ref_item.get("referenceLocator", "")))
        if len(purl_refs) > 1:
            doc.diagnostics.append(Diagnostic(
                DUPLICATE_PURL_REF,
                f"包 {spdx_id!r} 声明了多个 purl externalRef，无法确定唯一坐标",
                f"{loc}.externalRefs"))
        elif purl_refs:
            raw.purl_raw = purl_refs[0]
            try:
                raw.purl = parse_purl(purl_refs[0])
            except PurlError as exc:
                doc.diagnostics.append(Diagnostic(
                    INVALID_PURL, f"包 {spdx_id!r} 的 purl 非法: {exc}",
                    f"{loc}.externalRefs[{_purl_ref_index(refs)}]"))
        doc.components.append(raw)

    # relationships：只接受 DEPENDS_ON / DEPENDENCY_OF，其余忽略并计数
    relationships = data.get("relationships")
    if relationships is not None:
        if not isinstance(relationships, list):
            doc.diagnostics.append(Diagnostic(
                INVALID_STRUCTURE, "relationships 必须是数组",
                "$.relationships"))
        else:
            edge_keys: set[tuple[str, str]] = set()
            has_incoming: set[str] = set()
            edge_froms: set[str] = set()
            for idx, rel in enumerate(relationships):
                loc = f"$.relationships[{idx}]"
                if not isinstance(rel, dict):
                    doc.diagnostics.append(Diagnostic(
                        INVALID_STRUCTURE, "relationship 必须是对象", loc))
                    continue
                rel_type = rel.get("relationshipType")
                if rel_type not in (_SPDX_DEPENDS_ON, _SPDX_DEPENDENCY_OF):
                    doc.ignored_relationships += 1
                    continue
                src = rel.get("spdxElementId")
                dst = rel.get("relatedSpdxElement")
                if not isinstance(src, str) or not isinstance(dst, str):
                    doc.diagnostics.append(Diagnostic(
                        INVALID_STRUCTURE,
                        "relationship 缺少 spdxElementId/relatedSpdxElement 字符串",
                        loc))
                    continue
                # 统一成 from -> to（from 依赖 to）
                if rel_type == _SPDX_DEPENDS_ON:
                    from_ref, to_ref = src, dst
                else:  # A DEPENDENCY_OF B => B 依赖 A
                    from_ref, to_ref = dst, src
                if from_ref not in seen_ids:
                    doc.diagnostics.append(Diagnostic(
                        DANGLING_REF,
                        f"关系起点 {from_ref!r} 不指向任何已声明 package", loc))
                    continue
                if to_ref not in seen_ids:
                    doc.diagnostics.append(Diagnostic(
                        DANGLING_REF,
                        f"关系终点 {to_ref!r} 不指向任何已声明 package", loc))
                    continue
                key = (from_ref, to_ref)
                if key in edge_keys:
                    doc.duplicate_edges += 1
                    continue
                edge_keys.add(key)
                doc.edges.append((from_ref, to_ref, loc))
                edge_froms.add(from_ref)
                has_incoming.add(to_ref)
            # 根：有出边且无入边的节点（SPDX 无独立 dependencies 段）
            doc.root_refs = sorted(edge_froms - has_incoming)
    return doc


def _purl_ref_index(refs: list) -> int:
    """辅助定位：返回第一个 purl externalRef 的下标。"""
    for idx, item in enumerate(refs):
        if isinstance(item, dict) and item.get("referenceType") == "purl":
            return idx
    return 0
