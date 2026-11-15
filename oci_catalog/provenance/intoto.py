"""in-toto Statement v1 / SLSA Provenance v1 payload 解析（明确字段边界）。

支持的声明范围（超出即诊断，不静默猜测）：

* ``_type`` 必须为 ``https://in-toto.io/Statement/v1``；
* ``predicateType`` 必须为 ``https://slsa.dev/provenance/v1``；
* ``subject`` 为非空对象列表，每项有 ``name``（字符串）与 ``digest``
  映射；本接入器只读取其中的 ``sha256``（64 位十六进制），其余算法忽略；
* ``predicate.buildDefinition.buildType``：必需非空字符串；
* ``predicate.buildDefinition.resolvedDependencies``：必需列表，每个材料项
  有非空 ``uri`` 与含合法 ``sha256`` 的 ``digest`` 映射；**保留原列表
  位置**，同 URI 不同摘要是不同材料，完全重复的材料两处出现都保留；
* ``predicate.runDetails.builder.id``：必需非空字符串；
* ``predicate.runDetails.metadata.invocationId``：可选字符串，保留为
  构建任务标识。

构建者、构建类型与材料字符串一律**按原值处理**：不从相似名称推断等价，
不做大小写/空白归一。这里只登记直接输入材料；某材料恰好也是另一个镜像
时，不自动拼接成递归依赖图。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .jsonutil import (
    Diagnostic,
    DuplicateKeyError,
    StrictJSONError,
    load_json,
)

#: 支持的 statement 与 predicate 类型常量
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
SLSA_PREDICATE_TYPE = "https://slsa.dev/provenance/v1"

# 诊断错误码（INVALID_JSON/DUPLICATE_JSON_KEY 等结构码与 dsse 保持一致）
INVALID_JSON = "invalid_json"
DUPLICATE_JSON_KEY = "duplicate_json_key"
INVALID_STRUCTURE = "invalid_structure"
MISSING_FIELD = "missing_field"
INVALID_FIELD_TYPE = "invalid_field_type"
UNSUPPORTED_STATEMENT_TYPE = "unsupported_statement_type"
UNSUPPORTED_PREDICATE_TYPE = "unsupported_predicate_type"
EMPTY_SUBJECT_LIST = "empty_subject_list"
EMPTY_URI = "empty_uri"
INVALID_DIGEST = "invalid_digest"

_SHA256_HEX_RE = re.compile(r"^[0-9a-fA-F]{64}$")


def _read_sha256_hex(value: object, location: str,
                     diagnostics: list[Diagnostic]) -> str | None:
    """读取 digest 映射中的 sha256：64 位十六进制，统一存小写。"""
    if not isinstance(value, str) or not _SHA256_HEX_RE.fullmatch(value):
        diagnostics.append(Diagnostic(
            INVALID_DIGEST,
            "sha256 必须是 64 位十六进制字符串"
            + ("" if isinstance(value, str)
               else f"，实际类型 {type(value).__name__}"),
            location))
        return None
    return value.lower()


@dataclass(frozen=True)
class Subject:
    """statement 中的一个 subject 项（保留列表原位置）。"""

    index: int
    name: str
    sha256: str          # 小写十六进制，不含算法前缀

    def to_dict(self) -> dict:
        return {"index": self.index, "name": self.name, "sha256": self.sha256}


@dataclass(frozen=True)
class Material:
    """resolvedDependencies 中的一个材料项（保留列表原位置）。"""

    index: int
    uri: str
    sha256: str          # 小写十六进制，不含算法前缀

    def to_dict(self) -> dict:
        return {"index": self.index, "uri": self.uri, "sha256": self.sha256}


@dataclass
class ParsedStatement:
    """payload 解析结果；诊断非空即失败。"""

    subjects: list[Subject] = field(default_factory=list)
    build_type: str | None = None
    materials: list[Material] = field(default_factory=list)
    builder_id: str | None = None
    invocation_id: str | None = None
    diagnostics: list[Diagnostic] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.diagnostics


def _require_object(node: object, location: str,
                    diagnostics: list[Diagnostic]) -> dict | None:
    if not isinstance(node, dict):
        diagnostics.append(Diagnostic(
            INVALID_STRUCTURE,
            f"期望 JSON 对象，实际 {type(node).__name__}", location))
        return None
    return node


def _require_string(node: object, location: str,
                    diagnostics: list[Diagnostic],
                    allow_empty: bool = False) -> str | None:
    if not isinstance(node, str):
        diagnostics.append(Diagnostic(
            INVALID_FIELD_TYPE,
            f"期望字符串，实际 {type(node).__name__}", location))
        return None
    if not allow_empty and not node:
        diagnostics.append(Diagnostic(
            EMPTY_URI if location.endswith(".uri") else INVALID_FIELD_TYPE,
            "字符串不能为空", location))
        return None
    return node


def parse_statement(payload: bytes) -> ParsedStatement:
    """解析 in-toto Statement v1 payload 原始字节；诊断返回，不抛出。

    诊断位置以 ``payload:`` 为前缀，表示位于 base64 解码后的 payload
    文档内部（与信封层的 ``$`` 位置区分）。
    """
    parsed = ParsedStatement()
    diagnostics = parsed.diagnostics
    base = "payload:$"

    try:
        doc = load_json(payload, base)
    except StrictJSONError as exc:
        diagnostics.append(Diagnostic(INVALID_JSON, str(exc), base))
        return parsed
    except DuplicateKeyError as exc:
        diagnostics.append(Diagnostic(
            DUPLICATE_JSON_KEY,
            f"payload 含重复 JSON 键 {exc.key!r}（拒绝后值覆盖前值）",
            exc.path))
        return parsed

    if _require_object(doc, base, diagnostics) is None:
        return parsed

    # _type / predicateType
    statement_type = doc.get("_type")
    if "_type" not in doc:
        diagnostics.append(Diagnostic(
            MISSING_FIELD, "缺少必需字段 _type", f"{base}._type"))
    elif statement_type != STATEMENT_TYPE:
        diagnostics.append(Diagnostic(
            UNSUPPORTED_STATEMENT_TYPE,
            f"_type 必须是 {STATEMENT_TYPE!r}，实际 {statement_type!r}",
            f"{base}._type"))

    predicate_type = doc.get("predicateType")
    if "predicateType" not in doc:
        diagnostics.append(Diagnostic(
            MISSING_FIELD, "缺少必需字段 predicateType",
            f"{base}.predicateType"))
    elif predicate_type != SLSA_PREDICATE_TYPE:
        diagnostics.append(Diagnostic(
            UNSUPPORTED_PREDICATE_TYPE,
            f"predicateType 必须是 {SLSA_PREDICATE_TYPE!r}，"
            f"实际 {predicate_type!r}", f"{base}.predicateType"))

    _parse_subjects(doc.get("subject"), "subject" in doc, base, parsed)
    _parse_predicate(doc.get("predicate"), "predicate" in doc, base, parsed)
    return parsed


def _parse_subjects(subject: object, present: bool, base: str,
                    parsed: ParsedStatement) -> None:
    diagnostics = parsed.diagnostics
    location = f"{base}.subject"
    if not present:
        diagnostics.append(Diagnostic(
            MISSING_FIELD, "缺少必需字段 subject", location))
        return
    if not isinstance(subject, list):
        diagnostics.append(Diagnostic(
            INVALID_FIELD_TYPE,
            f"subject 必须是列表，实际 {type(subject).__name__}", location))
        return
    if not subject:
        diagnostics.append(Diagnostic(
            EMPTY_SUBJECT_LIST, "subject 不能为空列表", location))
        return
    for index, item in enumerate(subject):
        item_location = f"{location}[{index}]"
        if _require_object(item, item_location, diagnostics) is None:
            continue
        name = item.get("name")
        if "name" not in item:
            diagnostics.append(Diagnostic(
                MISSING_FIELD, "subject 项缺少 name", f"{item_location}.name"))
            name = None
        else:
            name = _require_string(name, f"{item_location}.name",
                                   diagnostics, allow_empty=True)
        digest = item.get("digest")
        if "digest" not in item:
            diagnostics.append(Diagnostic(
                MISSING_FIELD, "subject 项缺少 digest 映射",
                f"{item_location}.digest"))
            continue
        if _require_object(digest, f"{item_location}.digest",
                           diagnostics) is None:
            continue
        if "sha256" not in digest:
            diagnostics.append(Diagnostic(
                MISSING_FIELD,
                "subject 项 digest 映射缺少 sha256（本接入器只按 sha256 绑定）",
                f"{item_location}.digest.sha256"))
            continue
        sha256 = _read_sha256_hex(digest["sha256"],
                                  f"{item_location}.digest.sha256",
                                  diagnostics)
        if name is not None and sha256 is not None:
            parsed.subjects.append(Subject(index=index, name=name,
                                           sha256=sha256))


def _parse_predicate(predicate: object, present: bool, base: str,
                     parsed: ParsedStatement) -> None:
    diagnostics = parsed.diagnostics
    location = f"{base}.predicate"
    if not present:
        diagnostics.append(Diagnostic(
            MISSING_FIELD, "缺少必需字段 predicate", location))
        return
    if _require_object(predicate, location, diagnostics) is None:
        return

    # buildDefinition
    build_def_location = f"{location}.buildDefinition"
    if "buildDefinition" not in predicate:
        diagnostics.append(Diagnostic(
            MISSING_FIELD, "缺少必需字段 buildDefinition", build_def_location))
        build_def = None
    else:
        build_def = _require_object(predicate["buildDefinition"],
                                    build_def_location, diagnostics)
    if build_def is not None:
        if "buildType" not in build_def:
            diagnostics.append(Diagnostic(
                MISSING_FIELD, "缺少必需字段 buildType",
                f"{build_def_location}.buildType"))
        else:
            parsed.build_type = _require_string(
                build_def["buildType"],
                f"{build_def_location}.buildType", diagnostics)
        deps_location = f"{build_def_location}.resolvedDependencies"
        if "resolvedDependencies" not in build_def:
            diagnostics.append(Diagnostic(
                MISSING_FIELD, "缺少必需字段 resolvedDependencies",
                deps_location))
        else:
            _parse_materials(build_def["resolvedDependencies"],
                             deps_location, parsed)

    # runDetails
    run_location = f"{location}.runDetails"
    if "runDetails" not in predicate:
        diagnostics.append(Diagnostic(
            MISSING_FIELD, "缺少必需字段 runDetails", run_location))
        return
    run_details = _require_object(predicate["runDetails"], run_location,
                                  diagnostics)
    if run_details is None:
        return
    builder_location = f"{run_location}.builder"
    if "builder" not in run_details:
        diagnostics.append(Diagnostic(
            MISSING_FIELD, "缺少必需字段 builder", builder_location))
        builder = None
    else:
        builder = _require_object(run_details["builder"], builder_location,
                                  diagnostics)
    if builder is not None:
        if "id" not in builder:
            diagnostics.append(Diagnostic(
                MISSING_FIELD, "缺少必需字段 builder.id",
                f"{builder_location}.id"))
        else:
            parsed.builder_id = _require_string(
                builder["id"], f"{builder_location}.id", diagnostics)

    metadata = run_details.get("metadata")
    if metadata is not None:
        metadata_location = f"{run_location}.metadata"
        if _require_object(metadata, metadata_location, diagnostics) is None:
            return
        invocation = metadata.get("invocationId")
        if invocation is not None:
            parsed.invocation_id = _require_string(
                invocation, f"{metadata_location}.invocationId",
                diagnostics, allow_empty=True)


def _parse_materials(deps: object, location: str,
                     parsed: ParsedStatement) -> None:
    diagnostics = parsed.diagnostics
    if not isinstance(deps, list):
        diagnostics.append(Diagnostic(
            INVALID_FIELD_TYPE,
            f"resolvedDependencies 必须是列表，实际 {type(deps).__name__}",
            location))
        return
    for index, item in enumerate(deps):
        item_location = f"{location}[{index}]"
        if _require_object(item, item_location, diagnostics) is None:
            continue
        uri = item.get("uri")
        if "uri" not in item:
            diagnostics.append(Diagnostic(
                MISSING_FIELD, "材料项缺少 uri", f"{item_location}.uri"))
            uri = None
        else:
            uri = _require_string(uri, f"{item_location}.uri", diagnostics)
        digest = item.get("digest")
        if "digest" not in item:
            diagnostics.append(Diagnostic(
                MISSING_FIELD, "材料项缺少 digest 映射",
                f"{item_location}.digest"))
            continue
        if _require_object(digest, f"{item_location}.digest",
                           diagnostics) is None:
            continue
        if "sha256" not in digest:
            diagnostics.append(Diagnostic(
                MISSING_FIELD, "材料项 digest 映射缺少 sha256",
                f"{item_location}.digest.sha256"))
            continue
        sha256 = _read_sha256_hex(digest["sha256"],
                                  f"{item_location}.digest.sha256",
                                  diagnostics)
        if uri is not None and sha256 is not None:
            # 保留原列表位置；同 URI 不同摘要、完全重复项都各自登记
            parsed.materials.append(Material(index=index, uri=uri,
                                             sha256=sha256))
