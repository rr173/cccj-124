"""严格 JSON 与 OCI 描述符解析（内容对象仓的接收边界）。

这里只做**语法与结构**校验，不读原始对象字节，也不认定对象是否已在本仓：

* 重复 JSON 键（带 JSONPath）与非法 UTF-8 / 语法错误一律拒绝；
* 描述符必须含 ``mediaType``（非空字符串）、``digest``（合法 ``sha256:``）、
  ``size``（非负整数，布尔值不算整数）；``urls``/``annotations`` 等
  其它字段不参与寻址；
* 同一份 manifest 里对同一 digest 的描述必须彼此一致（media type 与 size
  相同），冲突即拒绝；
* 只接受两种 manifest 结构：OCI image manifest（config + layers）与
  OCI image index（manifests 递归）。Docker schema2 / manifest list 与
  artifact manifest 都按不支持拒绝——本仓管理的是 OCI Image Layout。

描述符给出的任何宿主路径都不被采用：对象位置只由校验过的 digest 生成。
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass

from ..digest import sha256_digest

OCI_IMAGE_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
OCI_IMAGE_INDEX = "application/vnd.oci.image.index.v1+json"
OCI_LAYOUT_VERSION = "1.0.0"

# 诊断码（导入失败时逐条给出，定位到 manifest 与 JSONPath）
INVALID_JSON = "invalid_json"
DUPLICATE_KEY = "duplicate_json_key"
INVALID_MANIFEST = "invalid_manifest"
UNSUPPORTED_MANIFEST_TYPE = "unsupported_manifest_type"
INVALID_DESCRIPTOR = "invalid_descriptor"
INVALID_DIGEST = "invalid_digest"
INVALID_SIZE = "invalid_size"
CONFLICTING_DESCRIPTOR = "conflicting_descriptor"
MISSING_OBJECT = "missing_object"
DIGEST_MISMATCH = "digest_mismatch"
SIZE_MISMATCH = "size_mismatch"
UNREADABLE_SOURCE = "unreadable_source"
INVALID_LAYOUT = "invalid_layout"
IMPORT_FAILED = "import_failed"

_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_HEX_RE = re.compile(r"^[0-9a-f]{64}$")


class SourceError(ValueError):
    """输入 layout 或 manifest 字节无法接受（携带机器可读诊断码）。"""

    def __init__(self, message: str, code: str = INVALID_MANIFEST,
                 location: str = ""):
        self.code = code
        self.location = location
        super().__init__(message)


class DuplicateKeyError(SourceError):
    def __init__(self, path: str, key: str):
        self.path = path
        self.key = key
        super().__init__(f"重复 JSON 键 {key!r}（位置 {path}）",
                         code=DUPLICATE_KEY, location=path)


@dataclass(frozen=True)
class Diagnostic:
    """一条接收诊断。``manifest``/``location`` 可能为空（根级问题）。"""

    code: str
    message: str
    manifest: str = ""
    location: str = ""

    def to_dict(self) -> dict:
        return {"code": self.code, "message": self.message,
                "manifest": self.manifest, "location": self.location}


class _Pairs(list):
    __slots__ = ()


def load_strict_json(raw: bytes, path: str = "$") -> object:
    """严格解析 JSON：非法 UTF-8/语法错误 -> SourceError；重复键带路径拒绝。"""
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SourceError(f"不是合法 UTF-8（{path}）: {exc}",
                          code=INVALID_JSON, location=path) from exc
    try:
        tree = json.loads(text, object_pairs_hook=_Pairs)
    except json.JSONDecodeError as exc:
        raise SourceError(f"JSON 语法错误（{path}）: {exc}",
                          code=INVALID_JSON, location=path) from exc
    return _materialize(tree, path)


def _materialize(node, path: str):
    if isinstance(node, _Pairs):
        result = {}
        for key, value in node:
            if key in result:
                raise DuplicateKeyError(path, key)
            result[key] = _materialize(value, f"{path}.{key}")
        return result
    if isinstance(node, list):
        return [_materialize(item, f"{path}[{i}]")
                for i, item in enumerate(node)]
    return node


def is_sha256(value: object) -> bool:
    return isinstance(value, str) and bool(_DIGEST_RE.match(value))


def is_sha256_hex(value: object) -> bool:
    return isinstance(value, str) and bool(_HEX_RE.match(value))


def is_non_negative_int(value: object) -> bool:
    """JSON 整数且 >= 0；``bool`` 明确排除（JSON true/false 不是 size）。"""
    return (isinstance(value, int) and not isinstance(value, bool)
            and value >= 0)


def blob_relpath(digest: str) -> str:
    """由已校验 digest 生成的仓内相对路径。"""
    if not is_sha256(digest):
        raise SourceError(f"非法 sha256 digest: {digest!r}",
                          code=INVALID_DIGEST)
    hexpart = digest.split(":", 1)[1]
    return f"sha256/{hexpart[:2]}/{hexpart}"


@dataclass(frozen=True)
class Descriptor:
    """一个 OCI 内容描述符（只保留寻址与结构字段）。"""

    media_type: str
    digest: str
    size: int
    location: str = ""

    def to_dict(self) -> dict:
        return {"media_type": self.media_type, "digest": self.digest,
                "size": self.size}

    @property
    def blob_relpath(self) -> str:
        """由 digest 生成的仓内相对路径；绝不使用描述符带来的任意路径。"""
        return blob_relpath(self.digest)


def parse_descriptor(node: object, location: str,
                     allowed_types: frozenset[str] | None = None
                     ) -> Descriptor:
    if not isinstance(node, dict):
        raise SourceError(f"{location}: 描述符必须是 JSON 对象",
                          code=INVALID_DESCRIPTOR, location=location)
    media_type = node.get("mediaType")
    if not isinstance(media_type, str) or not media_type:
        raise SourceError(f"{location}: 缺少非空 mediaType",
                          code=INVALID_DESCRIPTOR, location=location)
    if allowed_types is not None and media_type not in allowed_types:
        raise SourceError(
            f"{location}: 不支持的描述符 mediaType {media_type!r}",
            code=UNSUPPORTED_MANIFEST_TYPE, location=location)
    digest = node.get("digest")
    if not is_sha256(digest):
        raise SourceError(
            f"{location}: digest 必须是 'sha256:' + 64 位小写十六进制: "
            f"{digest!r}", code=INVALID_DIGEST, location=location)
    size = node.get("size")
    if not is_non_negative_int(size):
        raise SourceError(f"{location}: size 必须是非负整数: {size!r}",
                          code=INVALID_SIZE, location=location)
    return Descriptor(media_type=media_type, digest=digest, size=size,
                      location=location)


@dataclass(frozen=True)
class ParsedManifest:
    """一份 manifest 的解析结果（保持输入原字节由调用者另行保存）。"""

    digest: str
    media_type: str
    raw: bytes
    config: Descriptor | None = None
    layers: tuple[Descriptor, ...] = ()
    children: tuple[Descriptor, ...] = ()

    @property
    def is_index(self) -> bool:
        return self.media_type == OCI_IMAGE_INDEX


def parse_manifest(raw: bytes, expected_digest: str) -> ParsedManifest:
    """解析并校验一份 manifest 原始字节（digest 必须与字节一致）。

    结构规则：

    * ``schemaVersion`` 必须为 2；
    * image manifest：``config`` 一个描述符 + ``layers`` 描述符数组；
    * image index：``manifests`` 描述符数组（递归 index 允许）；
    * 同一份文档内同一 digest 的多次描述必须一致（mediaType/size），
      冲突拒绝。
    """
    actual = sha256_digest(raw)
    if actual != expected_digest:
        raise SourceError(
            f"manifest 字节摘要 {actual} 与描述的 {expected_digest} 不符",
            code=DIGEST_MISMATCH)
    document = load_strict_json(raw, path="$")
    if not isinstance(document, dict):
        raise SourceError("manifest 必须是 JSON 对象", code=INVALID_MANIFEST)
    if document.get("schemaVersion") != 2:
        raise SourceError("schemaVersion 必须为 2", code=INVALID_MANIFEST,
                          location="$.schemaVersion")
    media_type = document.get("mediaType")
    if not isinstance(media_type, str):
        raise SourceError("manifest 缺少字符串 mediaType",
                          code=INVALID_MANIFEST, location="$.mediaType")

    seen: dict[str, Descriptor] = {}

    def record(desc: Descriptor) -> Descriptor:
        old = seen.get(desc.digest)
        if old is not None:
            if old.media_type != desc.media_type or old.size != desc.size:
                raise SourceError(
                    f"同一 digest {desc.digest} 出现矛盾描述: "
                    f"({old.media_type}, {old.size}) vs "
                    f"({desc.media_type}, {desc.size})",
                    code=CONFLICTING_DESCRIPTOR, location=desc.location)
        else:
            seen[desc.digest] = desc
        return desc

    if media_type == OCI_IMAGE_MANIFEST:
        if "config" not in document:
            raise SourceError("image manifest 缺少 config",
                              code=INVALID_MANIFEST, location="$.config")
        config = record(parse_descriptor(document["config"], "$.config"))
        layers_node = document.get("layers")
        if not isinstance(layers_node, list):
            raise SourceError("image manifest 的 layers 必须是数组",
                              code=INVALID_MANIFEST, location="$.layers")
        layers = tuple(
            record(parse_descriptor(item, f"$.layers[{i}]"))
            for i, item in enumerate(layers_node))
        return ParsedManifest(digest=expected_digest, media_type=media_type,
                              raw=raw, config=config, layers=layers)
    if media_type == OCI_IMAGE_INDEX:
        manifests_node = document.get("manifests")
        if not isinstance(manifests_node, list):
            raise SourceError("image index 的 manifests 必须是数组",
                              code=INVALID_MANIFEST, location="$.manifests")
        children = tuple(
            record(parse_descriptor(item, f"$.manifests[{i}]"))
            for i, item in enumerate(manifests_node))
        return ParsedManifest(digest=expected_digest, media_type=media_type,
                              raw=raw, children=children)
    raise SourceError(f"不支持的 manifest mediaType: {media_type!r}",
                      code=UNSUPPORTED_MANIFEST_TYPE, location="$.mediaType")


@dataclass(frozen=True)
class LayoutRoot:
    """从 ``oci-layout`` + ``index.json`` 选出的根描述符与 layout 目录。"""

    layout_dir: str
    root: Descriptor
    layout_digest: str


def read_layout_root(layout_dir: str, root_digest: str) -> LayoutRoot:
    """校验本地 OCI Image Layout，并确认根 digest 出现在 ``index.json``。

    * ``oci-layout`` 必须存在且 ``imageLayoutVersion`` 为 ``1.0.0``；
    * ``index.json`` 必须是合法 image index，其中必须有一条描述符与
      给定的根 digest 相同（mediaType 为 image manifest 或 image index）；
    * 根对象只按 digest 到 ``blobs/sha256/<hex>`` 读取，**不采用**
      ``index.json`` 中描述符可能携带的 ``urls`` 或任何宿主路径。

    该函数只读输入目录，不写、不改名、不删除任何输入文件。
    """
    if not os.path.isdir(layout_dir):
        raise SourceError(f"layout 目录不存在或不是目录: {layout_dir}",
                          code=INVALID_LAYOUT)
    layout_file = os.path.join(layout_dir, "oci-layout")
    index_file = os.path.join(layout_dir, "index.json")
    for path in (layout_file, index_file):
        if not os.path.isfile(path):
            raise SourceError(f"layout 缺少必需文件: {path}",
                              code=INVALID_LAYOUT)

    try:
        with open(layout_file, "rb") as fh:
            layout_raw = fh.read()
        with open(index_file, "rb") as fh:
            index_raw = fh.read()
    except OSError as exc:
        raise SourceError(f"无法读取 layout 文件: {exc}",
                          code=UNREADABLE_SOURCE) from exc
    layout_doc = load_strict_json(layout_raw, path="oci-layout")
    if (not isinstance(layout_doc, dict)
            or layout_doc.get("imageLayoutVersion") != OCI_LAYOUT_VERSION):
        raise SourceError("oci-layout 的 imageLayoutVersion 必须为 '1.0.0'",
                          code=INVALID_LAYOUT)
    index_doc = load_strict_json(index_raw, path="index.json")
    if not isinstance(index_doc, dict) or not isinstance(
            index_doc.get("manifests"), list):
        raise SourceError("index.json 必须含 manifests 数组",
                          code=INVALID_LAYOUT)

    matches: list[Descriptor] = []
    for i, item in enumerate(index_doc["manifests"]):
        try:
            desc = parse_descriptor(item, f"index.json.manifests[{i}]")
        except SourceError as exc:
            if item and isinstance(item, dict) and item.get("digest") == root_digest:
                raise
            continue
        if desc.digest == root_digest:
            matches.append(desc)
    if not matches:
        raise SourceError(
            f"index.json 中没有 digest 为 {root_digest} 的可读根描述符",
            code=INVALID_LAYOUT)
    first = matches[0]
    for other in matches[1:]:
        if other.media_type != first.media_type or other.size != first.size:
            raise SourceError(
                f"index.json 对根 {root_digest} 存在矛盾描述",
                code=CONFLICTING_DESCRIPTOR)
    if first.media_type not in (OCI_IMAGE_MANIFEST, OCI_IMAGE_INDEX):
        raise SourceError(
            f"不支持的根 manifest mediaType: {first.media_type!r}",
            code=UNSUPPORTED_MANIFEST_TYPE, location="index.json")
    return LayoutRoot(layout_dir=os.path.abspath(layout_dir), root=first,
                      layout_digest=sha256_digest(layout_raw))
