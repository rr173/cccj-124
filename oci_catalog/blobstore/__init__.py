"""本机共享 OCI 原始对象仓（离线镜像治理）。

模块划分：

* :mod:`oci_catalog.blobstore.layout`   —— 严格 JSON、OCI 描述符/layout 解析
* :mod:`oci_catalog.blobstore.locking`  —— 发布锁、读者保护锁、进程身份
* :mod:`oci_catalog.blobstore.store`    —— 独立 SQLite 元数据 + 原始对象文件、
  闭包导入、名称管理、固定读者上下文、两阶段回收
* :mod:`oci_catalog.blobstore.queries`  —— 名称/闭包查询与对象字节导出
* :mod:`oci_catalog.blobstore.blobstore_cli` —— 命令行入口

本子系统只做原始字节的共享存储与生命周期：不运行镜像、不联网拉取、
不合成 tar 文件树、不分析软件清单，也不读写目录/SBOM/文件视图等既有库。
"""

from .layout import (
    OCI_IMAGE_INDEX,
    OCI_IMAGE_MANIFEST,
    Diagnostic,
    Descriptor,
    ParsedManifest,
    SourceError,
    parse_manifest,
    read_layout_root,
)
from .store import (
    DEFAULT_CHUNK_SIZE,
    GC_ALREADY_DELETED,
    GC_DELETED,
    GC_SKIPPED,
    IMPORTED,
    NAME_DELETED,
    NAME_NOT_FOUND,
    NAME_REPLACED,
    NAME_SET,
    READER_ACTIVE,
    READER_CLOSED,
    READER_EXITED,
    REPO_CORRUPT,
    REPO_OK,
    BlobReader,
    BlobStore,
    ClosedReaderError,
    GcPlan,
    GcRun,
    ImportResult,
    RefInfo,
    StoreError,
    UnknownNameError,
    UnknownPlanError,
)
from .queries import (
    closure_manifest,
    export_object,
    list_refs,
    reader_manifest,
    resolve_ref,
)

__all__ = [
    "OCI_IMAGE_MANIFEST", "OCI_IMAGE_INDEX",
    "Diagnostic", "Descriptor", "ParsedManifest", "SourceError",
    "parse_manifest", "read_layout_root",
    "BlobStore", "BlobReader", "ImportResult", "RefInfo", "GcPlan", "GcRun",
    "StoreError", "UnknownNameError", "UnknownPlanError", "ClosedReaderError",
    "DEFAULT_CHUNK_SIZE",
    "IMPORTED", "NAME_SET", "NAME_REPLACED", "NAME_DELETED", "NAME_NOT_FOUND",
    "GC_DELETED", "GC_ALREADY_DELETED", "GC_SKIPPED",
    "READER_ACTIVE", "READER_CLOSED", "READER_EXITED",
    "REPO_OK", "REPO_CORRUPT",
    "list_refs", "resolve_ref", "closure_manifest", "reader_manifest",
    "export_object",
]
