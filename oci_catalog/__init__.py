"""OCI Distribution 只读目录采集器（离线镜像治理）。"""

from .client import RegistryClient
from .collector import Collector
from .digest import DigestError, sha256_digest
from .fake_registry import (
    FakeRegistry,
    IMAGE_MEDIA_TYPES,
    INDEX_MEDIA_TYPES,
    make_descriptor,
    make_image_manifest,
    make_index_manifest,
)
from .models import (
    AuthError,
    CollectionInterrupted,
    CursorInvalid,
    Descriptor,
    DigestMismatch,
    ManifestInfo,
    ManifestKind,
    NotFound,
    Platform,
    QuarantineReason,
    ScanReport,
    TagEventType,
)
from .queries import (
    diff_namespace_scans,
    latest_completed_scans,
    query_platform_references,
    query_tag_history,
    split_namespace,
)
from .blobstore import (
    BlobReader,
    BlobStore,
    GcPlan,
    GcRun,
    StoreError,
    export_object,
    list_refs,
    read_layout_root,
)
from .pusher import (
    PushConfig,
    PushResult,
    PushReceiver,
    RetryExhausted,
    push,
)
from .sbom import (
    Diagnostic,
    ImportResult,
    ParsedDocument,
    Purl,
    PurlError,
    SBOMStore,
    parse_document,
    parse_purl,
    query_component_images,
    query_image_components,
)
from .store import CatalogStore
from .fileview import (
    BuildResult,
    FileViewStore,
    LayerIngestError,
    TreeMerge,
    ViewDiagnostic,
    ViewPathError,
    UnknownViewError,
    list_tree,
    read_file_bytes,
    stat_path,
)
from .relational import (
    PlanError,
    RelationalStore,
    RunOutcome,
    SourceReadError,
    open_result_store,
    run_plan,
)
from .provenance import (
    Evaluation,
    ImportResult as ProvenanceImportResult,
    Policy,
    PolicyError,
    ProvenanceStore,
    evaluate_evidence,
    key_fingerprint,
    load_policy,
    query_image_provenance,
    query_material_images,
)
from .vuln import (
    AFFECTED,
    NOT_AFFECTED,
    UNCOVERED,
    UNKNOWN,
    AdvisoryError,
    AdvisorySet,
    NoSBOMError,
    UnknownAdvisoryId,
    build_report,
    load_advisory_dir,
    query_advisory,
)

__all__ = [
    "RegistryClient", "Collector", "CatalogStore",
    "FakeRegistry", "IMAGE_MEDIA_TYPES", "INDEX_MEDIA_TYPES",
    "make_descriptor", "make_image_manifest", "make_index_manifest",
    "DigestError", "sha256_digest",
    "AuthError", "CollectionInterrupted", "CursorInvalid",
    "Descriptor", "DigestMismatch", "ManifestInfo", "ManifestKind",
    "NotFound", "Platform", "QuarantineReason", "ScanReport",
    "TagEventType",
    "diff_namespace_scans", "latest_completed_scans",
    "query_platform_references", "query_tag_history", "split_namespace",
    # SBOM 子系统
    "Purl", "PurlError", "parse_purl", "Diagnostic", "ParsedDocument",
    "parse_document", "SBOMStore", "ImportResult",
    "query_image_components", "query_component_images",
    # 镜像层文件视图子系统
    "FileViewStore", "BuildResult", "TreeMerge", "LayerIngestError",
    "ViewDiagnostic", "ViewPathError", "UnknownViewError",
    "list_tree", "stat_path", "read_file_bytes",
    # 离线关系加工子系统
    "run_plan", "open_result_store", "RunOutcome", "RelationalStore",
    "PlanError", "SourceReadError",
    # 离线构建证明子系统
    "ProvenanceStore", "ProvenanceImportResult", "Policy", "PolicyError",
    "load_policy", "key_fingerprint", "evaluate_evidence", "Evaluation",
    "query_image_provenance", "query_material_images",
    # 离线公告关联子系统
    "AdvisoryError", "AdvisorySet", "load_advisory_dir",
    "AFFECTED", "NOT_AFFECTED", "UNCOVERED", "UNKNOWN",
    "NoSBOMError", "UnknownAdvisoryId", "build_report", "query_advisory",
    # 本机共享 OCI 原始对象仓子系统
    "BlobStore", "BlobReader", "StoreError", "GcPlan", "GcRun",
    "read_layout_root", "list_refs", "export_object",
    # OCI 镜像交付发布器子系统
    "PushConfig", "PushResult", "PushReceiver", "RetryExhausted", "push",
]
