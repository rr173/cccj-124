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
from .store import CatalogStore

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
]
