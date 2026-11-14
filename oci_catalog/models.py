"""数据模型与公共异常。

本模块中的所有数据类都是不可变的值对象，对应 OCI Distribution Specification
里的概念：manifest 描述（含 config/layer/子 manifest）、平台描述、扫描报告等。
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional


# ---------------------------------------------------------------------------
# 异常
# ---------------------------------------------------------------------------
class OCIError(Exception):
    """所有 OCI 采集相关异常的基类。"""


class HTTPError(OCIError):
    """非预期的 HTTP 状态码。"""

    def __init__(self, status: int, message: str, url: str = ""):
        super().__init__(f"HTTP {status} {url}: {message}")
        self.status = status
        self.message = message
        self.url = url


class NotFound(OCIError):
    """404：tag/manifest/repository 已被删除。"""


class AuthError(OCIError):
    """鉴权失败（无法换取 token 或权限不足）。"""


class CursorInvalid(OCIError):
    """分页游标已失效（registry 分页状态被重置）。"""


class DigestMismatch(OCIError):
    """响应内容的实际摘要与 registry 声明的 digest 不一致。"""

    def __init__(self, expected: str, actual: str, repository: str = ""):
        super().__init__(
            f"digest 校验失败 repository={repository!r} "
            f"expected={expected} actual={actual}"
        )
        self.expected = expected
        self.actual = actual
        self.repository = repository


class CollectionInterrupted(OCIError):
    """采集在 repository 边界之外被中断（分页失效等），可从检查点续办。"""

    def __init__(self, last_repository: Optional[str], reason: str = ""):
        super().__init__(f"采集中断，最后完成的 repository={last_repository!r}: {reason}")
        self.last_repository = last_repository
        self.reason = reason


# ---------------------------------------------------------------------------
# 枚举
# ---------------------------------------------------------------------------
class ManifestKind(str, Enum):
    """manifest 的结构类别。"""

    IMAGE = "image"          # 单平台 image manifest（含 config + layers）
    INDEX = "index"          # 多平台索引（含子 manifest）
    UNKNOWN = "unknown"      # 未知 media type：只登记身份，不展开结构


class TagEventType(str, Enum):
    """tag -> digest 历史事件类型。"""

    CREATED = "created"      # 新 tag 首次出现
    MOVED = "moved"          # tag 被覆盖，指向另一个 digest
    DELETED = "deleted"      # tag 被删除


class QuarantineReason(str, Enum):
    """仓库被隔离的原因。"""

    DIGEST_MISMATCH = "digest_mismatch"


class ScanStatus(str, Enum):
    SCAN_RUNNING = "running"
    SCAN_INTERRUPTED = "interrupted"
    SCAN_COMPLETED = "completed"


# ---------------------------------------------------------------------------
# 值对象
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Platform:
    """OCI ``platform`` 描述对象（index manifests 的 descriptors 中出现）。"""

    architecture: str = ""
    os: str = ""
    os_version: str = ""
    os_features: tuple[str, ...] = ()
    variant: str = ""
    features: tuple[str, ...] = ()

    @classmethod
    def from_dict(cls, data: Optional[dict]) -> "Platform":
        if not data:
            return cls()
        return cls(
            architecture=data.get("architecture", ""),
            os=data.get("os", ""),
            os_version=data.get("os.version", ""),
            os_features=tuple(data.get("os.features") or ()),
            variant=data.get("variant", ""),
            features=tuple(data.get("features") or ()),
        )

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class Descriptor:
    """OCI content descriptor（子 manifest / config / layer 的公共结构）。"""

    digest: str
    media_type: str
    size: int = 0
    platform: Optional[Platform] = None
    # 仅子 manifest 描述符会带 url/annotations，这里保留原始注解
    annotations: dict = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict) -> "Descriptor":
        platform_data = data.get("platform")
        return cls(
            digest=data["digest"],
            media_type=data.get("mediaType", ""),
            size=int(data.get("size", 0) or 0),
            platform=Platform.from_dict(platform_data) if platform_data else None,
            annotations=dict(data.get("annotations") or {}),
        )


@dataclass(frozen=True)
class ManifestInfo:
    """一次 manifest 拉取的解析结果。

    ``kind`` 决定结构字段如何解释：
    * IMAGE：``config`` 与 ``layers`` 有值；
    * INDEX：``manifests`` 有值（每个 descriptor 带 platform）；
    * UNKNOWN：结构字段为空，只保留 digest/media_type/raw 大小，不递归。
    """

    digest: str
    media_type: str
    kind: ManifestKind
    config: Optional[Descriptor] = None
    layers: tuple[Descriptor, ...] = ()
    manifests: tuple[Descriptor, ...] = ()
    size: int = 0
    subject: Optional[Descriptor] = None

    def to_dict(self) -> dict:
        return {
            "digest": self.digest,
            "media_type": self.media_type,
            "kind": self.kind.value,
            "config": asdict(self.config) if self.config else None,
            "layers": [asdict(x) for x in self.layers],
            "manifests": [asdict(x) for x in self.manifests],
            "size": self.size,
            "subject": asdict(self.subject) if self.subject else None,
        }


@dataclass
class PageResult:
    """分页列表采集结果。"""

    items: list
    """去重后的本页条目（tag 名或 repository 名）。"""
    next_cursor: Optional[str]
    """下一页游标；None 表示到末页。"""
    duplicates: int
    """本页中被去重丢弃的重复条目数（用于验证分页重复处理）。"""


@dataclass
class ScanReport:
    """一次（或续办后完成的）扫描的汇总信息。"""

    scan_id: int
    status: str
    repositories_total: int = 0
    repositories_completed: int = 0
    repositories_quarantined: int = 0
    tags_seen: int = 0
    events_created: int = 0
    events_moved: int = 0
    events_deleted: int = 0
    manifests_ingested: int = 0
    index_expansions: int = 0
    duplicate_page_items: int = 0
    resumed: bool = False
    interrupt_reason: Optional[str] = None

    def to_dict(self) -> dict:
        return asdict(self)
