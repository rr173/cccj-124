"""离线 SBOM 数据接入与依赖血缘查询子系统。

模块划分：

* :mod:`oci_catalog.sbom.purl`     —— Package URL 解析与规范化（合并坐标）
* :mod:`oci_catalog.sbom.sbom_parser` —— CycloneDX/SPDX 文档解析与数据契约校验
* :mod:`oci_catalog.sbom.sbom_store`  —— 独立 SQLite 库、镜像绑定校验、单文件事务导入
* :mod:`oci_catalog.sbom.sbom_queries` —— 镜像组件导出与组件反查（含最短依赖路径）
* :mod:`oci_catalog.sbom.sbom_cli`   —— 可直接运行的批量导入/查询入口

本子系统只读访问既有镜像目录库，不写目录库、不产生 tag 事件，也不访问网络。
"""

from .purl import Purl, PurlError, parse_purl, SUPPORTED_PURL_TYPES
from .sbom_parser import (
    Diagnostic,
    ParsedDocument,
    RawComponent,
    detect_format,
    parse_document,
)
from .sbom_store import ImportResult, SBOMStore
from .sbom_queries import query_component_images, query_image_components

__all__ = [
    "Purl", "PurlError", "parse_purl", "SUPPORTED_PURL_TYPES",
    "Diagnostic", "ParsedDocument", "RawComponent", "detect_format",
    "parse_document",
    "ImportResult", "SBOMStore",
    "query_image_components", "query_component_images",
]
