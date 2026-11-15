"""离线公告关联子系统：本地 OSV 风格公告 × 已导入 SBOM 的版本判定。

模块划分：

* :mod:`oci_catalog.vuln.versions`  —— PyPI（PEP 440）/ npm（严格 SemVer）
  版本解析与 OSV events 区间校验、求值
* :mod:`oci_catalog.vuln.advisory`  —— 公告目录读取、结构校验、编号等价组
* :mod:`oci_catalog.vuln.correlate` —— 只读关联引擎：逐组件出现项判定与报告
* :mod:`oci_catalog.vuln.vuln_cli`  —— 命令行入口（report / advisory）

边界：不重新导入 SBOM、不访问在线漏洞库、不做运行时漏洞检测、不判断代码
路径能否触发漏洞；公告目录与 SBOM/目录库只读，唯一输出是 JSON 报告。
版本比较委托 ``packaging`` 与 ``semantic_version``（函数内延迟导入，
纯标准库环境下 ``import oci_catalog`` 不受影响）。
"""

from .advisory import (
    Advisory,
    AdvisoryError,
    AdvisorySet,
    Affected,
    Group,
    Range,
    load_advisory_dir,
)
from .correlate import (
    AFFECTED,
    NOT_AFFECTED,
    UNCOVERED,
    UNKNOWN,
    NoSBOMError,
    UnknownAdvisoryId,
    build_report,
    query_advisory,
)
from .versions import (
    Interval,
    VersionParseError,
    validate_range_events,
    versions_available,
)

__all__ = [
    "Advisory", "AdvisoryError", "AdvisorySet", "Affected", "Group", "Range",
    "load_advisory_dir",
    "AFFECTED", "NOT_AFFECTED", "UNCOVERED", "UNKNOWN",
    "NoSBOMError", "UnknownAdvisoryId", "build_report", "query_advisory",
    "Interval", "VersionParseError", "validate_range_events",
    "versions_available",
]
