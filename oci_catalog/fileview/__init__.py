"""镜像层文件视图子系统：离线合成镜像最终文件树。

模块划分：

* :mod:`oci_catalog.fileview.layer_archive`   —— 层归档解析（tar/tar+gzip）、
  路径安全、白标记/不透明目录、硬链接解析与层序归并（纯内存）
* :mod:`oci_catalog.fileview.fileview_store`  —— 独立 SQLite 库、镜像绑定
  校验、单镜像事务构建、失败诊断
* :mod:`oci_catalog.fileview.fileview_queries` —— 列树 / 路径溯源 / 取文件字节
* :mod:`oci_catalog.fileview.fileview_cli`    —— 可直接运行的构建与查询入口

本子系统只读访问既有镜像目录库，不写目录库、不产生 tag 事件，不访问网络，
也不执行镜像中的任何代码；视图数据落在独立 SQLite 库，与目录库、SBOM 库
物理隔离。
"""

from .layer_archive import (
    ENTRY_DIR,
    ENTRY_FILE,
    ENTRY_HARDLINK,
    ENTRY_SYMLINK,
    LayerIngestError,
    MergedEntry,
    TreeMerge,
    ViewDiagnostic,
    normalize_member_path,
    parse_layer_archive,
)
from .fileview_queries import (
    UnknownViewError,
    ViewPathError,
    list_tree,
    normalize_query_path,
    read_file_bytes,
    stat_path,
)
from .fileview_store import (
    BUILT,
    FAILED,
    REPLACED,
    BuildResult,
    FileViewStore,
)

__all__ = [
    "ENTRY_DIR", "ENTRY_FILE", "ENTRY_HARDLINK", "ENTRY_SYMLINK",
    "LayerIngestError", "MergedEntry", "TreeMerge", "ViewDiagnostic",
    "normalize_member_path", "parse_layer_archive",
    "UnknownViewError", "ViewPathError",
    "list_tree", "normalize_query_path", "read_file_bytes", "stat_path",
    "BUILT", "FAILED", "REPLACED", "BuildResult", "FileViewStore",
]
