"""OCI 镜像交付发布器（可中断后继续）。

把本机对象仓中保留名称选中的镜像，经受支持的 OCI Distribution 子集
真正送到远端仓库，最后更新交付标签。模块划分：

* :mod:`oci_catalog.pusher.errors`   —— 异常分类（待继续/不可继续可区分）
* :mod:`oci_catalog.pusher.progress` —— 进度文件：绑定校验、状态机、原子落盘
* :mod:`oci_catalog.pusher.client`   —— 发布侧 HTTP 客户端（子集 + 同源纪律）
* :mod:`oci_catalog.pusher.receiver` —— 接收端 HTTP 服务（演示/测试用，
  真实保存字节与请求记录，支持故障注入）
* :mod:`oci_catalog.pusher.pusher`   —— 发布编排（固定读者、对账恢复、依赖序）
* :mod:`oci_catalog.pusher.pusher_cli` —— 命令行入口
* :mod:`oci_catalog.pusher.sample_data` —— 可重建演示数据

边界：只读使用本机对象仓（``open_reader`` 固定根 + 分块读取）；不读写
目录库、SBOM 库、文件视图库、关系库、证明库或公告库；不解包、不重压缩、
不重新序列化清单。
"""

from .errors import (AuthProblem, ProgressProblem, ProtocolProblem,
                     PushError, RangeMismatch, RetryExhausted, SessionGone,
                     SourceProblem, TransientProblem)
from .progress import Binding, Progress, normalize_endpoint
from .client import PushHttpClient
from .pusher import (PushConfig, PushResult, STATUS_COMPLETED,
                     STATUS_IN_PROGRESS, push)
from .receiver import PushReceiver

__all__ = [
    "PushConfig", "PushResult", "push",
    "STATUS_COMPLETED", "STATUS_IN_PROGRESS",
    "PushHttpClient", "PushReceiver",
    "Binding", "Progress", "normalize_endpoint",
    "PushError", "SourceProblem", "ProgressProblem", "ProtocolProblem",
    "AuthProblem", "TransientProblem", "RetryExhausted",
    "RangeMismatch", "SessionGone",
]
