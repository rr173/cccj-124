"""交付发布子系统的异常分类。

三类结局必须在命令行退出码上可区分：

* **待继续**（可恢复中断）：网络异常、连接中断、可重试的 5xx 在有限
  额度内用尽——进度已按保守口径落盘，运维人员带上同一进度文件再次
  执行同一命令即可继续。对应 :class:`RetryExhausted`。
* **不可继续**：源仓/名称/字节问题、进度损坏或绑定冲突、远端违反受
  支持的 HTTP 子集（非法 Range、跨来源 Location、错误完成摘要、
  HEAD 矛盾、依赖缺失等 4xx）、鉴权拒绝。对应 :class:`SourceProblem`、
  :class:`ProgressProblem`、:class:`ProtocolProblem`（含
  :class:`AuthProblem`）。这些错误在发送任何写请求之前或之时确定，
  重跑同一命令不会自愈，必须人工处置。
* **成功**：交付标签已确认指向本次根。

单步请求失败先归类为 :class:`TransientProblem`（网络/超时/5xx）进入
有限重试；额度用尽才汇总为 :class:`RetryExhausted`。
"""

from __future__ import annotations

from typing import Optional


class PushError(Exception):
    """发布作业失败的基类。"""


class SourceProblem(PushError):
    """源仓不可用：名称不存在/已改指向、闭包字节不可读（不可继续）。"""


class ProgressProblem(PushError):
    """进度文件损坏或绑定冲突（不可继续：不覆盖、不新建、不发写请求）。"""


class ProtocolProblem(PushError):
    """远端违反受支持的 HTTP 子集（不可继续的协议错误）。"""


class AuthProblem(ProtocolProblem):
    """401/403 鉴权拒绝：明确失败，不无限重试。"""


class TransientProblem(PushError):
    """单步请求的可重试失败：网络异常、连接中断、超时、5xx。"""


class RetryExhausted(PushError):
    """可重试故障额度用尽：进度已保存，可带同一进度文件继续。"""


class RangeMismatch(PushError):
    """PATCH 错位块（416）：携带服务端确认的前缀与位置，供对账继续。

    这不是失败，而是服务端告知"我实际收到的前缀"的信号；客户端应以
    该值为准继续，而不是按本地记住的字节数。
    """

    def __init__(self, message: str, offset: int,
                 location: Optional[str] = None):
        self.offset = offset
        self.location = location
        super().__init__(message)


class SessionGone(PushError):
    """上传会话已不存在（PATCH/PUT 时 404）：调用方应重开会话。"""
