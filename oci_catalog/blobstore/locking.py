"""跨进程协调：内容仓发布锁、读者保护锁与进程身份。

协调模型（本机共享目录，不依赖后台守护进程）：

* **发布锁** ``locks/publish.lock``：导入在“把暂存字节改名进对象路径 +
  写元数据事务”这一段持有它；回收计划快照与删除也持有它。读者读取
  期间**不**持有该锁，因此长读不会阻塞其他进程发布无关引用或回收。
* **读者保护锁** ``readers/<reader_id>.lock``：读者打开上下文时取得
  ``flock(LOCK_EX)`` 并保持到关闭。flock 由内核在进程退出（含 SIGKILL、
  ``os._exit``）时自动释放，因此下一次回收能据此辨认死亡读者，无需人工
  删除 pin 文件，也不靠“过了多少秒”判断。
* **进程身份**：读者行同时记录 ``pid``、``/proc/<pid>/stat`` 的启动时间
  与 ``boot_id``，只在锁文件本身无法使用时作为保守回退；PID 被复用时
  启动时间不同，不会把新进程误认成旧读者。
* **导入暂存锁** ``staging/<import_id>.lock``：导入把对象字节写进
  ``staging/<import_id>/`` 期间持有；回收只清理由“无持有者”的暂存目录，
  因此不会把正在进行中的导入当垃圾。

``flock`` 是 Linux/POSIX 语义；本仓定位为本机共享目录，不支持跨主机锁。
"""

from __future__ import annotations

import errno
import fcntl
import os

try:  # pragma: no cover - 非 Linux 环境没有 /proc
    _HAVE_FCNTL = True
except ImportError:  # pragma: no cover
    _HAVE_FCNTL = False


class LockError(RuntimeError):
    """锁文件无法打开或平台不支持。"""


class FileLock:
    """基于 ``flock`` 的文件锁；``fd`` 保持打开期间锁有效。"""

    def __init__(self, path: str):
        self.path = path
        self.fd: int | None = None

    def acquire(self, blocking: bool = True) -> bool:
        if not _HAVE_FCNTL:  # pragma: no cover
            raise LockError("本机不支持 flock，无法进行跨进程协调")
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o600)
        flags = fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB)
        try:
            fcntl.flock(fd, flags)
        except OSError as exc:
            os.close(fd)
            if exc.errno in (errno.EAGAIN, errno.EACCES):
                return False
            raise LockError(f"无法锁定 {self.path}: {exc}") from exc
        self.fd = fd
        return True

    def release(self) -> None:
        if self.fd is not None:
            try:
                fcntl.flock(self.fd, fcntl.LOCK_UN)
            finally:
                os.close(self.fd)
                self.fd = None

    def __enter__(self) -> "FileLock":
        self.acquire()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.release()


def lock_is_held(path: str) -> bool | None:
    """探测锁文件当前是否有持有者。

    返回 ``True``（有人持有）、``False``（无人持有，文件可能存在）或
    ``None``（文件不存在/无法探测）。
    """
    if not os.path.exists(path):
        return None
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError:
        return None
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            if exc.errno in (errno.EAGAIN, errno.EACCES):
                return True
            return None
        fcntl.flock(fd, fcntl.LOCK_UN)
        return False
    finally:
        os.close(fd)


# ---------------------------------------------------------------------------
# 进程身份（仅作锁不可用时的保守回退）
# ---------------------------------------------------------------------------
def _read_boot_id() -> str:
    try:
        with open("/proc/sys/kernel/random/boot_id", encoding="ascii") as fh:
            return fh.read().strip()
    except OSError:
        return ""


def process_identity() -> tuple[int, str, str]:
    """返回 (pid, 进程启动时间, boot_id)；无 /proc 时启动时间为空串。"""
    pid = os.getpid()
    return pid, _process_start_time(pid), _read_boot_id()


def _process_start_time(pid: int) -> str:
    try:
        with open(f"/proc/{pid}/stat", encoding="utf-8", errors="replace") as fh:
            data = fh.read()
    except OSError:
        return ""
    # comm 字段可能含空格与右括号，从最后一个 ')' 之后切分
    close = data.rfind(")")
    if close < 0:
        return ""
    fields = data[close + 2:].split()
    # /proc/<pid>/stat 的第 22 个字段（从 1 计）是 starttime；
    # 去掉 pid 与 comm 后，它在 fields 中的下标是 19。
    if len(fields) <= 19:
        return ""
    return fields[19]


def process_alive(pid: int, start_time: str, boot_id: str) -> bool | None:
    """判断记录中的进程是否仍存活。

    * boot_id 不同或没有记录：``None``（无法判断，调用者应按保守方式处理）；
    * 进程不存在或启动时间不符（PID 复用）：``False``；
    * 启动时间一致：``True``。
    """
    if not start_time or not boot_id:
        return None
    current_boot = _read_boot_id()
    if current_boot and current_boot != boot_id:
        return None
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        pass
    except OSError:
        return None
    actual = _process_start_time(pid)
    if not actual:
        return False
    return actual == start_time
