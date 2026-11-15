"""交付发布命令行入口（纯标准库）。

用法::

    python3 -m oci_catalog.pusher.pusher_cli push \\
        --store /srv/blobs --name delivery-a \\
        --endpoint http://127.0.0.1:5000 --repo mirror/worker \\
        --tag release-7 --progress ./progress.json \\
        [--token TOKEN] [--chunk-size 1048576] [--max-attempts 3] \\
        [--timeout 10] [--backoff 0.2]

同一条命令带同一进度文件再次执行即可从中断处继续；参数与进度绑定冲突、
进度损坏、源不可用、协议错误都在发送写请求前或之时拒绝。

退出码（三种结局可区分）：

* ``0`` 交付完成：交付标签已确认指向本次根；
* ``5`` 待继续：可重试故障额度用尽，进度已保存，重跑同一命令继续；
* ``2`` 不可继续：源问题 / 进度损坏或绑定冲突 / 协议错误 / 鉴权拒绝。
"""

from __future__ import annotations

import argparse
import json
import sys

from .errors import (AuthProblem, ProgressProblem, ProtocolProblem,
                     PushError, RetryExhausted, SourceProblem)
from .pusher import (DEFAULT_BACKOFF, DEFAULT_CHUNK_SIZE,
                     DEFAULT_MAX_ATTEMPTS, DEFAULT_TIMEOUT, PushConfig,
                     push)

EXIT_OK = 0
EXIT_FAILED = 2
EXIT_RESUMABLE = 5


def _print_json(payload, file=None) -> None:
    print(json.dumps(payload, indent=2, ensure_ascii=False),
          file=file if file is not None else sys.stdout)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pusher_cli",
        description="把保留名称选中的镜像交付到远端仓库（可中断后继续）")
    sub = parser.add_subparsers(dest="command", required=True)
    p_push = sub.add_parser("push", help="交付一个保留名称选中的根闭包")
    p_push.add_argument("--store", required=True, help="源仓位置（对象仓目录）")
    p_push.add_argument("--name", required=True, help="保留名称")
    p_push.add_argument("--endpoint", required=True,
                        help="目标服务地址（http(s)://host[:port]）")
    p_push.add_argument("--repo", required=True, help="仓库路径")
    p_push.add_argument("--tag", required=True, help="交付标签")
    p_push.add_argument("--progress", required=True, help="进度文件路径")
    p_push.add_argument("--token", default=None,
                        help="固定 Bearer token（不做 token 协商）")
    p_push.add_argument("--chunk-size", type=int,
                        default=DEFAULT_CHUNK_SIZE,
                        help="PATCH 块大小（字节，默认 1MiB）")
    p_push.add_argument("--max-attempts", type=int,
                        default=DEFAULT_MAX_ATTEMPTS,
                        help="连续可重试故障的尝试额度（默认 3）")
    p_push.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT,
                        help="单次请求超时秒数（默认 10）")
    p_push.add_argument("--backoff", type=float, default=DEFAULT_BACKOFF,
                        help="重试间隔秒数（默认 0.2）")
    return parser


def main(argv: list | None = None) -> int:
    args = _build_parser().parse_args(argv)
    config = PushConfig(
        store_path=args.store, name=args.name, endpoint=args.endpoint,
        repo=args.repo, tag=args.tag, progress_path=args.progress,
        token=args.token, chunk_size=args.chunk_size,
        max_attempts=args.max_attempts, timeout=args.timeout,
        backoff=args.backoff)
    try:
        result = push(config)
    except RetryExhausted as exc:
        _print_json({"status": "in_progress", "error": str(exc),
                     "hint": "带同一进度文件重跑同一命令即可继续"},
                    file=sys.stderr)
        return EXIT_RESUMABLE
    except (SourceProblem, ProgressProblem, ProtocolProblem,
            AuthProblem) as exc:
        _print_json({"status": "failed", "error": str(exc)},
                    file=sys.stderr)
        return EXIT_FAILED
    except PushError as exc:
        _print_json({"status": "failed", "error": str(exc)},
                    file=sys.stderr)
        return EXIT_FAILED
    _print_json(result.to_dict())
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
