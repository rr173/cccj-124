"""离线关系加工命令行入口（纯标准库，离线运行）。

用法::

    # 执行一份声明式计划（成功落库，失败只留 run_failures，退出码 2）
    python3 -m oci_catalog.relational.relational_cli run \\
        --plan plan.json --output results.db \\
        --views views.db --catalog catalog.db

    # 列出库中的 run / 某 run 的节点
    python3 -m oci_catalog.relational.relational_cli --output results.db runs
    python3 -m oci_catalog.relational.relational_cli --output results.db nodes \\
        --run 1

    # 查询某节点结果行 / 拒绝明细 / 按行 ID 追溯
    python3 -m oci_catalog.relational.relational_cli --output results.db rows \\
        --run 1 --node region_summary
    python3 -m oci_catalog.relational.relational_cli --output results.db \\
        rejections --run 1 [--table orders]
    python3 -m oci_catalog.relational.relational_cli --output results.db trace \\
        --run 1 --node region_summary --row-id 3

    # 导出节点为 UTF-8 CSV（可重定向到文件）
    python3 -m oci_catalog.relational.relational_cli --output results.db \\
        export --run 1 --node order_detail > detail.csv

    # 查看失败 run 诊断
    python3 -m oci_catalog.relational.relational_cli --output results.db failures

计划/读写类失败退出码 2；查询类错误（run/节点/行不存在）退出码 3。
"""

from __future__ import annotations

import argparse
import json
import sys

from .api import open_result_store, run_plan
from .plan import PlanError, load_plan
from .store import NodeNotFoundError, RunNotFoundError


def _print_json(payload, file=None) -> None:
    print(json.dumps(payload, indent=2, ensure_ascii=False, default=str),
          file=file if file is not None else sys.stdout)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="relational_cli",
        description="离线关系加工：声明式计划 -> 可查询业务结果与逐行血缘")
    parser.add_argument("--output", help="关系结果 SQLite 库")
    sub = parser.add_subparsers(dest="command", required=True)

    p_run = sub.add_parser("run", help="校验并执行一份计划")
    p_run.add_argument("--plan", required=True, help="计划 JSON 文件")
    p_run.add_argument("--output", required=True,
                       help="关系结果 SQLite 库（不存在则创建）")
    p_run.add_argument("--views", required=True,
                       help="已构建文件视图库（只读）")
    p_run.add_argument("--catalog", required=True,
                       help="镜像目录库（只读）")

    sub.add_parser("runs", help="列出全部 run")

    p_nodes = sub.add_parser("nodes", help="列出某 run 的结果节点")
    p_nodes.add_argument("--run", type=int, required=True)

    p_rows = sub.add_parser("rows", help="查询某节点的结果行")
    p_rows.add_argument("--run", type=int, required=True)
    p_rows.add_argument("--node", required=True)

    p_rej = sub.add_parser("rejections", help="查询拒绝明细")
    p_rej.add_argument("--run", type=int, required=True)
    p_rej.add_argument("--table", default=None)

    p_trace = sub.add_parser("trace", help="按结果行 ID 追溯源记录")
    p_trace.add_argument("--run", type=int, required=True)
    p_trace.add_argument("--node", required=True)
    p_trace.add_argument("--row-id", type=int, required=True)

    p_export = sub.add_parser("export", help="导出节点为 UTF-8 CSV")
    p_export.add_argument("--run", type=int, required=True)
    p_export.add_argument("--node", required=True)

    sub.add_parser("failures", help="列出失败 run 诊断")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    if args.command == "run":
        try:
            plan_dict = load_plan(args.plan)
        except PlanError as exc:
            _print_json({"ok": False, "error_code": "plan_invalid",
                         "error_message": str(exc)}, file=sys.stderr)
            return 2
        import json as _json
        with open(args.plan, encoding="utf-8") as fh:
            raw_plan = _json.load(fh)
        outcome = run_plan(raw_plan, args.output, args.views, args.catalog)
        _print_json(outcome.to_dict())
        return 0 if outcome.ok else 2

    if not args.output:
        _print_json({"error": "查询命令需要 --output 结果库"},
                    file=sys.stderr)
        return 3
    store = open_result_store(args.output)
    try:
        if args.command == "runs":
            _print_json({"runs": store.list_runs()})
            return 0
        try:
            if args.command == "nodes":
                _print_json({"run_id": args.run,
                             "nodes": store.list_nodes(args.run)})
            elif args.command == "rows":
                _print_json(store.fetch_rows(args.run, args.node))
            elif args.command == "rejections":
                _print_json({"run_id": args.run, "rejections":
                             store.list_rejections(args.run, args.table)})
            elif args.command == "trace":
                _print_json(store.trace_row(args.run, args.node,
                                            args.row_id))
            elif args.command == "failures":
                _print_json({"failures": store.list_failures()})
            elif args.command == "export":
                sys.stdout.write(store.export_node_csv(args.run, args.node))
                sys.stdout.flush()
        except (RunNotFoundError, NodeNotFoundError) as exc:
            _print_json({"error": str(exc)}, file=sys.stderr)
            return 3
        return 0
    finally:
        store.close()


if __name__ == "__main__":
    raise SystemExit(main())
