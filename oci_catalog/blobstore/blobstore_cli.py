"""可直接运行的 OCI 原始对象仓入口（纯标准库，离线运行）。

用法::

    # 导入：一个本地 OCI Image Layout + 根 manifest digest，可选绑定保留名称
    python3 -m oci_catalog.blobstore.blobstore_cli --store /srv/blobs import \\
        --layout /incoming/delivery-a --root sha256:aaaa... --name delivery-a

    # 名称管理：显式替换 / 删除（删除只解除引用，不立即删字节）
    python3 -m oci_catalog.blobstore.blobstore_cli --store ... name set \\
        --name delivery-a --root sha256:bbbb...
    python3 -m oci_catalog.blobstore.blobstore_cli --store ... name delete \\
        --name delivery-a
    python3 -m oci_catalog.blobstore.blobstore_cli --store ... refs
    python3 -m oci_catalog.blobstore.blobstore_cli --store ... closure \\
        --root sha256:aaaa...

    # 读取：把固定闭包内一个 layer 的原始字节导出到文件
    python3 -m oci_catalog.blobstore.blobstore_cli --store ... export \\
        --name delivery-a --digest sha256:1111... --output ./layer.bin

    # 回收：先生成候选清单，人核对后再显式应用
    python3 -m oci_catalog.blobstore.blobstore_cli --store ... gc plan
    python3 -m oci_catalog.blobstore.blobstore_cli --store ... gc apply \\
        --plan <plan_id>

    # 仓库状态 / 账目 / 恢复
    python3 -m oci_catalog.blobstore.blobstore_cli --store ... status
    python3 -m oci_catalog.blobstore.blobstore_cli --store ... stats
    python3 -m oci_catalog.blobstore.blobstore_cli --store ... recover

退出码：0 成功；2 导入失败或仓库状态异常；3 名称/读者/路径类操作错误；
4 计划不存在或计划参数错误。
"""

from __future__ import annotations

import argparse
import json
import sys

from .queries import (
    closure_manifest,
    export_object,
    list_refs,
    resolve_ref,
)
from .store import (
    GcPlan,
    BlobStore,
    ClosedReaderError,
    StoreError,
    UnknownNameError,
    UnknownPlanError,
)


def _print_json(payload, file=None) -> None:
    print(json.dumps(payload, indent=2, ensure_ascii=False),
          file=file if file is not None else sys.stdout)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="blobstore_cli",
        description="本机共享 OCI 原始对象仓：导入闭包、命名、固定读取、两阶段回收")
    parser.add_argument("--store", required=True,
                        help="对象仓根目录（元数据与原始对象都放在这里）")
    sub = parser.add_subparsers(dest="command", required=True)

    p_import = sub.add_parser("import", help="导入一个本地 OCI Image Layout 闭包")
    p_import.add_argument("--layout", required=True,
                          help="本地 OCI Image Layout 目录")
    p_import.add_argument("--root", required=True,
                          help="根 manifest 的 sha256 digest")
    p_import.add_argument("--name", default=None,
                          help="可选：导入成功后绑定的保留名称")

    p_name = sub.add_parser("name", help="保留名称管理")
    name_sub = p_name.add_subparsers(dest="name_command", required=True)
    p_set = name_sub.add_parser("set", help="把名称指向已完整持有的闭包根")
    p_set.add_argument("--name", required=True)
    p_set.add_argument("--root", required=True)
    p_del = name_sub.add_parser("delete", help="删除名称（不立即删对象）")
    p_del.add_argument("--name", required=True)

    sub.add_parser("refs", help="列出全部保留名称")
    p_resolve = sub.add_parser("resolve", help="查看名称当前指向的根与闭包")
    p_resolve.add_argument("--name", required=True)

    p_closure = sub.add_parser("closure", help="查看某个根的完整闭包清单")
    p_closure.add_argument("--root", required=True)

    p_export = sub.add_parser("export", help="在固定读者上下文中导出对象字节")
    p_export.add_argument("--name", required=True,
                          help="打开读者时名称指向的根即为固定闭包")
    p_export.add_argument("--digest", required=True,
                          help="要导出的对象 digest（必须在固定闭包内）")
    p_export.add_argument("--output", required=True,
                          help="输出文件路径（已存在则拒绝覆盖）")

    p_gc = sub.add_parser("gc", help="两阶段回收")
    gc_sub = p_gc.add_subparsers(dest="gc_command", required=True)
    gc_sub.add_parser("plan", help="生成候选清单（不删除）")
    p_apply = gc_sub.add_parser("apply", help="显式应用一份计划")
    p_apply.add_argument("--plan", required=True, help="计划 ID")
    gc_sub.add_parser("plans", help="列出历史计划")
    gc_sub.add_parser("runs", help="列出历史应用结果")

    sub.add_parser("status", help="仓库一致性检查")
    sub.add_parser("stats", help="对象数与唯一字节账目")
    sub.add_parser("recover", help="重开进程后的保守恢复")
    return parser


def _print_plan(plan: GcPlan) -> None:
    _print_json(plan.to_dict())


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        store = BlobStore(args.store)
    except (StoreError, OSError) as exc:
        _print_json({"error": str(exc)}, file=sys.stderr)
        return 2
    try:
        if args.command == "import":
            result = store.import_layout(args.layout, args.root, args.name)
            _print_json(result.to_dict())
            return 0 if result.ok else 2

        if args.command == "name":
            if args.name_command == "set":
                try:
                    status = store.set_ref(args.name, args.root)
                except StoreError as exc:
                    _print_json({"error": str(exc)}, file=sys.stderr)
                    return 3
                _print_json({"name": args.name, "root": args.root,
                             "status": status})
                return 0
            status = store.delete_ref(args.name)
            _print_json({"name": args.name, "status": status})
            return 0 if status != "not_found" else 3

        if args.command == "refs":
            _print_json({"refs": list_refs(store)})
            return 0

        if args.command == "resolve":
            try:
                _print_json(resolve_ref(store, args.name))
            except UnknownNameError:
                _print_json({"error": f"名称不存在: {args.name}"},
                            file=sys.stderr)
                return 3
            return 0

        if args.command == "closure":
            try:
                _print_json(closure_manifest(store, args.root))
            except StoreError as exc:
                _print_json({"error": str(exc)}, file=sys.stderr)
                return 3
            return 0

        if args.command == "export":
            try:
                reader = store.open_reader(args.name)
            except (UnknownNameError, StoreError) as exc:
                _print_json({"error": str(exc)}, file=sys.stderr)
                return 2
            try:
                result = export_object(reader, args.digest, args.output)
            except (StoreError, ClosedReaderError) as exc:
                _print_json({"error": str(exc)}, file=sys.stderr)
                return 2
            finally:
                reader.close()
            _print_json(result)
            return 0

        if args.command == "gc":
            if args.gc_command == "plan":
                try:
                    plan = store.plan_gc()
                except StoreError as exc:
                    _print_json({"error": str(exc)}, file=sys.stderr)
                    return 2
                _print_plan(plan)
                return 0
            if args.gc_command == "apply":
                try:
                    run = store.apply_gc(args.plan)
                except UnknownPlanError:
                    _print_json({"error": f"计划不存在: {args.plan}"},
                                file=sys.stderr)
                    return 4
                except StoreError as exc:
                    _print_json({"error": str(exc)}, file=sys.stderr)
                    return 2
                _print_json(run.to_dict())
                return 0
            if args.gc_command == "plans":
                _print_json({"plans": store.list_gc_plans()})
                return 0
            _print_json({"runs": store.list_gc_runs()})
            return 0

        if args.command == "status":
            health = store.check_health()
            _print_json(health)
            return 0 if health["status"] == "ok" else 2

        if args.command == "stats":
            _print_json(store.stats())
            return 0

        if args.command == "recover":
            _print_json(store.recover())
            return 0
    finally:
        store.close()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
