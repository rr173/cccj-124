"""可直接运行的镜像层文件视图入口（纯标准库，离线运行）。

用法::

    # 构建：--layer 给出 "层digest=本地归档路径"，可重复；
    # 镜像 digest 必须是目录中已收录的单平台 image manifest
    python3 -m oci_catalog.fileview.fileview_cli \\
        --catalog /path/catalog.db --views /path/views.db build \\
        --image sha256:aaaa... \\
        --layer sha256:1111...=/layers/l1.tar.gz \\
        --layer sha256:2222...=/layers/l2.tar

    # 列目录（前缀按路径段边界匹配）
    python3 -m oci_catalog.fileview.fileview_cli \\
        --catalog ... --views ... list --image sha256:aaaa... --prefix /data

    # 查看某个路径来自哪一层
    python3 -m oci_catalog.fileview.fileview_cli \\
        --catalog ... --views ... stat --image sha256:aaaa... --path /data/app.conf

    # 把选定普通文件的原始字节写到标准输出（不重编码）
    python3 -m oci_catalog.fileview.fileview_cli \\
        --catalog ... --views ... cat --image sha256:aaaa... \\
        --path /data/bin/blob.bin > blob.bin

    # 查看构建时实际使用的层序 / 失败诊断
    python3 -m oci_catalog.fileview.fileview_cli \\
        --catalog ... --views ... layers --image sha256:aaaa...
    python3 -m oci_catalog.fileview.fileview_cli \\
        --catalog ... --views ... failures

构建存在诊断时退出码为 2；查询类错误（无视图/路径不存在/类型不符/
穿越符号链接）退出码为 3。
"""

from __future__ import annotations

import argparse
import json
import sys

from .fileview_queries import (
    UnknownViewError,
    ViewPathError,
    list_tree,
    read_file_bytes,
    stat_path,
)
from .fileview_store import FileViewStore


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fileview_cli",
        description="离线镜像层文件视图：构建、列目录、溯源、取文件字节")
    parser.add_argument("--catalog", required=True,
                        help="既有镜像目录 SQLite 库（只读打开）")
    parser.add_argument("--views", required=True,
                        help="文件视图独立 SQLite 库（不存在则创建）")
    sub = parser.add_subparsers(dest="command", required=True)

    p_build = sub.add_parser("build", help="按 manifest 层序归并构建文件视图")
    p_build.add_argument("--image", required=True,
                         help="单平台 image manifest digest")
    p_build.add_argument(
        "--layer", action="append", default=[], metavar="DIGEST=PATH",
        help="层 digest 与本地归档文件路径的映射，可重复")

    p_list = sub.add_parser("list", help="按目录前缀列出文件树")
    p_list.add_argument("--image", required=True)
    p_list.add_argument("--prefix", default="/")

    p_stat = sub.add_parser("stat", help="查看路径类型与来源层")
    p_stat.add_argument("--image", required=True)
    p_stat.add_argument("--path", required=True)

    p_cat = sub.add_parser("cat", help="把普通文件原始字节写到标准输出")
    p_cat.add_argument("--image", required=True)
    p_cat.add_argument("--path", required=True)

    p_layers = sub.add_parser("layers", help="查看构建时实际使用的层序")
    p_layers.add_argument("--image", required=True)

    sub.add_parser("failures", help="列出全部构建失败诊断")
    return parser


def _parse_layer_mappings(values: list[str]) -> dict[str, str]:
    mappings: dict[str, str] = {}
    for value in values:
        if "=" not in value:
            raise SystemExit(f"--layer 参数格式必须是 DIGEST=PATH: {value!r}")
        digest, _, path = value.partition("=")
        if not digest or not path:
            raise SystemExit(f"--layer 参数格式必须是 DIGEST=PATH: {value!r}")
        mappings[digest] = path
    return mappings


def _print_json(payload, file=None) -> None:
    print(json.dumps(payload, indent=2, ensure_ascii=False),
          file=file if file is not None else sys.stdout)


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    store = FileViewStore(args.views, args.catalog)
    try:
        if args.command == "build":
            result = store.build_view(args.image,
                                      _parse_layer_mappings(args.layer))
            _print_json(result.to_dict())
            return 0 if result.ok else 2

        if args.command == "list":
            try:
                _print_json(list_tree(store, args.image, args.prefix))
            except (UnknownViewError, ViewPathError) as exc:
                _print_json({"error": str(exc)}, file=sys.stderr)
                return 3
            return 0

        if args.command == "stat":
            try:
                _print_json(stat_path(store, args.image, args.path))
            except (UnknownViewError, ViewPathError) as exc:
                _print_json({"error": str(exc)}, file=sys.stderr)
                return 3
            return 0

        if args.command == "cat":
            try:
                data = read_file_bytes(store, args.image, args.path)
            except (UnknownViewError, ViewPathError) as exc:
                _print_json({"error": str(exc)}, file=sys.stderr)
                return 3
            # 原始字节直写 stdout，不做任何文本编码
            sys.stdout.buffer.write(data)
            sys.stdout.buffer.flush()
            return 0

        if args.command == "layers":
            view = store.get_view(args.image)
            if view is None:
                _print_json(
                    {"error": f"镜像没有可查询的文件视图: {args.image}"},
                    file=sys.stderr)
                return 3
            layers = [dict(row) for row in
                      store.list_view_layers(view["view_id"])]
            _print_json({"image_digest": args.image, "layers": layers})
            return 0

        if args.command == "failures":
            rows = [dict(row) for row in store.list_failures()]
            for row in rows:
                row["diagnostics"] = json.loads(row.pop("diagnostics_json"))
            _print_json({"failures": rows})
            return 0
    finally:
        store.close()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
