"""可直接运行的批量导入与查询入口（纯标准库，离线运行）。

用法::

    # 批量导入：每个 --bind 给出 "清单路径=镜像manifest摘要"，可重复
    python3 -m oci_catalog.sbom.sbom_cli import \\
        --catalog /path/to/catalog.db --sbom /path/to/sbom.db \\
        --bind ./vendor-a.cdx.json=sha256:aaaa... \\
        --bind ./vendor-b.spdx.json=sha256:bbbb...

    # 查询 1：镜像 digest -> 组件出现明细 + 直接依赖
    python3 -m oci_catalog.sbom.sbom_cli image \\
        --catalog /path/to/catalog.db --sbom /path/to/sbom.db \\
        --digest sha256:aaaa...

    # 查询 2：组件 purl -> 包含它的镜像与每份清单中的依赖路径
    python3 -m oci_catalog.sbom.sbom_cli component \\
        --catalog /path/to/catalog.db --sbom /path/to/sbom.db \\
        --purl 'pkg:pypi/urllib3@1.26.18'

导入结果逐文件打印 JSON 状态；任一文件失败时进程退出码为 2，
查询类错误（未收录 digest/坐标）退出码为 3。
"""

from __future__ import annotations

import argparse
import json
import sys

from .sbom_queries import query_component_images, query_image_components
from .sbom_store import SBOMStore


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sbom_cli",
        description="离线 SBOM 批量导入与依赖血缘查询")
    parser.add_argument("--catalog", required=True,
                        help="既有镜像目录 SQLite 库（只读打开）")
    parser.add_argument("--sbom", required=True,
                        help="SBOM 独立 SQLite 库（不存在则创建）")
    sub = parser.add_subparsers(dest="command", required=True)

    p_import = sub.add_parser("import", help="批量导入清单文件")
    p_import.add_argument(
        "--bind", action="append", default=[], metavar="PATH=DIGEST",
        help="清单路径与其绑定的单平台 image manifest digest，可重复")

    p_image = sub.add_parser("image", help="镜像 digest 导出组件明细")
    p_image.add_argument("--digest", required=True)

    p_component = sub.add_parser("component", help="组件坐标反查镜像与路径")
    p_component.add_argument("--purl", required=True)
    return parser


def _parse_bindings(values: list[str]) -> list[tuple[str, str]]:
    bindings: list[tuple[str, str]] = []
    for value in values:
        if "=" not in value:
            raise SystemExit(f"--bind 参数格式必须是 PATH=DIGEST: {value!r}")
        path, _, digest = value.partition("=")
        if not path or not digest:
            raise SystemExit(f"--bind 参数格式必须是 PATH=DIGEST: {value!r}")
        bindings.append((path, digest))
    return bindings


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    store = SBOMStore(args.sbom, args.catalog)
    try:
        if args.command == "import":
            results = store.import_paths(_parse_bindings(args.bind))
            payload = {"results": [r.to_dict() for r in results]}
            print(json.dumps(payload, indent=2, ensure_ascii=False))
            return 0 if all(r.ok for r in results) else 2

        if args.command == "image":
            try:
                print(json.dumps(
                    query_image_components(store, args.digest),
                    indent=2, ensure_ascii=False))
            except KeyError as exc:
                print(json.dumps({"error": str(exc)}, ensure_ascii=False),
                      file=sys.stderr)
                return 3
            return 0

        if args.command == "component":
            try:
                print(json.dumps(
                    query_component_images(store, args.purl),
                    indent=2, ensure_ascii=False))
            except (KeyError, ValueError) as exc:
                print(json.dumps({"error": str(exc)}, ensure_ascii=False),
                      file=sys.stderr)
                return 3
            return 0
    finally:
        store.close()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
