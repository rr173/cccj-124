"""离线构建证明接入的命令行入口（本地运行，不访问网络）。

用法::

    # 批量导入：每个 --bind 给出 "信封路径=镜像manifest摘要"，可重复
    python3 -m oci_catalog.provenance.provenance_cli import \\
        --catalog /path/catalog.db --prov /path/provenance.db \\
        --bind ./image-amd64.intoto.jsonl=sha256:aaaa... \\
        --bind ./image-arm64.intoto.jsonl=sha256:bbbb...

    # 按策略评价（全部证据，或 --image 限定一个镜像），结论追加评价历史
    python3 -m oci_catalog.provenance.provenance_cli verify \\
        --catalog ... --prov ... --policy policy.json [--image sha256:...]

    # 查询 1：镜像 digest -> 每份构建证明 + 当前策略下的评价
    python3 -m oci_catalog.provenance.provenance_cli image \\
        --catalog ... --prov ... --policy policy.json --digest sha256:...

    # 查询 2：材料 URI + sha256 -> 当前策略下具有可信证明的镜像
    python3 -m oci_catalog.provenance.provenance_cli material \\
        --catalog ... --prov ... --policy policy.json \\
        --uri https://mirror.example/dataset.tar.gz --sha256 <64hex>

    # 辅助：评价历史 / 导入失败诊断
    python3 -m oci_catalog.provenance.provenance_cli evaluations --prov ... --catalog ...
    python3 -m oci_catalog.provenance.provenance_cli failures   --prov ... --catalog ...

退出码：0 正常；2 导入存在失败文件；3 查询错误（未收录 digest 等）；
4 策略不合法（在处理证据前报错）。
"""

from __future__ import annotations

import argparse
import json
import sys

from .policy import PolicyError, load_policy
from .queries import (
    evaluate_evidence,
    query_image_provenance,
    query_material_images,
)
from .store import ProvenanceStore


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="provenance_cli",
        description="离线构建证明（DSSE/in-toto/SLSA）接入与信任评价")
    parser.add_argument("--catalog", required=True,
                        help="既有镜像目录 SQLite 库（只读打开）")
    parser.add_argument("--prov", required=True,
                        help="构建证明独立 SQLite 库（不存在则创建）")
    sub = parser.add_subparsers(dest="command", required=True)

    p_import = sub.add_parser("import", help="批量导入 DSSE 信封文件")
    p_import.add_argument(
        "--bind", action="append", default=[], metavar="PATH=DIGEST",
        help="信封路径与其绑定的单平台 image manifest digest，可重复")

    p_verify = sub.add_parser("verify", help="按策略评价证据并记录结论")
    p_verify.add_argument("--policy", required=True, help="信任策略 JSON 文件")
    p_verify.add_argument("--image", default=None,
                          help="只评价该镜像的证据（默认全部）")

    p_image = sub.add_parser("image", help="镜像 digest 列出每份构建证明")
    p_image.add_argument("--policy", required=True)
    p_image.add_argument("--digest", required=True)

    p_material = sub.add_parser("material", help="材料坐标反查可信镜像")
    p_material.add_argument("--policy", required=True)
    p_material.add_argument("--uri", required=True)
    p_material.add_argument("--sha256", required=True,
                            help="材料 sha256（64 位十六进制）")

    p_evals = sub.add_parser("evaluations", help="查看评价历史（策略摘要+结论）")
    p_evals.add_argument("--evidence", type=int, default=None,
                         help="只看某份证据（默认全部）")

    sub.add_parser("failures", help="查看导入失败诊断")
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


def _load_policy_or_exit(path: str):
    try:
        with open(path, "rb") as fh:
            return load_policy(fh.read())
    except OSError as exc:
        print(json.dumps({"error": f"无法读取策略文件: {exc}"},
                         ensure_ascii=False), file=sys.stderr)
        raise SystemExit(4)
    except PolicyError as exc:
        print(json.dumps({
            "error": "策略不合法（未处理任何证据）",
            "diagnostics": [d.to_dict() for d in exc.diagnostics],
        }, indent=2, ensure_ascii=False), file=sys.stderr)
        raise SystemExit(4)


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    store = ProvenanceStore(args.prov, args.catalog)
    try:
        if args.command == "import":
            results = store.import_paths(_parse_bindings(args.bind))
            print(json.dumps({"results": [r.to_dict() for r in results]},
                             indent=2, ensure_ascii=False))
            return 0 if all(r.ok for r in results) else 2

        if args.command == "verify":
            policy = _load_policy_or_exit(args.policy)
            if args.image is not None:
                evidences = store.list_evidence_for_image(args.image)
            else:
                evidences = store.list_all_evidence()
            evaluations = [evaluate_evidence(store, row, policy).to_dict()
                           for row in evidences]
            print(json.dumps({
                "policy_sha256": policy.policy_sha256,
                "evaluated": len(evaluations),
                "evaluations": evaluations,
            }, indent=2, ensure_ascii=False))
            return 0

        if args.command == "image":
            policy = _load_policy_or_exit(args.policy)
            try:
                print(json.dumps(
                    query_image_provenance(store, args.digest, policy),
                    indent=2, ensure_ascii=False))
            except (KeyError, ValueError) as exc:
                print(json.dumps({"error": str(exc)}, ensure_ascii=False),
                      file=sys.stderr)
                return 3
            return 0

        if args.command == "material":
            policy = _load_policy_or_exit(args.policy)
            try:
                print(json.dumps(
                    query_material_images(store, args.uri, args.sha256,
                                          policy),
                    indent=2, ensure_ascii=False))
            except ValueError as exc:
                print(json.dumps({"error": str(exc)}, ensure_ascii=False),
                      file=sys.stderr)
                return 3
            return 0

        if args.command == "evaluations":
            rows = store.list_evaluations(args.evidence)
            print(json.dumps({
                "evaluations": [dict(row) for row in rows],
            }, indent=2, ensure_ascii=False))
            return 0

        if args.command == "failures":
            rows = store.list_failures()
            print(json.dumps({
                "failures": [dict(row) for row in rows],
            }, indent=2, ensure_ascii=False))
            return 0
    finally:
        store.close()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
