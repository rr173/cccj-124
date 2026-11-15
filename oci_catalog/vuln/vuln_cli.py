"""离线公告关联作业的命令行入口（纯离线，不访问在线漏洞库）。

用法::

    # 为指定镜像生成逐组件出现项的版本判定报告（JSON）
    python3 -m oci_catalog.vuln.vuln_cli report \\
        --catalog /path/to/catalog.db --sbom /path/to/sbom.db \\
        --advisories /path/to/advisory-dir \\
        --digest sha256:aaaa... [--output report.json]

    # 按任一公告编号（id 或别名）查询该镜像范围中的命中安装项与来源位置
    python3 -m oci_catalog.vuln.vuln_cli advisory \\
        --catalog ... --sbom ... --advisories ... \\
        --digest sha256:aaaa... --id PYSEC-FAKE-0001

退出码：

* 0：作业完成（报告可能包含命中；本工具是报告而非门禁）；
* 2：公告目录不合法（重复 JSON 键/重复 id/结构错误/已支持区间事件错误），
  整次作业失败，不输出貌似完整的评估；
* 3：查询类错误（镜像没有 SBOM、digest 非法、公告编号未知）；
* 4：缺少版本判定依赖（packaging / semantic_version）。
"""

from __future__ import annotations

import argparse
import json
import sys

from .advisory import AdvisoryError, load_advisory_dir
from .correlate import (
    NoSBOMError,
    UnknownAdvisoryId,
    build_report,
    query_advisory,
)
from .versions import MissingVersionDependency


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vuln_cli",
        description="离线公告关联：本地 OSV 风格公告 × 已导入 SBOM 的版本判定")
    parser.add_argument("--catalog", required=True,
                        help="既有镜像目录 SQLite 库（只读打开）")
    parser.add_argument("--sbom", required=True,
                        help="既有 SBOM SQLite 库（只读打开，不重新导入）")
    parser.add_argument("--advisories", required=True,
                        help="本地 OSV 风格公告目录（只读）")
    sub = parser.add_subparsers(dest="command", required=True)

    p_report = sub.add_parser(
        "report", help="为指定镜像生成逐组件出现项的版本判定报告")
    p_report.add_argument("--digest", required=True,
                          help="单平台 image manifest digest")
    p_report.add_argument("--output", default=None,
                          help="报告 JSON 写出路径（缺省写标准输出）")

    p_advisory = sub.add_parser(
        "advisory", help="按任一公告编号查询该镜像范围中的命中安装项")
    p_advisory.add_argument("--digest", required=True,
                            help="单平台 image manifest digest")
    p_advisory.add_argument("--id", required=True,
                            help="公告 id 或其任一等价别名")
    return parser


def _emit(payload: dict, output: str | None) -> None:
    text = json.dumps(payload, indent=2, ensure_ascii=False)
    if output:
        with open(output, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
        print(f"报告已写入 {output}", file=sys.stderr)
    else:
        print(text)


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    try:
        advisory_set = load_advisory_dir(args.advisories)
    except AdvisoryError as exc:
        print(json.dumps({
            "error": "advisory_dir_invalid",
            "diagnostics": [d.to_dict() for d in exc.diagnostics],
        }, indent=2, ensure_ascii=False), file=sys.stderr)
        return 2
    except MissingVersionDependency as exc:
        print(json.dumps({
            "error": "missing_dependency",
            "message": f"{exc}；请安装 packaging 与 semantic_version",
        }, ensure_ascii=False), file=sys.stderr)
        return 4

    try:
        if args.command == "report":
            report = build_report(advisory_set, args.sbom, args.catalog,
                                  args.digest, args.advisories)
            _emit(report, args.output)
            return 0
        if args.command == "advisory":
            result = query_advisory(advisory_set, args.sbom, args.catalog,
                                    args.digest, args.id)
            _emit(result, None)
            return 0
    except NoSBOMError as exc:
        print(json.dumps({
            "error": "no_sbom",
            "status": "no_sbom",
            "message": str(exc),
            "note": "该镜像没有已导入 SBOM，无法评估；"
                    "不能给出零漏洞的成功结论。",
        }, ensure_ascii=False), file=sys.stderr)
        return 3
    except UnknownAdvisoryId as exc:
        print(json.dumps({"error": "unknown_advisory_id",
                          "message": str(exc)}, ensure_ascii=False),
              file=sys.stderr)
        return 3
    except MissingVersionDependency as exc:
        print(json.dumps({
            "error": "missing_dependency",
            "message": f"{exc}；请安装 packaging 与 semantic_version",
        }, ensure_ascii=False), file=sys.stderr)
        return 4
    except ValueError as exc:
        print(json.dumps({"error": "invalid_argument",
                          "message": str(exc)}, ensure_ascii=False),
              file=sys.stderr)
        return 3
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
