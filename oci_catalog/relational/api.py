"""可调用的 Python 接口：一条命令完成“校验计划 -> 读视图 -> 加工 -> 落库”。

入口 :func:`run_plan` 与 :func:`open_result_store` 构成完整的离线关系
加工 API。全程：

* 不访问 registry，不打开镜像内宿主路径——文件字节只经只读文件视图获取；
* 计划先全量校验（重名/未知引用/循环/类型），不合法直接拒绝，不建输出；
* 文件级致命错误（不存在、编码损坏、CSV 结构损坏）让整次加工失败，
  只有记录级不合约进入拒绝明细；
* 成功才在单事务内提交全部节点；任何中途异常都回滚，只留 run_failures。
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Optional

from .engine import Engine, RunArtifacts
from .plan import Plan, PlanError, parse_plan
from .sources import (
    FORMAT_CSV,
    FORMAT_JSONL,
    ReadOnlyViewReader,
    SourceReadError,
    parse_csv_table,
    parse_jsonl_table,
)
from .store import (
    NodeNotFoundError,
    OutputConflictError,
    RelationalStore,
    RunHandle,
    RunNotFoundError,
)

# 失败 run 的错误码（run_failures.error_code）
ERR_PLAN_INVALID = "plan_invalid"
ERR_SOURCE_READ = "source_read_failed"
ERR_OUTPUT_CONFLICT = "output_conflict"
ERR_EXECUTION = "execution_failed"


@dataclass
class RunOutcome:
    """run_plan 的返回：成功句柄或失败诊断（二者互斥）。"""

    ok: bool
    handle: Optional[RunHandle] = None
    error_code: Optional[str] = None
    error_message: Optional[str] = None
    failure_run_id: Optional[int] = None

    def to_dict(self) -> dict:
        return {
            "ok": self.ok,
            "run_id": self.handle.run_id if self.handle else None,
            "node_names": self.handle.node_names if self.handle else [],
            "source_record_count":
                self.handle.source_record_count if self.handle else 0,
            "rejection_count":
                self.handle.rejection_count if self.handle else 0,
            "error_code": self.error_code,
            "error_message": self.error_message,
            "failure_run_id": self.failure_run_id,
        }


def _canonical_plan_json(plan_dict: dict) -> str:
    return json.dumps(plan_dict, ensure_ascii=False, sort_keys=True)


def run_plan(plan_dict: dict, output_db: str, views_db: str,
             catalog_db: str) -> RunOutcome:
    """执行一份声明式计划并把结果落到独立 SQLite 库。

    :param plan_dict: 已在内存中的计划字典（JSON 结构，见项目文档）。
    :param output_db: 结果库输出路径；不得等于任一输入库路径。
    :param views_db: 已构建成功的镜像文件视图库（只读打开）。
    :param catalog_db: 既有镜像目录库（只读打开，供视图绑定校验）。
    :returns: :class:`RunOutcome`；失败时不抛出，而是带错误码返回，
        且保证没有任何成功半成品可被查询。
    """
    plan_json = _canonical_plan_json(plan_dict)

    # 1) 计划全量校验（任何数据读取之前）
    try:
        plan: Plan = parse_plan(plan_dict)
    except PlanError as exc:
        return _record_persisted_failure(
            output_db, views_db, catalog_db,
            ERR_PLAN_INVALID, str(exc), plan_json)

    # 2) 输出路径冲突在写入前拒绝（此时还没建任何结果）
    store: Optional[RelationalStore] = None
    try:
        try:
            store = RelationalStore(
                output_db,
                input_db_paths=[views_db, catalog_db])
        except OutputConflictError as exc:
            return _record_persisted_failure(
                output_db, views_db, catalog_db,
                ERR_OUTPUT_CONFLICT, str(exc), plan_json)

        # 3) 经只读视图读取并解析全部输入表
        reader = ReadOnlyViewReader(views_db, catalog_db)
        try:
            tables = {}
            try:
                for input_name in sorted(plan.inputs):
                    spec = plan.inputs[input_name]
                    byte_sources = [
                        (ref.image_digest, ref.path,
                         reader.fetch_bytes(ref.image_digest, ref.path))
                        for ref in spec.files]
                    if spec.format == FORMAT_CSV:
                        tables[input_name] = parse_csv_table(
                            input_name, spec.contract, byte_sources)
                    elif spec.format == FORMAT_JSONL:
                        tables[input_name] = parse_jsonl_table(
                            input_name, spec.contract, byte_sources)
            except SourceReadError as exc:
                failure_id = store.record_failure(
                    ERR_SOURCE_READ,
                    f"[{exc.code}] {exc.message} "
                    f"(image={exc.image_digest}, path={exc.file_path})",
                    plan_json)
                return RunOutcome(False, error_code=ERR_SOURCE_READ,
                                  error_message=exc.message,
                                  failure_run_id=failure_id)

            # 4) 引擎执行（纯内存变换 + 血缘）
            try:
                artifacts: RunArtifacts = Engine(plan, tables).run()
            except Exception as exc:  # 执行期任何意外都不得留下半成品
                failure_id = store.record_failure(
                    ERR_EXECUTION, f"{type(exc).__name__}: {exc}", plan_json)
                return RunOutcome(False, error_code=ERR_EXECUTION,
                                  error_message=str(exc),
                                  failure_run_id=failure_id)

            # 5) 单事务原子落库
            handle = store.save_run(artifacts, plan_json)
            return RunOutcome(True, handle=handle)
        finally:
            reader.close()
    finally:
        if store is not None:
            store.close()


def _record_persisted_failure(output_db: str, views_db: str,
                              catalog_db: str, code: str,
                              message: str, plan_json: str) -> RunOutcome:
    """计划级/冲突类失败：若可安全打开输出库则留 run_failures 诊断。

    输出路径冲突时不能写该库，直接返回失败而不落任何文件；其余情况
    在独立事务写一条 failure run（不创建任何结果节点）。
    """
    if code == ERR_OUTPUT_CONFLICT:
        return RunOutcome(False, error_code=code, error_message=message)
    try:
        store = RelationalStore(output_db,
                                input_db_paths=[views_db, catalog_db])
    except OutputConflictError:
        return RunOutcome(False, error_code=ERR_OUTPUT_CONFLICT,
                          error_message=message)
    try:
        failure_id = store.record_failure(code, message, plan_json)
    finally:
        store.close()
    return RunOutcome(False, error_code=code, error_message=message,
                      failure_run_id=failure_id)


def open_result_store(output_db: str) -> RelationalStore:
    """以只读方式打开一个已落库的结果库（新进程查询入口）。"""
    return RelationalStore(output_db, readonly=True)
