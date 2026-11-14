"""只读目录采集器。

编排规则：

1. 分页拉 ``_catalog`` 得到 repository 列表；分页游标失效时，整个 scan 标记为
   interrupted 并保留检查点，下次 ``run()`` 从最后一个已完成 repository 之后继续。
2. 每个 repository 在**单个事务**内处理：tag 列表 -> 逐 tag 拉 manifest ->
   递归展开 index -> 对比旧 tag_state 生成 created/moved/deleted 事件 -> 提交。
   任何 digest 不符都会隔离该仓库并整体回滚，不写入半截数据。
3. manifest 按 digest 去重：同一 digest 被多个 tag/仓库引用只建立一次内容身份。
4. 全程只访问 catalog/tags/manifests 三类端点，绝不下载 layer/blob。
"""

from __future__ import annotations

from typing import Optional

from .client import RegistryClient
from .models import (
    CollectionInterrupted,
    CursorInvalid,
    DigestMismatch,
    ManifestInfo,
    ManifestKind,
    NotFound,
    QuarantineReason,
    ScanReport,
    ScanStatus,
    TagEventType,
)
from .store import CatalogStore


class Collector:
    def __init__(self, client: RegistryClient, store: CatalogStore,
                 registry_name: Optional[str] = None,
                 page_size: Optional[int] = None,
                 stop_after_repos: Optional[int] = None):
        """
        :param stop_after_repos: 测试钩子——完成这么多个 repository 后模拟中断
        """
        self.client = client
        self.store = store
        self.registry = registry_name or client.base_url
        self.page_size = page_size
        self.stop_after_repos = stop_after_repos

    # ------------------------------------------------------------------
    def run(self) -> ScanReport:
        """执行一次扫描；若上次 interrupted，则自动从检查点续办。"""
        scan_id, resumed, checkpoint = self.store.start_scan(self.registry)
        report = ScanReport(scan_id=scan_id, status=ScanStatus.SCAN_RUNNING.value,
                            resumed=resumed)

        try:
            repositories, duplicates = self._collect_catalog(report, checkpoint)
            report.repositories_total = len(repositories)
            report.duplicate_page_items = duplicates

            for repository in repositories:
                if self.store.is_repo_completed(scan_id, repository):
                    report.repositories_completed += 1
                    continue
                if self.store.is_quarantined(self.registry, repository):
                    report.repositories_quarantined += 1
                    continue
                self._process_repository(scan_id, repository, report)
                report.repositories_completed += 1

                # 测试钩子：在 repository 边界模拟进程中断
                if (self.stop_after_repos is not None
                        and report.repositories_completed >= self.stop_after_repos):
                    reason = (f"simulated interruption after "
                              f"{report.repositories_completed} repositories")
                    self.store.interrupt_scan(scan_id, reason)
                    report.status = ScanStatus.SCAN_INTERRUPTED.value
                    report.interrupt_reason = reason
                    return report
        except CollectionInterrupted as exc:
            # catalog 或仓库内 tags 分页游标失效：保留 repository 边界检查点
            self.store.interrupt_scan(scan_id, exc.reason)
            report.status = ScanStatus.SCAN_INTERRUPTED.value
            report.interrupt_reason = exc.reason
            return report

        self.store.complete_scan(scan_id)
        report.status = ScanStatus.SCAN_COMPLETED.value
        self._fill_counts(scan_id, report)
        return report

    def _fill_counts(self, scan_id: int, report: ScanReport) -> None:
        report.tags_seen = self.store.count_observations(scan_id)
        report.events_created = self.store.count_events(scan_id, TagEventType.CREATED)
        report.events_moved = self.store.count_events(scan_id, TagEventType.MOVED)
        report.events_deleted = self.store.count_events(scan_id, TagEventType.DELETED)
        report.repositories_quarantined = self.store.count_quarantined(self.registry)

    # ------------------------------------------------------------------
    # _catalog 分页：游标失效 -> 在 repository 边界中断
    # ------------------------------------------------------------------
    def _collect_catalog(self, report: ScanReport,
                         resume_after: Optional[str]) -> tuple[list[str], int]:
        names: list[str] = []
        seen: set[str] = set()
        duplicates = 0
        cursor: Optional[str] = None
        try:
            while True:
                page = self.client.list_repositories_page(
                    cursor=cursor, page_size=self.page_size)
                duplicates += page.duplicates
                for name in page.items:
                    if name in seen:  # 跨页重复也要去重
                        duplicates += 1
                        continue
                    seen.add(name)
                    names.append(name)
                if page.next_cursor is None:
                    break
                cursor = page.next_cursor
        except CursorInvalid as exc:
            # 分页状态丢失：保留已完成的仓库边界，下次续办
            last = self.store.get_checkpoint(self.registry)
            raise CollectionInterrupted(last, f"catalog 游标失效: {exc}") from exc

        if resume_after is not None:
            try:
                idx = names.index(resume_after)
                names = names[idx + 1:]
            except ValueError:
                # 检查点仓库已从 registry 删除：从头开始也无妨，已完成的会跳过
                pass
        return names, duplicates

    # ------------------------------------------------------------------
    # 单个 repository：边界事务
    # ------------------------------------------------------------------
    def _process_repository(self, scan_id: int, repository: str,
                            report: ScanReport) -> None:
        if not self.store.begin_repo_ingestion(scan_id, self.registry, repository):
            report.repositories_quarantined += 1
            return
        try:
            tags = self._collect_tags(repository)
            current: dict[str, str] = {}  # tag -> digest

            for tag in tags:
                info = self._fetch_and_ingest(repository, tag, report)
                current[tag] = info.digest
                self.store.record_tag_observation(
                    scan_id, self.registry, repository, tag,
                    info.digest, info.media_type)
                self._record_tag_change(scan_id, repository, tag, info)

            # 本轮已不存在的旧 tag -> deleted 事件
            for row in self.store.list_tag_states(self.registry, repository):
                if row["tag"] not in current:
                    self.store.record_tag_event(
                        scan_id, self.registry, repository, row["tag"],
                        TagEventType.DELETED, row["digest"], None)
                    self.store.delete_tag_state(
                        self.registry, repository, row["tag"])
        except DigestMismatch as exc:
            # 隔离整个 repository，本仓库所有缓冲写入全部回滚
            self.store.rollback_repo_ingestion()
            self.store.quarantine_repo(
                self.registry, repository, QuarantineReason.DIGEST_MISMATCH,
                expected=exc.expected, actual=exc.actual)
            report.repositories_quarantined += 1
            return
        except CursorInvalid as exc:
            self.store.rollback_repo_ingestion()
            raise CollectionInterrupted(
                self.store.get_checkpoint(self.registry),
                f"tags 游标失效 ({repository}): {exc}") from exc

        self.store.commit_repo_ingestion(scan_id, self.registry, repository)

    def _collect_tags(self, repository: str) -> list[str]:
        tags: list[str] = []
        seen: set[str] = set()
        cursor: Optional[str] = None
        while True:
            page = self.client.list_tags_page(
                repository, cursor=cursor, page_size=self.page_size)
            for tag in page.items:
                if tag not in seen:
                    seen.add(tag)
                    tags.append(tag)
            if page.next_cursor is None:
                break
            cursor = page.next_cursor
        return tags

    # ------------------------------------------------------------------
    # manifest 拉取 + 索引递归（带环检测）
    # ------------------------------------------------------------------
    def _fetch_and_ingest(self, repository: str, reference: str,
                          report: ScanReport,
                          trail: Optional[set[str]] = None) -> ManifestInfo:
        trail = set(trail or ())
        info = self.client.get_manifest(repository, reference)
        if info.digest in trail:
            # 索引环：registry 数据异常，停止递归但保留已见内容
            return info
        trail = trail | {info.digest}

        # 内容身份按 digest 去重；已收录过的 manifest 不重复写库
        if not self.store.has_manifest(info.digest):
            self.store.upsert_manifest(info)
            report.manifests_ingested += 1

        if info.kind is ManifestKind.INDEX:
            report.index_expansions += 1
            for child in info.manifests:
                # 子 manifest 用 digest 寻址（不可变引用），递归展开各平台
                try:
                    self._fetch_and_ingest(
                        repository, child.digest, report, trail)
                except NotFound:
                    # 索引引用了已被 GC 的子 manifest：跳过该平台，
                    # 索引本身的 descriptor 仍保留在 manifest_children 中
                    continue
        return info

    # ------------------------------------------------------------------
    def _record_tag_change(self, scan_id: int, repository: str,
                           tag: str, info: ManifestInfo) -> None:
        previous = self.store.get_tag_state(self.registry, repository, tag)
        if previous is None:
            self.store.record_tag_event(
                scan_id, self.registry, repository, tag,
                TagEventType.CREATED, None, info.digest)
        elif previous["digest"] != info.digest:
            self.store.record_tag_event(
                scan_id, self.registry, repository, tag,
                TagEventType.MOVED, previous["digest"], info.digest)
        self.store.upsert_tag_state(
            self.registry, repository, tag, info.digest, info.media_type)
