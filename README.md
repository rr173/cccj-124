# OCI Distribution 只读目录采集器（离线镜像治理）

面向离线镜像治理仓库的只读采集组件：从 OCI Distribution 兼容 registry 采集
repository/tag/manifest 元数据，按 digest 建立不可变内容身份，把 tag 的每次
指向变化记录为历史事件，并支持扫描中断后从 repository 边界续办。

**不下载任何 layer/blob，不依赖真实 registry**——内置内存假 registry、不透明
分页游标和 Bearer 鉴权入口用于本地验证。

## 目录结构

```
oci_catalog/
├── digest.py          # sha256 digest 计算/校验（恒定时间比较）
├── models.py          # 值对象、枚举、异常（ManifestInfo/Platform/事件类型…）
├── fake_registry.py   # 假 registry：HTTP 服务 + 分页游标 + 鉴权 + 故障注入
├── client.py          # OCI Distribution 只读 HTTP 客户端（无 blob 方法）
├── store.py           # SQLite 持久化：内容身份/事件/检查点/隔离/快照
├── collector.py       # 采集编排：递归展开、事件判定、事务、隔离、续办
└── queries.py         # 三类治理查询
tests/                 # 26 个 unittest 用例（无第三方依赖）
smoke_demo.py          # 端到端冒烟演示
```

## 核心语义

### 内容（digest）不可变，名称（tag）可变

* `manifests` 表以 digest 为主键，全局唯一。同一 digest 被多个 tag、多个
  repository 引用时只建立**一次**内容身份（`upsert_manifest` 先查再插）。
* tag 是可变名称，只存于 `tag_state`（当前指向）与 `tag_events`（历史流）。
  每次扫描对比当前观察与旧状态，产生三类只追加事件：
  * `created`：新 tag 首次出现；
  * `moved`：tag 被覆盖，事件同时记录 `old_digest`/`new_digest`；
  * `deleted`：tag 消失（含指向的 manifest 被 GC 的情形）。
* digest 寻址的子 manifest 递归拉取时天然不可变；404（被 GC）只跳过该平台，
  索引 descriptor 与引用路径仍保留，查询结果标记为 `kind=missing`。

### 采集内容

每个 repository 收集：tag 列表、每个 tag 当前 manifest 的 digest 与 media
type、image manifest 的 config/layer digest、index manifest 的子 manifest
descriptor 与平台描述；index 递归展开到各平台子 manifest（带环检测，支持嵌套
索引）。未知 media type 只登记 digest/media type/size（`kind=unknown`），
不猜测结构、不展开。

### digest 校验与仓库隔离

客户端每次拉取 manifest 都用 `Docker-Content-Digest` 头与响应字节的实际
sha256 比对；不符立即抛 `DigestMismatch`。采集器在 **repository 单事务**
内处理整个仓库，任何阶段（含索引子 manifest）校验失败都会：

1. 回滚该仓库的全部缓冲写入（无半截 tag/事件/内容身份）；
2. 在 `quarantined_repos` 登记原因与 expected/actual digest；
3. 后续扫描直接跳过隔离仓库（隔离需人工处置，不自动解除）。

### 分页失效与 repository 边界续办

* 分页同时识别响应体与 RFC 5988 `Link: rel="next"` 头（兼容无尖括号写法）；
  页内与跨页重复条目都去重，游标按真实 offset 推进，不会死循环。
* 游标失效（registry 返回 416/400 RANGE_ERROR）抛 `CursorInvalid`：
  * catalog 阶段失效：scan 标记 `interrupted`，保留检查点；
  * 仓库内 tags 分页失效：该仓库事务回滚，检查点停在上一个完整提交的仓库。
* `checkpoints` 记录每个 registry 最后完成的 repository。再次 `run()` 会
  续办同一个 `scan_id`，已完成/已隔离的仓库自动跳过，事件不重复。

## 三类查询（`oci_catalog.queries`）

| 函数 | 用途 |
|---|---|
| `query_platform_references(store, digest)` | 按 digest 递归展开 index 树，返回每个叶子平台的 manifest/config/layer digest、平台描述、引用路径，以及引用该 digest 的全部 tag |
| `query_tag_history(store, registry, repo, tag)` | 返回 tag 当前指向与完整 created/moved/deleted 事件流 |
| `diff_namespace_scans(store, registry, namespace, scan_a, scan_b)` | 比较两次扫描在该 namespace 下的 tag 增/删/改指向与 repository 集合变化 |

## 假 registry 的测试能力

* `FakeRegistry(auth_enabled=..., duplicate_injection=...)`，线程化 HTTP 服务；
* 不透明 base64 游标（内含 epoch），`bump_cursor_epoch()` 让全部旧游标立即失效；
* Bearer 协商：401 + `WWW-Authenticate` → `/token`（强制 Basic `user:pass`）
  → 按 scope 发放不透明 token，registry 侧强制校验 scope；
* `corrupt_manifest_digest(repo, digest)` 注入错误 digest 头；
* `put_manifest/retag/delete_tag/delete_manifest` 模拟覆盖、删除、GC；
* 观测点 `blob_requests` / `manifest_requests` 用于断言 layer 零下载。

## 运行

```bash
# 全部测试（26 个，纯标准库）
python3 -I -m unittest discover -s tests -p 'test_*.py' -v

# 端到端演示（鉴权 + 多平台 + 改指向/删除 + 三类查询）
python3 -I smoke_demo.py
```

## 测试覆盖对照

| 需求场景 | 用例 |
|---|---|
| 多平台索引递归（含嵌套） | `test_nested_index_expands_to_all_platforms` |
| tag 改指向/删除/重建 | `test_full_tag_lifecycle`、`test_unchanged_tag_emits_no_new_events`、`test_tag_pointing_to_deleted_manifest` |
| 分页重复与游标失效 | `test_duplicate_page_items_are_deduplicated`、`test_cursor_invalid_during_catalog_raises_interrupt`、`test_cursor_expiration_interrupts_and_resumes` |
| 中断续办（多批次幂等） | `test_resume_is_idempotent_across_restarts`、`test_catalog_cursor_failure_mid_scan_then_resume`、`test_tags_cursor_failure_rolls_back_repo_and_resumes` |
| 未知 media type | `test_unknown_media_type_registered_but_not_expanded` |
| 摘要不符与隔离 | `test_digest_mismatch_quarantines_repository`、`test_quarantined_repo_skipped_on_rescan`、`test_corruption_in_index_child_quarantines_whole_repo` |
| 同 digest 多 tag 不重复建身份 | `test_same_digest_multiple_tags_single_identity` |
| namespace 两次扫描对比 | `test_diff_*`（3 个） |
| 鉴权协商与 scope 强制 | `test_auth.py`（4 个） |
| 不下载 layer / 子 manifest GC 容错 | `test_layers_are_never_downloaded`、`test_garbage_collected_index_child_is_tolerated` |

## 设计取舍

* 存储选 SQLite 单文件 + WAL：治理场景读多写少、批处理串行提交，零外部依赖；
  写路径以 repository 为最小事务边界，与续办边界一致。
* 客户端基于标准库 `urllib`，无第三方依赖；对接真实 registry 时只需替换
  `RegistryClient` 的基址与凭据，采集/存储/查询层不变。
* 隔离是粘性状态：digest 不符意味着 registry 响应不可信，自动重试可能反复
  污染数据，因此要求人工核实后手工清除 `quarantined_repos` 行。
