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
├── queries.py         # 三类治理查询
└── sbom/              # 离线 SBOM 接入与依赖血缘查询（独立 SQLite 库）
    ├── purl.py            # Package URL 解析/规范化（generic/pypi/npm）
    ├── sbom_parser.py     # CycloneDX/SPDX 解析与数据契约诊断
    ├── sbom_store.py      # 镜像绑定校验、单文件事务、幂等导入
    ├── sbom_queries.py    # 镜像导出 + 组件反查（菱形/环安全最短路径）
    ├── sbom_cli.py        # 批量导入/查询入口（python3 -m ...）
    └── sample_data.py     # 可重建的关联供应商清单样例
oci_catalog/fileview/  # 镜像层文件视图：离线合成镜像最终文件树（独立 SQLite 库）
    ├── layer_archive.py   # tar/tar+gzip 解析、路径安全、白标记/不透明目录、层序归并
    ├── fileview_store.py  # 镜像绑定校验、单镜像事务构建、失败诊断
    ├── fileview_queries.py# 列树 / 路径溯源 / 取文件原始字节
    ├── fileview_cli.py    # 构建与查询入口（python3 -m ...）
    └── sample_layers.py   # 可重建的多层归档演示样例
tests/                 # 184 个 unittest 用例（无第三方依赖）
smoke_demo.py          # 目录采集端到端冒烟演示
run_sbom_demo.py       # SBOM 全流程演示（在独立子进程中做显式验收）
verify_sbom_demo.py    # 被 run_sbom_demo 以新进程启动的验收脚本
run_fileview_demo.py   # 文件视图全流程演示（多层归档 + 新进程验收）
verify_fileview_demo.py# 被 run_fileview_demo 以新进程启动的验收脚本
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
# 全部测试（184 个，纯标准库）
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

## 离线 SBOM 接入与依赖血缘（`oci_catalog.sbom`）

在目录采集之上，把供应商随镜像提供的 CycloneDX/SPDX 软件物料清单加工成统一的
组件明细与依赖关系，并从目录库带出平台上下文。**只做清单数据加工**：不做漏洞
检测、不访问网络；目录库以只读方式打开，接入清单不产生任何 tag 事件，SBOM
数据落在独立 SQLite 库。

### 数据契约

| 维度 | CycloneDX JSON | SPDX JSON |
|---|---|---|
| 文件内身份 | 组件 `bom-ref`（含嵌套 `components`，全文档唯一） | 包 `SPDXID`（全文档唯一） |
| 节点来源 | 递归 `components`，记录 JSONPath 位置 | `packages`，记录 JSONPath 位置 |
| 坐标 | 组件 `purl` 字段 | `externalRefs` 中 `referenceType=purl`（多 purl 报错） |
| 依赖边 | `dependencies`：`ref -> dependsOn[]` | 仅 `DEPENDS_ON`/`DEPENDENCY_OF` 转同方向边；其余关系忽略并计数 |
| 悬空引用 | 边端点不是已声明 bom-ref → 诊断 | 关系端点不是已声明 SPDXID → 诊断 |

* 组件名、版本、供应者、**许可证原始表达**（不做 SPDX 表达式归一）与源文件
  位置全部随出现记录保留，可查回原资料。
* 不靠显示名连接节点；**不同文件即使复用相同引用名也互不相干**——跨文件
  合并只发生在 purl 坐标上，且每个文件内身份（bom-ref/SPDXID）的出现记录
  与依赖边独立保留。
* 非法 purl、文件内重复引用、依赖指向不存在引用，都产出带**文件 + JSONPath
  位置**的诊断；任何诊断都会让整份文件被拒绝。

### purl 归一化（可合并坐标）

* 支持类型：`generic`、`pypi`、`npm`（类型大小写归一，其他类型拒绝）；
* PyPI 按 PEP 503 归一：`[-_.]+` 连续组合 → 单个连字符并转小写
  （`Flask_Core.Ext` 与 `flask-core-ext` 是同一身份）；
* npm scope 转小写、包名本体保留大小写；带百分号编码的名称先解码再规范编码；
* qualifier 键排序、值做规范百分号编码；版本、qualifier、subpath 都参与身份
  区分——同名不同版本、不同 qualifiers、npm 不同 scope 不会误合并；
* 无 purl 的组件 `component_id` 为空，只保留文件内身份，**不从名称/版本臆造
  全局身份**。

### 存储、绑定与事务

* 绑定目标由调用者显式提供，必须是目录中已收录的**单平台 image manifest**；
  tag、index digest、unknown manifest、未收录摘要分别以
  `binding_not_digest`/`binding_not_image`/`binding_unknown_digest` 拒绝。
* 每个文件一个事务：失败时不写任何 components/occurrences/edges，只在
  `import_failures` 留诊断，失败文件不可能被查询成完整清单；逐文件独立成败。
* 重复文件语义：同 `source_path` 重导 → `replaced`（级联替换，不留修订流）；
  不同路径但内容 sha256 与绑定相同 → `duplicate_skipped`；同内容绑定不同
  镜像 → 独立文件 `imported`。

### 两类查询

| 函数 / 子命令 | 行为 |
|---|---|
| `query_image_components` / `image --digest` | 按镜像 digest 逐份来源清单导出组件出现明细、归一化 purl、源位置与**直接依赖**，并带出平台上下文 |
| `query_component_images` / `component --purl` | 按 purl 反查包含该组件的镜像；**每份清单分别**给出从根到该组件的最短依赖路径 |

路径按 `file_id` 严格分组，**绝不跨来源清单拼边**。图允许菱形与环：BFS 距离
保证查询必然终止，环不使清单失效；多条同长路径按文件内引用名字典序稳定选择；
与根不连通的环岛屿以分量内最小引用名为锚点并标注 `anchor_note`。

### 运行

```bash
# 全部测试（184 个，纯标准库；含目录采集回归）
python3 -I -m unittest discover -s tests -p 'test_*.py' -v

# SBOM 端到端演示：关联供应商清单 + 新进程显式验收（期待集合/路径手写列出）
python3 -I run_sbom_demo.py

# 命令行入口
python3 -m oci_catalog.sbom.sbom_cli import --catalog catalog.db --sbom sbom.db \
    --bind vendor-a.cdx.json=sha256:aaaa... --bind vendor-b.spdx.json=sha256:bbbb...
python3 -m oci_catalog.sbom.sbom_cli image    --catalog ... --sbom ... --digest sha256:...
python3 -m oci_catalog.sbom.sbom_cli component --catalog ... --sbom ... --purl 'pkg:pypi/requests@2.32.3'
```

## 镜像层文件视图（`oci_catalog.fileview`）

交付离线数据处理镜像时，需要取出镜像里**实际生效**的配置与数据字典；
直接遍历每层压缩包会把旧版文件、已删除文件也取出来。本子系统按
manifest 层序把各层归并成最终文件树，落独立 SQLite 视图库，之后可
列目录、溯源路径来自哪一层、把选定普通文件的原始字节写到标准输出。
**全程离线**：不拉取 registry，不执行镜像中的任何代码；目录库只读，
SBOM 库与视图库互不混写。

### 层接入边界

* 支持未压缩 tar 与 gzip tar，**按目录库登记的 layer media type 解读**
  （不嗅探）；zstd 等其他压缩格式以 `unsupported_layer_media` 拒绝。
* 归档原始字节的 sha256 必须与 layer digest 一致（`digest_mismatch`）；
  缺层映射（`missing_layer_archive`）、归档不可读、损坏归档、非法成员
  路径、不可解析/成环硬链接，诊断都同时指出**镜像与层**，且整次构建
  失败——不保存任何可供查询的成功视图，只在 `view_failures` 留诊断。
* 绑定目标必须是目录中已收录的单平台 image manifest；tag、index
  digest、未收录摘要分别拒绝。
* 同一层被多个镜像引用时，每个镜像按自己的层序独立归并（视图与层序
  逐镜像记录）；只有文件内容字节按 sha256 在视图库内去重。

### 归并语义（overlay）

* 后层普通文件替换前层同路径内容；目录 ↔ 非目录相互替换时，子树随
  最终类型收敛。
* `.wh.<name>` 删除低层条目（含子树），`.wh..wh..opq` 遮蔽低层该目录
  全部内容；**只遮蔽低层**，同层内容保留，结果不取决于白标记在 tar
  中的先后位置；白标记不作为业务文件导出。
* 同一归档内归一后同路径的成员：**靠后者胜**，胜出成员的归档位置
  （`member_index`）随条目保留。
* 成员路径归一化：拒绝 `..`、绝对路径、空路径、非 UTF-8 名称，
  绝不写到视图树之外。

### 条目与链接

* 区分普通文件 / 目录 / 符号链接 / 硬链接；每条保留最终路径、类型、
  大小、模式、最近改变该路径的 layer digest 与 tar 成员名。
* 符号链接只作为链接信息查询：列树与取文件都**不跟随**（穿越符号
  链接的查询路径被明确拒绝，不可能读到宿主文件）。
* 硬链接目标可在同层靠后的成员中，也可复用低层文件；归并时解析为
  内容快照——后续层覆盖目标路径不影响已建立的链接。无法解析或成环
  的硬链接明确拒绝。

### 查询与入口

| 函数 / 子命令 | 行为 |
|---|---|
| `list_tree` / `list --prefix` | 按目录前缀列树（路径段边界匹配，`/data` 不混 `/database`） |
| `stat_path` / `stat --path` | 查看路径类型与来源层、tar 成员 |
| `read_file_bytes` / `cat --path` | 普通文件/硬链接原始字节直写 stdout（不做文本重编码） |
| `build --image --layer DIGEST=PATH` | 按 manifest 层序构建视图（失败退出码 2） |
| `layers` / `failures` | 查看构建层序 / 失败诊断 |

```bash
# 全部测试（184 个，纯标准库；含目录采集与 SBOM 回归）
python3 -I -m unittest discover -s tests -p 'test_*.py' -v

# 文件视图端到端演示：两平台目录 + 三层归档合成 + 新进程手写验收
python3 -I run_fileview_demo.py

# 命令行入口
python3 -m oci_catalog.fileview.fileview_cli --catalog catalog.db \
    --views views.db build --image sha256:aaaa... \
    --layer sha256:1111...=/layers/l1.tar.gz --layer sha256:2222...=/layers/l2.tar
python3 -m oci_catalog.fileview.fileview_cli --catalog ... --views ... \
    list --image sha256:aaaa... --prefix /data
python3 -m oci_catalog.fileview.fileview_cli --catalog ... --views ... \
    cat --image sha256:aaaa... --path /data/bin/blob.bin > blob.bin
```

## 设计取舍

* 存储选 SQLite 单文件 + WAL：治理场景读多写少、批处理串行提交，零外部依赖；
  写路径以 repository 为最小事务边界，与续办边界一致。
* 客户端基于标准库 `urllib`，无第三方依赖；对接真实 registry 时只需替换
  `RegistryClient` 的基址与凭据，采集/存储/查询层不变。
* 隔离是粘性状态：digest 不符意味着 registry 响应不可信，自动重试可能反复
  污染数据，因此要求人工核实后手工清除 `quarantined_repos` 行。
