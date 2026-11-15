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
oci_catalog/relational/ # 离线关系加工：声明式计划 -> 业务结果 + 逐行血缘（独立 SQLite 库）
    ├── contract.py          # 字段契约、严格类型/定点十进制、单记录校验
    ├── sources.py           # 只读视图取字节、CSV/JSONL 解析、物理行定位
    ├── expression.py        # 受限过滤表达（手写分析器、三值逻辑、无 eval）
    ├── plan.py              # 计划全量校验（重名/未知引用/循环/顺序无关拓扑）
    ├── engine.py            # 选列/过滤/连接/分组执行与血缘多重集
    ├── store.py             # 单事务原子落库、新进程查询/追溯/CSV 导出
    ├── relational_cli.py    # 命令行入口（python3 -m ...）
    ├── sample_relational.py # 可重建的关系加工演示数据与计划
    └── README.md            # 计划格式与运行方式详述
oci_catalog/provenance/ # 离线构建证明：DSSE 信封 + in-toto/SLSA 声明 + 本地信任策略（独立 SQLite 库）
    ├── jsonutil.py          # 严格 JSON（重复键带 JSONPath 拒绝）
    ├── dsse.py              # DSSE 信封解析、PAE、Ed25519 验签（cryptography）
    ├── intoto.py            # in-toto Statement v1 / SLSA Provenance v1 解析
    ├── policy.py            # 本地信任策略：公钥登记 + 授权规则 + 门槛校验
    ├── store.py             # 独立 SQLite 证据库、绑定校验、幂等导入
    ├── queries.py           # 证据评价（即时验签计票）与镜像/材料两类查询
    ├── provenance_cli.py    # 命令行入口（python3 -m ...）
    ├── sample_data.py       # 可重建的三对测试密钥/信封/策略样例
    └── README.md            # 字段边界、策略例子、失败与未信任的区别、限制
oci_catalog/vuln/      # 离线公告关联：本地 OSV 风格公告 × 已导入 SBOM 的版本判定（只读输入）
    ├── versions.py          # PEP 440（packaging）/ 严格 SemVer（semantic_version）与 OSV 区间校验求值
    ├── advisory.py          # 公告目录读取、结构校验、编号等价组（传递闭包）
    ├── correlate.py         # 只读关联引擎：逐出现项判定、报告与按编号查询
    ├── vuln_cli.py          # 命令行入口（python3 -m ...）
    ├── sample_data.py       # 可重建的两平台 SBOM + 人工公告样例
    └── README.md            # 本次接受的公告子集、区间语义、状态机与限制
tests/                 # 454 个 unittest 用例（目录/SBOM/文件视图/关系为纯标准库；证明子系统需 cryptography，公告关联需 packaging+semantic_version）
smoke_demo.py          # 目录采集端到端冒烟演示
run_sbom_demo.py       # SBOM 全流程演示（在独立子进程中做显式验收）
verify_sbom_demo.py    # 被 run_sbom_demo 以新进程启动的验收脚本
run_fileview_demo.py   # 文件视图全流程演示（多层归档 + 新进程验收）
verify_fileview_demo.py# 被 run_fileview_demo 以新进程启动的验收脚本
run_relational_demo.py # 关系加工全流程演示（声明式计划 + 新进程手写验收）
verify_relational_demo.py # 被 run_relational_demo 以新进程启动的验收脚本
run_provenance_demo.py # 构建证明全流程演示（导入/换策略/新进程验收）
verify_provenance_demo.py # 被 run_provenance_demo 以新进程启动的验收脚本
run_vuln_demo.py       # 公告关联全流程演示（命令行报告 + 另一进程按别名查询 + 新进程验收）
verify_vuln_demo.py    # 被 run_vuln_demo 以新进程启动的验收脚本（期待值手写为常量表）
```

## 依赖安装

目录采集、SBOM、文件视图、关系加工四个子系统为**纯标准库**；两个子系统
各有一个第三方依赖（函数内延迟导入，缺失时其余功能与 `import oci_catalog`
不受影响，对应测试自动跳过）：

```bash
pip install cryptography                # 仅 provenance 子系统需要
pip install packaging semantic_version  # 仅 vuln 子系统需要
```

本仓库根目录的 `.venv/` 已按上述方式备好（`python3 -m venv .venv
--without-pip` 后把纯 Python wheel 解包进其 site-packages），下文用
`.venv/bin/python` 表示装好依赖的解释器。

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
# 全部测试（454 个；目录采集纯标准库，证明子系统需 cryptography，公告关联需 packaging+semantic_version）
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
# 全部测试（454 个；含目录采集回归，依赖缺失时对应子系统用例自动跳过）
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
# 全部测试（454 个；含目录采集与 SBOM 回归，依赖缺失时对应子系统用例自动跳过）
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

## 离线关系加工（`oci_catalog.relational`）

在文件视图之上，把镜像里的离线数据文件（按日期分区的订单 CSV、逐行
JSON 客户归属、一对多费用表）接成可查询的关系结果。交付人员提交一份
**声明式计划**（数据文件 + 字段契约 + 加工步骤），即可得到订单明细、
客户汇总等业务结果，并对任意结果行逐行追溯来源记录与贡献次数。
计划格式与完整语义见 `oci_catalog/relational/README.md`。

### 边界与确定性

* **不执行任意 Python/SQL**：过滤条件是受限表达语言（手写词法/语法
  分析 + 三值逻辑，无 `eval`、无字符串拼执行），列引用与常量类型在
  执行前全部校验；
* **只读输入**：文件字节只经文件视图 `read_file_bytes` 获取，不访问
  registry、不把镜像路径当宿主路径打开；目录库/视图库以 `mode=ro`
  打开；输出库若指向任一输入库，写入前拒绝；
* **定点十进制**：`decimal` 不经二进制浮点、不截断，`0.10+0.20=0.30`，
  存储与导出保留字面量；
* **两级失败语义**：单记录不合约进拒绝明细（带原始值/文件/记录序号/
  物理行/原因），其它记录继续；文件不存在、编码损坏、CSV 结构损坏、
  计划不合法则拒绝整次加工；
* **顺序无关**：节点先全量校验（重名、未知引用、循环依赖指出具体
  节点），再按依赖拓扑执行，打乱节点顺序结果不变；
* **连接/分组规则**：空键不彼此匹配、重复键保留全部匹配组合、左连接
  空侧补 null 且不虚构来源；NULL 自成一组，空输入产出零个分组；
* **原子落库**：整份计划的所有节点/源记录/血缘/拒绝在单事务提交，
  中途出错回滚，不可能查到只含部分节点的“成功” run。

### 血缘与可追溯

源记录保存 image digest、文件路径、记录序号与物理起始/结束行
（CSV 跨行记录的序号与物理行号分别记录）。选列/过滤保持血缘，连接
合并真实配对的两侧来源，分组只合并真正入组的行；同一源记录经一对多
连接参与多条结果时贡献次数累加。追溯按“结果节点 + 持久化结果行 ID”
返回去重、稳定排序的源记录及原始字段值，行 ID 在新进程中依然有效。

### 运行

```bash
# 全部测试（454 个；含目录采集/SBOM/文件视图回归，依赖缺失时对应子系统用例自动跳过）
python3 -I -m unittest discover -s tests -p 'test_*.py' -v

# 关系加工端到端演示（含新进程手写期待值验收）
python3 -I run_relational_demo.py

# 命令行入口
python3 -m oci_catalog.relational.relational_cli run \
    --plan plan.json --output results.db --views views.db --catalog catalog.db
python3 -m oci_catalog.relational.relational_cli --output results.db \
    trace --run 1 --node region_summary --row-id 32
python3 -m oci_catalog.relational.relational_cli --output results.db \
    export --run 1 --node region_summary > summary.csv
```

## 离线构建证明接入（`oci_catalog.provenance`）

供应商随镜像交来“这份镜像由哪个构建任务、用了哪些输入材料生成”的签名
声明（DSSE 信封 + in-toto/SLSA provenance）。交付人员把信封绑定到一个
精确的 image digest，原始证据落独立 SQLite 库；再选择一份**本地信任
策略**，得到已核验的构建者、构建任务与输入材料明细。**全程本地**：不
连接透明日志、证书服务或 registry；Ed25519 验签全部委托 `cryptography`
库（唯一第三方依赖，且只有本子系统需要），不自行实现密码算法。字段
边界、策略格式与限制的完整说明见 `oci_catalog/provenance/README.md`。

### 语义要点

* **绑定只认摘要**：声明的 subject 中必须存在 sha256 与所绑定单平台
  image digest 相同的项（可在非首项）；不按 name/tag 猜测，index 与
  未收录摘要拒绝；
* **对原始字节验签**：验签数据是 PAE（`DSSEv1` + 长度前缀），对
  base64 解码后的原始 payload 验签，绝不重序列化 JSON；信封/payload/
  策略中的重复 JSON 键带位置拒绝；base64 接受标准与 URL 安全编码；
* **策略不是信封自述**：策略登记 Ed25519 公钥与规则（唯一 ID、精确
  匹配 builder.id/buildType、授权公钥集合、正整数门槛）；规则冲突、
  未知公钥、门槛超过独立公钥数都在处理证据前报错；
* **计票按公钥字节**：同一公钥的多个别名、重复签名都只算一票；keyid
  只作提示，签名者由实际验签确定；票数只在同一信封的同一原始载荷内
  累计；坏签名/未知签名者留诊断但不阻断达到门槛的信封通过；
* **证据与可信投影分离**：结构合法但暂不被信任的证据照常保留，查询
  明确区分未达门槛/无匹配规则/签名不成立；换策略重新评价已保存的
  原始证据即可，不沿用旧通过标志；每次评价记录策略内容摘要与结论；
* **结论的限制**：`trusted` 只表示获授权密钥签过这份绑定声明，不
  证明镜像确实按声明执行过构建。

### 运行

```bash
# 全部测试（454 个；证明子系统需要 cryptography，缺失时其用例自动跳过）
.venv/bin/python -I -m unittest discover -s tests -p 'test_*.py' -v

# 构建证明端到端演示：三对测试密钥 + 换策略重评价 + 新进程手写验收
.venv/bin/python -I run_provenance_demo.py

# 命令行入口
python3 -m oci_catalog.provenance.provenance_cli import \\
    --catalog catalog.db --prov provenance.db \\
    --bind ./image-amd64.intoto.json=sha256:aaaa...
python3 -m oci_catalog.provenance.provenance_cli verify \\
    --catalog ... --prov ... --policy policy.json
python3 -m oci_catalog.provenance.provenance_cli image \\
    --catalog ... --prov ... --policy policy.json --digest sha256:...
python3 -m oci_catalog.provenance.provenance_cli material \\
    --catalog ... --prov ... --policy policy.json \\
    --uri https://mirror.example/dataset.tar.gz --sha256 <64hex>
```

## 离线公告关联（`oci_catalog.vuln`）

交付人员把安全团队下载的漏洞公告（本地 OSV 风格目录）逐条对照已导入的
SBOM 库：公告只写“从哪个版本引入、在哪个版本修好”，本作业负责加工
公告中的**受影响版本集合**并与现有安装坐标关联，为指定镜像生成逐组件
出现项的版本判定报告。**不重新导入 SBOM、不访问在线漏洞库、不做运行时
漏洞检测、不判断代码路径能否触发漏洞**；公告目录与 SBOM/目录库只读，
唯一输出是 JSON 报告。公告子集、区间语义与状态机的完整定义见
`oci_catalog/vuln/README.md`。

### 语义要点

* **版本判定**：PyPI 用 `packaging.version.Version`（PEP 440），npm 用
  `semantic_version.Version`（严格 SemVer，缺段拒绝、预发行数字段按数字
  比较、构建元数据不影响区间先后）；不转浮点、不按文本排序、不补写版本
  段；只支持 PyPI 的 `ECOSYSTEM` 与 npm 的 `SEMVER` 区间，其他生态与
  区间类型保留为无法判断；
* **events 按原列表解释**：`introduced` 含下界（`"0"` 表示从所有版本
  之前开始）、`fixed`/`limit` 排除端点、`last_affected` 包含端点、可
  再次引入、未结束区间延伸到未来；倒退/重叠/不交替/端点不可解析都定位
  文件与字段并使整次作业失败，不跳过坏公告；
* **编号等价组**：`id`+`aliases` 的无向传递闭包（允许环、允许指向无
  文件的编号），组内字典序最小编号为稳定展示名；`related` 不并组；
  撤回公告不贡献范围但别名仍作编号解释，撤回不传染同组有效公告；别名
  只合并展示，不把甲公告的范围套给乙公告的包；
* **逐出现项展示**：同一组件在两份清单中出现就是两条记录（不合并成
  一条库存）；同一漏洞的多个编号并为一组（不报成几个漏洞）；每条保留
  镜像 digest、平台、清单来源、文件内引用、原 purl 与命中依据（公告
  id、affected 下标、区间位置）；qualifiers 原样带回；
* **状态机**：`affected` / `unknown` / `not_affected_in_feed` /
  `uncovered`；缺 purl、不支持生态、缺安装版本一律 `unknown` 而非
  安全；未知与确定不命中不混用；已知命中不被其他未知声明抹掉；没有
  SBOM 的镜像单独说明（退出码 3），不给出“零漏洞”成功结论；没有
  找到命中只代表这批输入的覆盖情况，不代表镜像没有漏洞。

### 运行

```bash
# 全部测试（454 个；公告关联子系统需要 packaging 与 semantic_version，
# 缺失时其用例自动跳过）
.venv/bin/python -I -m unittest discover -s tests -p 'test_*.py' -v

# 公告关联端到端演示：两平台 SBOM + 人工公告 + 命令行报告 +
# 另一进程按别名查询 + 手写期待表验收
.venv/bin/python -I run_vuln_demo.py

# 命令行入口
python3 -m oci_catalog.vuln.vuln_cli report \\
    --catalog catalog.db --sbom sbom.db --advisories ./advisories \\
    --digest sha256:aaaa... [--output report.json]
python3 -m oci_catalog.vuln.vuln_cli advisory \\
    --catalog ... --sbom ... --advisories ... \\
    --digest sha256:aaaa... --id VULN-CCCC
```

## 设计取舍

* 存储选 SQLite 单文件 + WAL：治理场景读多写少、批处理串行提交，零外部依赖；
  写路径以 repository 为最小事务边界，与续办边界一致。
* 客户端基于标准库 `urllib`，无第三方依赖；对接真实 registry 时只需替换
  `RegistryClient` 的基址与凭据，采集/存储/查询层不变。
* 隔离是粘性状态：digest 不符意味着 registry 响应不可信，自动重试可能反复
  污染数据，因此要求人工核实后手工清除 `quarantined_repos` 行。
