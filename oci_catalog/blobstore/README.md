# 本机共享 OCI 原始对象仓（`oci_catalog.blobstore`）

离线机房收齐一批数据作业镜像后，多个交付批次共用大层。删掉一个交付名称
不代表它的层都能删；另一个进程可能正从旧名称指向的镜像逐层读取。本子系统
提供一个**本机共享的原始对象仓**：交付人员把本地 OCI Image Layout 纳入仓、
调整保留名称、查看可释放的实际空间并执行两阶段回收。

边界：

* 只管理**原始字节的共享存储与生命周期**；不运行镜像、不访问网络/registry、
  不合成 tar 文件树、不分析软件清单；
* 不读写目录采集库、SBOM 库、文件视图库、关系库、证明库或公告库；
* 对象仓拥有自己的字节副本，输入目录移走后仍可读取；
* 元数据用**独立 SQLite**（`store.db`），原始对象存**普通文件**（按校验过的
  digest 命名，路径绝不由描述符决定）。

## 存储布局

```
<store-root>/
├── store.db                     # 元数据（SQLite，WAL，synchronous=FULL）
├── blobs/sha256/xx/<64hex>      # 原始对象：普通文件，只按 digest 生成路径
├── staging/<import_id>/         # 导入暂存（未发布字节）
├── staging/<import_id>.lock     # 该次导入的暂存锁（导入全程 flock 持有）
├── trash/<uuid>                 # 删除中的对象（先移到此处再记结果）
├── locks/publish.lock           # 发布/回收协调锁
└── readers/<reader_id>.lock     # 读者保护锁（读者全程 flock 持有）
```

`store.db` 主要表：

| 表 | 含义 |
|---|---|
| `objects` | 唯一对象：digest 主键、真实长度、仓内相对路径 |
| `manifests` | manifest 身份：digest、mediaType、`kind=index\|image` |
| `manifest_edges` | 每份 manifest 对子对象的边（config/layer/child，含位置） |
| `closures` / `closure_objects` | 每个根 manifest 的完整闭包及其 role |
| `refs` | 保留名称 → 根 manifest（多对一；名称可替换/删除） |
| `readers` | 读者会话：固定根、pid/启动时间/boot_id、status |
| `gc_plans` / `gc_plan_objects` | 回收候选清单（计划）的冻结快照 |
| `gc_runs` / `gc_items` | 每次应用的逐项结果（deleted/already_deleted/skipped） |
| `import_failures` | 失败导入的诊断（不产生任何可见内容） |

## 接收边界

一次导入指定一个本地 layout 与**一个根 manifest 的 sha256**：

* layout 必须是 `oci-layout`（`imageLayoutVersion=1.0.0`）+ `index.json`，
  且 `index.json` 中确有该 digest 的描述符；对象只从
  `blobs/sha256/<hex>` 读取，描述符中的其它路径/`urls` 一律不采用。
* 根可以是 OCI image manifest，也可以是可递归展开的 OCI image index；
  Docker schema2/manifest list、artifact manifest 一律以
  `unsupported_manifest_type` 拒绝。
* 沿描述符走完根、子 manifest、config 与 layer 闭包。每份 manifest 的原始
  字节必须与根/描述符 digest 一致（并且文档内 `mediaType` 与描述符一致），
  config 与 layer 当**不透明字节**。
* 只接收合法 sha256（`sha256:` + 64 位小写十六进制）与非负整数 size
  （布尔不算整数）。所有对象按实际字节核对**真实长度与摘要**；逐块复制，
  不会把整个大层读入内存。
* 拒绝：缺失对象、长度不符、摘要不符、不支持的 manifest 类型、重复 JSON
  键（带 JSONPath）、同一文档/跨描述符的同摘要矛盾描述。描述符声明的
  mediaType 与文档内不一致也拒绝。
* 失败是整体的：不移动字节、不登记对象、不绑定名称；只在
  `import_failures` 留诊断。原同名引用保持原状仍可用。

### 去重与账目

磁盘占用按**唯一对象实际长度**计算，不按层出现次数累加：多个名称、多个
根、同一根里的多条边共享同一对象时只计一次。`stats()` 给出对象数与唯一
字节数；每份闭包的 `unique_bytes` 是其闭包内对象长度之和。

## 名称与读者生命周期

* `set_ref(name, root)` / `delete_ref(name)` 显式替换或删除名称。删除名称
  **不** unlink 任何对象——对象是否释放只由回收决定。
* 名称只能指向本仓已完整持有的闭包；失败导入不能让名称指到半份内容。
* `open_reader(name)` 以一个上下文固定名称**当时**指向的根：
  * 返回 `BlobReader`，其 `root` 是固定根的描述符，
    `objects()/roles()/object_digests()` 给出闭包清单；
  * `open(digest)` / `read_chunks(digest)` / `read_all(digest)` 只能读取
    固定闭包内对象；闭包外 digest 一律拒绝；
  * 直到 `close()`（或 `with` 退出）对象受保护。读者行登记 `pid`、
    `/proc/<pid>` 启动时间与 boot_id。
* 名称此后改指向或删除，已有读者仍取原字节；新读者按最新名称解析。
* 上下文关闭立即解除保护；进程被强制结束（含 SIGKILL、`os._exit`）时，
  内核释放 reader `flock`，**下一次回收**据此辨认死亡并释放保护——不要求
  人工删 pin 文件，也不靠“过了固定秒数”判断慢读者失效（活着的慢读者
  不会被时间判死）。
* 长读期间不持有全局发布锁：其他进程仍可发布无关引用、规划空间、回收
  不受保护对象。

## 两阶段回收

`plan_gc()`：

* 可达根 = 当前全部保留名称 + 全部活跃读者的固定根；沿 `manifest_edges`
  从根递归求可达对象（索引、清单、config、共享层都参与，不只保护 layer
  或只计顶层索引）。
* 候选 = 当前不可达的**完整对象**（元数据存在且字节长度正确），列出各自
  size 与唯一字节总数。未发布暂存（无 `objects` 行、暂存锁无人持有）与
  发布崩溃留下的“有字节无元数据”孤儿也计入候选。
* 计划冻结保存；生成计划不删除任何字节。
* **任何被引用/活跃读者闭包缺损时先报仓库状态异常**（`gc plan` 退出码
  2），不得把“读不到”当成“没有引用”而大面积清理。

`apply_gc(plan_id)`：

* 逐项重新检查当前引用与活跃读者：后来受到保护的候选记 `skipped` 并说明
  原因；仍无保护的继续删；某一项状态变化不影响无关候选。
* 只处理该计划里列出的对象；计划生成后新出现的对象绝不顺带删除。
* 结果如实区分 `deleted` / `already_deleted` / `skipped`；重跑同一清单
  能看到上次中断前已删的项，不宣称“整次事务从未发生”。
* 多个回收者并发处理有交集的清单：发布锁串行化，每个候选恰好被删一次，
  另一回收者如实报告已删除。

## 协调与恢复（跨 SQLite 与文件系统）

**可见性边界**：名称/闭包/对象的登记在**一个 SQLite 事务**中提交；字节在
提交前已落到最终路径。因此：

* 名称永远只能指向已提交的完整闭包；提交前崩溃不会让名称指到半份内容，
  原名称照常可用。
* 字节先移动、事务后提交时崩溃，只会留下**无 `objects` 行的孤儿文件**：
  它们不可见，会被下一次 `gc plan` 列为候选交人确认。

**锁**：

* `locks/publish.lock`（flock）串行化“字节移动 + 元数据提交”与“回收计划/
  应用”。导入的逐块复制与读者的长读**不**持有它。
* `readers/<id>.lock`（flock）由读者持有到关闭；进程退出由内核释放，
  这是死亡读者的权威判据。`pid + 启动时间 + boot_id` 只在锁文件无法探测时
  作保守回退；无法判断时保持保护。
* `staging/<import_id>.lock` 由导入全程持有。回收清理暂存前先探测它，
  所以**正在进行的导入不会被当成垃圾**。

**回收应用的落盘顺序**（单候选）：先 `rename` 字节到 `trash/` → 记
`gc_items` 结果 → 删除 `objects`/闭包元数据 → unlink `trash` 文件。中途
退出后重跑：文件已不在（但元数据在）的不可达候选记 `already_deleted` 并
清掉遗留元数据；已记结果的候选保持原结果。

**重开进程后**：`recover()` 清理 `trash/` 与无主暂存，并返回
`check_health()`；`status` 子命令报告 `ok/corrupt`。发布事务残留的孤儿
对象不自动删除，而是进入下一次回收候选。README 顶部所述三类异常退出
（导入发布前、回收删除中、读者被强杀）都有对应演示与回归用例。

**不引入**：修订流、后台队列、定时守护进程；恢复只靠上述锁语义、
SQLite 事务与显式命令。

## Python API

```python
from oci_catalog.blobstore import BlobStore
from oci_catalog.blobstore.queries import export_object, closure_manifest

with BlobStore("/srv/blobs") as store:
    result = store.import_layout("/incoming/delivery-a",
                                 "sha256:aaaa...", name="delivery-a")
    assert result.ok

    with store.open_reader("delivery-a") as reader:   # 固定根
        root = reader.root                            # 描述符
        for desc in reader.objects():
            with reader.open(desc.digest) as chunks:  # 分块，不整层入内存
                for chunk in chunks:
                    ...
    # 关闭后立即解除保护

    plan = store.plan_gc()            # 候选清单，不删除
    run = store.apply_gc(plan.plan_id)  # 逐项复核后删除
    store.set_ref("delivery-a", other_root)  # 显式替换
    store.delete_ref("delivery-a")           # 只解除引用
```

导出单个 layer 到文件（在固定读者上下文内、逐块写、写后复核摘要）：

```python
with store.open_reader("delivery-a") as reader:
    export_object(reader, layer_digest, "/out/layer.bin")
```

## 终端命令

```bash
# 导入一个 layout 的根闭包，并绑定名称
python3 -m oci_catalog.blobstore.blobstore_cli --store /srv/blobs import \
    --layout /incoming/delivery-a --root sha256:aaaa... --name delivery-a

# 名称管理
python3 -m oci_catalog.blobstore.blobstore_cli --store /srv/blobs \
    name set --name delivery-a --root sha256:bbbb...
python3 -m oci_catalog.blobstore.blobstore_cli --store /srv/blobs \
    name delete --name delivery-a
python3 -m oci_catalog.blobstore.blobstore_cli --store /srv/blobs refs
python3 -m oci_catalog.blobstore.blobstore_cli --store /srv/blobs \
    closure --root sha256:aaaa...

# 读取：在固定读者上下文中导出一个 layer 的原始字节
python3 -m oci_catalog.blobstore.blobstore_cli --store /srv/blobs export \
    --name delivery-a --digest sha256:1111... --output ./layer.bin

# 两阶段回收
python3 -m oci_catalog.blobstore.blobstore_cli --store /srv/blobs gc plan
python3 -m oci_catalog.blobstore.blobstore_cli --store /srv/blobs \
    gc apply --plan <plan_id>
python3 -m oci_catalog.blobstore.blobstore_cli --store /srv/blobs gc runs

# 状态 / 账目 / 恢复
python3 -m oci_catalog.blobstore.blobstore_cli --store /srv/blobs status
python3 -m oci_catalog.blobstore.blobstore_cli --store /srv/blobs stats
python3 -m oci_catalog.blobstore.blobstore_cli --store /srv/blobs recover
```

退出码：`0` 成功；`2` 导入失败/仓库状态异常/读取或导出错误；`3` 名称或
路径类操作错误；`4` 计划不存在。

## 可复建示例

`oci_catalog/blobstore/sample_data.py` 用代码生成一份**真实字节**的 OCI Image
Layout：两层嵌套 index → linux/amd64 与 linux/arm64 两个镜像；两个平台共享
base 层、各有独有层；另有两个 image manifest 根（B 复用 base，C/D 为纯垃圾），
`index.json` 登记全部根。amd64 独有层含 `0x00-0xff` 全字节，用于非 UTF-8
逐字节核对。

```bash
python3 -I run_blobstore_demo.py
```

演示按一次真实腾盘操作组织，并打印人工账单：

| 根 | 对象数 | 唯一字节 |
|---|---|---|
| A（嵌套索引，两平台） | 10 | 3120 |
| B（复用 base） | 4 | 851 |
| C（垃圾） | 3 | 547 |
| D（垃圾） | 3 | 541 |
| 全仓并集（base 只算一次） | 19 | 4939 |

步骤：导入 → 移走输入目录 → 新进程 CLI 导出非 UTF-8 layer 并逐字节核对 →
读者固定在旧引用并暂停 → 管理进程替换/删除名称、生成并应用回收（无关垃圾
消失、旧读者仍取全内容）→ 释放读者再回收（仅旧闭包独有对象消失、共享
对象保留）→ 进程屏障（计划后新引用整条跳过、其他候选照删）→ 计划后新导入
对象不在旧计划范围 → 活着的慢读者 / 被强杀读者 → 两个回收者处理有交集
清单 → 导入发布前 / 回收删除中异常退出 → 缺对象/坏长度/坏摘要导入与缺损
闭包回收的非零退出。最后 `verify_blobstore_demo.py` 在**新进程**中按手写
常量表核对集合与字节数（不调用正式可达性函数）。

## 回归

```bash
python3 -I -m unittest discover -s tests -p 'test_blobstore_*.py' -v
# 全部回归
python3 -I -m unittest discover -s tests -p 'test_*.py'
```

对象仓子系统为纯标准库，与其他子系统无依赖关系。
