# 离线公告关联（`oci_catalog.vuln`）

交付人员把安全团队下载的漏洞公告（本地 OSV 风格目录）与**已经导入的**
SBOM 库对照，为指定镜像生成逐组件出现项的版本判定报告，判定依据能查回
原公告。**全程离线**：不访问在线漏洞库、不重新导入 SBOM、不做运行时
漏洞检测、不判断代码路径能否触发漏洞。公告目录、SBOM 库、目录库都只读，
唯一输出是 JSON 报告。

## 本次接受的公告子集（固定边界）

目录下每个 `*.json` 文件是一份公告，其他文件忽略。文件按文件名字典序
处理，结果与遍历顺序无关。

### 顶层结构

| 字段 | 约束 |
|---|---|
| `id` | 必需，非空字符串，**全目录唯一**（重复即整次作业失败） |
| `aliases` | 可选，非空字符串列表；与 `id` 构成编号等价关系 |
| `related` | 可选，非空字符串列表；只是关联，**不**构成等价 |
| `withdrawn` | 可选字符串；**非空表示该条已撤回** |
| `affected` | 可选列表；每项见下 |
| 其他字段 | `summary`/`details`/`severity`/`published` 等说明性字段一律忽略 |

### affected 项

| 字段 | 约束 |
|---|---|
| `package.ecosystem` | 必需，非空字符串；仅 `PyPI`、`npm` 可确定判定 |
| `package.name` | 必需，非空字符串 |
| `versions` | 可选，非空字符串列表（允许空列表，但空列表不提供任何判定依据） |
| `ranges` | 可选列表；每项为 `{"type": ..., "events": [...]}` |

### range 项

* `type`：必需，非空字符串；`events`：必需，列表；
* **仅 `("PyPI", "ECOSYSTEM")` 与 `("npm", "SEMVER")` 是已支持区间**，
  其事件按下表严格校验，任何错误都定位文件与字段并使整次作业失败；
* 其他类型（`GIT`、生态不支持的 `SEMVER`/`ECOSYSTEM` 组合等）不校验
  事件，该声明记为**无法判断**（不是不受影响）。

### events 语义（按原列表顺序解释，绝不排序“修复”输入）

* 每项恰好一个事件键：`introduced` / `fixed` / `limit` / `last_affected`；
* 必须从 `introduced` 开始，开闭交替；
* `introduced` 开始**包含**下界的区间；字符串 `"0"` 仅在 `introduced`
  中表示从所有版本之前开始；
* `fixed` / `limit` 结束且**不包含**端点；`last_affected` 结束且
  **包含**端点；结束后可再次 `introduced`；最后一个未结束区间延伸到未来；
* 除起点的 `"0"` 外，端点必须能按该生态解析；
* 区间不能倒退或互相重叠：`last_affected` 可与本段下界相等，其余结束
  端点必须高于下界；后段可从前段**排除的**结束端点（fixed/limit）开始，
  但不能等于前段 `last_affected` 已包含的最后版本。

### 版本比较

* PyPI：`packaging.version.Version`（PEP 440，含 dev/rc/post 次序）；
* npm：`semantic_version.Version`（**严格 SemVer**，缺段写法如 `1.0`
  直接拒绝，不补写版本段；预发行数字段按数字比较、数字段低于非数字段、
  正式版高于对应预发行；构建元数据不影响区间先后——求值只使用优先级
  比较运算符）；
* 不转成浮点、不按文本排序；
* 多个合法区间与 `versions` 精确列表之间取**并集**；`versions` 按解码后
  的原版本字符串**精确匹配**——文本不同但排序相等的版本（如
  `1.4.0+build.7` 与 `1.4.0`）不视作同一个列表项。

### 编号等价组

* `id` 与 `aliases` 构成**无向**关系，取传递闭包（允许环，允许指向没有
  独立文件的编号）；组内字典序最小编号为稳定展示名；
* `related` 只是关联而非等价，不并组；
* 撤回公告的 `aliases` 仍参与并组（编号解释），但其 affected 声明
  **不参加命中**，撤回也不传染同组其他有效公告；
* 别名只用于合并同一漏洞的展示：**不**把甲公告对包 A 的范围套给乙公告
  的包 B；命中依据仍指出实际贡献的有效公告 id、affected 下标与区间位置。

### 失败语义（不跳过坏公告）

以下问题都定位**文件与字段**并使整次作业失败（退出码 2），绝不跳过坏
公告后输出貌似完整的评估：重复 JSON 键、重复 id、字段结构错误（缺
id/空 id/类型错误等）、已支持区间的事件错误（倒退、重叠、不交替、
端点不可解析、`"0"` 位置错误等）。

## 安装坐标匹配

* 生态、包名、版本都取自 SBOM 库中已归一的 **purl**：PyPI 名称按既有
  PEP 503 规则归一，npm 保留 scope（scope 小写、包名本体大小写敏感）；
* 有 qualifiers/subpath 的安装项仍按其生态与包名匹配公告，qualifiers
  随 canonical purl 与原 purl **原样带回**报告；
* **不**用组件显示名替代缺失 purl，**不**拿其他字段的版本补齐无版本
  purl。

## 出现项状态机

对每个组件出现项 × 相关公告组给出 命中/不命中/无法判断，再汇成出现项
状态：

| 状态 | 条件 |
|---|---|
| `affected` | 任一相关组有确定命中（其他未知声明不抹掉已知命中） |
| `unknown` | 无命中，但相关有效声明中存在：不支持的范围类型、无法解析的安装版本、缺少可用版本集合；或缺 purl、不支持生态、缺安装版本 |
| `not_affected_in_feed` | 所有相关声明都能判定且均不命中 |
| `uncovered` | 公告目录中根本没有该包的有效（未撤回）声明 |

* 缺 purl、不支持生态、缺安装版本**不能写成安全**（一律 `unknown`）；
* 未知与确定不命中不混用；空 `versions` 不能替代不支持的范围证明不受影响；
* 没有 SBOM 的镜像**单独说明**（退出码 3），不能给出“零漏洞”的成功结论。

## 报告结构（`vuln-correlation/v1`）

按**组件出现项**展示（同一组件在两份清单中出现就是两条记录，不合并成
一条库存；同一漏洞的多个编号经等价组合并为一个组，不报成几个不同漏
洞）。每条出现项保留：镜像 digest、平台、清单来源（`source_path` /
`file_id` / `doc_format`）、文件内引用（`file_ref`）、源位置
（`location`）、原 purl（`purl_raw`）与归一 purl（`canonical_purl`）、
安装版本、状态、逐组判定与命中依据（公告 id、affected 下标、区间位置
或 versions 下标）。报告尾部固定携带 `limitations`：没有找到命中只代表
这批输入的覆盖情况，**不代表镜像没有漏洞**。

## 命令行

```bash
# 为指定镜像生成逐组件出现项的版本判定报告
python3 -m oci_catalog.vuln.vuln_cli report \
    --catalog catalog.db --sbom sbom.db --advisories ./advisories \
    --digest sha256:aaaa... [--output report.json]

# 按任一公告编号（id 或别名）查询该镜像范围中的命中安装项与全部来源位置
python3 -m oci_catalog.vuln.vuln_cli advisory \
    --catalog catalog.db --sbom sbom.db --advisories ./advisories \
    --digest sha256:aaaa... --id VULN-CCCC
```

退出码：0 作业完成（报告可能包含命中，本工具是报告而非门禁）；2 公告
目录不合法；3 查询类错误（镜像没有 SBOM、digest 非法、公告编号未知）；
4 缺少版本判定依赖（packaging / semantic_version）。

## 依赖与运行

版本比较委托第三方库（仅此子系统需要，函数内延迟导入，其余子系统不受
影响）：

```bash
pip install packaging semantic_version
# 或本项目根目录已备好 .venv：
#   python3 -m venv .venv --without-pip
#   并把两个纯 Python wheel 解包进 .venv 的 site-packages
```

```bash
# 测试（缺依赖时本子系统用例自动跳过）
.venv/bin/python -I -m unittest discover -s tests -p 'test_*.py' -v
# 端到端演示（命令行生成报告 + 另一进程按别名查询 + 手写期待表验收）
.venv/bin/python -I run_vuln_demo.py
```

## 这些结论不能证明什么（重要限制）

* 没有找到命中只代表**这批输入**（本公告目录 × 已导入 SBOM）的覆盖
  情况，报告与本文档都不据此声称镜像没有漏洞；
* `not_affected_in_feed` 仅表示相关公告声明都能判定且安装版本均不
  命中；`uncovered` 仅表示这批公告中没有该包的有效声明；
* 本作业不检测运行时漏洞，不判断代码路径能否触发漏洞，不评估利用
  条件；命中只表示“安装版本落在公告声明的受影响集合内”。
