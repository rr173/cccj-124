# 离线构建证明接入（`oci_catalog.provenance`）

交付人员把供应商随镜像交来的 DSSE 信封绑定到一个精确的 image digest，
保留原始证据；再选择一份本地信任策略，得到已核验的构建者、构建任务与
输入材料明细。**全程本地**：不连接透明日志、证书服务或 registry；
Ed25519 验签全部委托 `cryptography` 库，本项目不自行实现密码算法。

## 支持的声明范围（明确边界，不声称兼容所有证明格式）

### DSSE 信封

* 顶层 JSON 对象：`payloadType`、`payload`（base64）、`signatures` 列表；
  列表元素为对象，含可选 `keyid` 与必需 `sig`（base64）；
* `payloadType` 必须为 `application/vnd.in-toto+json`；
* base64 接受**标准与 URL 安全**字母表，要求正确填充（`=` 至多两个且
  仅在末尾）；非法字符、错误填充、长度不合法都明确拒绝；
* 信封、payload、策略中的**重复 JSON 键一律拒绝**（带 JSONPath 定位），
  不用后值悄悄覆盖；
* `signatures` 为空列表视为结构不完整；
* 验签数据为 PAE（Pre-Authentication Encoding）：

  ```
  DSSEv1 <len(payloadType)> <payloadType> <len(payload)> <payload>
  ```

  `DSSEv1` 为 ASCII 字节，分隔符为单个空格；两个长度都是**无前导零的
  十进制 ASCII**，分别按 payloadType 的 UTF-8 字节数与 payload 原始
  字节数计算。对 base64 解码后的**原始 payload 字节**验签，绝不把
  JSON 重新序列化后验签（改一个空白都会使签名不成立）。

### in-toto Statement v1 / SLSA Provenance v1 payload

| 字段 | 约束 |
|---|---|
| `_type` | 必须等于 `https://in-toto.io/Statement/v1` |
| `predicateType` | 必须等于 `https://slsa.dev/provenance/v1` |
| `subject` | 非空对象列表；每项有 `name`（字符串）与 `digest` 映射；只读取其中的 `sha256`（64 位十六进制，统一存小写），其余算法忽略 |
| `predicate.buildDefinition.buildType` | 必需，非空字符串 |
| `predicate.buildDefinition.resolvedDependencies` | 必需，列表；每项有非空 `uri` 与含合法 `sha256` 的 `digest` 映射 |
| `predicate.runDetails.builder.id` | 必需，非空字符串 |
| `predicate.runDetails.metadata.invocationId` | 可选字符串，保留为构建任务标识 |

语义边界：

* **绑定只认摘要**：必须存在 `sha256` 与所绑定 image digest 相同的
  subject 项；不按 `name`/tag 猜测绑定；多 subject 时精确绑定命中项
  （可以在非首项），命中位置随证据保留；
* 材料**保留原列表位置**：同 URI 不同摘要是不同材料；完全重复的材料
  两处出现都登记，不丢证据；
* 构建者、构建类型、材料字符串**按原值处理**：不做大小写/空白归一，
  不从相似名称推断等价；
* 只登记**直接输入**材料；某材料恰好也是另一个镜像时，不自动拼接成
  递归依赖图。

## 信任策略（本地提供，不是信封里的自述）

```json
{
  "keys": {
    "key-a": "d6f021da6db21e8b3533f9b447211180744d3e28cfcd7a3f836f0c75c8698fa4",
    "key-b": "a4840f17322098d4e4d07d434c1e14281aa706c219ae01c6e98217c2a5137041"
  },
  "rules": [
    {
      "id": "etl-provenance",
      "builder_id": "https://builder.example.com/offline-etl",
      "build_type": "https://buildtypes.example.com/offline-etl/v1",
      "authorized_keys": ["key-a", "key-b"],
      "threshold": 2
    }
  ]
}
```

* 公钥写法：64 位十六进制，或 base64（标准/URL 安全）的 32 字节
  Ed25519 公钥；公钥身份是**公钥字节本身**，指纹 = 原始 32 字节的
  sha256；
* 每条规则有唯一 `id`、精确匹配的 `builder_id` 与 `build_type`、一组
  被授权的公钥名和正整数门槛 `threshold`；
* 以下问题在**处理任何证据之前**报错（退出码 4）：重复 JSON 键、规则
  ID 重复、两条规则命中同一 `(builder_id, build_type)`（规则冲突）、
  规则引用未登记的公钥名、门槛非正整数、门槛超过授权集合的**独立
  公钥数**；
* 策略内容摘要对规范化 JSON（键排序、紧凑分隔符、UTF-8）计算：同一
  套规则不因排版差异得到不同摘要。

## 评价语义

* 每次评价都从库中取出原始证据（payload 原字节、签名原字节），用
  **当前给出的策略**即时验签与计票；不沿用任何旧策略的通过标志。
  重新打开进程、换一份策略即可重新评价，无需再提供供应商文件；
* 签名者身份由**实际验签**决定：逐个尝试策略登记的公钥；`keyid` 只作
  提示——把有效签名的 keyid 改成另一名字不能冒认签名者；
* 同一公钥登记两个名字（别名）、同一公钥的重复签名，都只算**一票**；
* 票数只在**同一信封的同一原始载荷**内累计：两份内容相同但各只有
  一票的信封不能拼起来凑门槛（它们是不同的证据行，各自评价）；
* 无效签名（keyid 指向已登记公钥但验不出）与未知签名者（任何已登记
  公钥都验不出）各自留下诊断，但不阻断：同一份信封达到所需独立授权
  公钥数时仍判可信；
* 每次评价（无论结论）追加到 `evaluations` 表：策略内容摘要 + 结论 +
  计入指纹 + 逐签名报告，便于说明某次结论依据哪套规则。

结论与原因：

| verdict | reason | 含义 |
|---|---|---|
| `trusted` | `threshold_met` | 命中规则且独立授权公钥数达到门槛 |
| `untrusted` | `no_matching_rule` | 策略中没有命中 (builder, buildType) 的规则 |
| `untrusted` | `no_valid_signatures` | 没有任何签名能用已登记公钥验出 |
| `untrusted` | `threshold_not_met` | 有有效签名但计入门槛的独立授权公钥数不足 |

## 证据保存与可信投影分离

* 导入时登记：信封原字节及其 sha256、payload 原字节及其 sha256、绑定
  镜像、全部 subject（含命中标记）、材料出现位置、签名（keyid + 原
  字节）；
* 结构坏、绑定不成立的文件给出**具体位置**的诊断（信封内 `$...`，
  payload 内 `payload:$...`），只留在 `import_failures`，不可能被查成
  完整构建来源；
* 一份签名正确但尚不被当前策略信任的结构合法证据**仍需保留**，查询时
  明确是未达门槛、无匹配规则或签名不成立，不与可信来源混为一谈；
* 证据身份 = （信封字节 sha256, 绑定镜像 digest)：重复导入相同信封与
  绑定复用证据身份（`duplicate_skipped`），换本地文件名不多算证明；
  同一 payload 不同签名组合是不同信封；同一信封绑定不同镜像是不同
  证据行；
* 数据在**独立 SQLite 库**；目录库只读（校验绑定、带出平台上下文），
  SBOM/文件视图/关系库完全不接触。

## 两类查询

| 函数 / 子命令 | 行为 |
|---|---|
| `query_image_provenance` / `image --digest` | 按镜像列出每份构建证明：绑定命中的 subject 位置、构建者、构建类型、任务标识、材料原位置、实际验证出的公钥指纹、计入门槛的签名与整体原因 |
| `query_material_images` / `material --uri --sha256` | 按材料 URI 与 sha256 **精确**反查在当前策略下具有可信证明的镜像，带回证据身份与构建任务；未通过证明的材料不混入 |

同一镜像存在相互不同的合法声明时**逐份展示**，不擅自认定最后导入的
一份是真实历史。

## 命令行

```bash
python3 -m oci_catalog.provenance.provenance_cli import \\
    --catalog catalog.db --prov provenance.db \\
    --bind ./image-amd64.intoto.json=sha256:aaaa... \\
    --bind ./image-arm64.intoto.json=sha256:bbbb...
python3 -m oci_catalog.provenance.provenance_cli verify \\
    --catalog ... --prov ... --policy policy.json [--image sha256:...]
python3 -m oci_catalog.provenance.provenance_cli image \\
    --catalog ... --prov ... --policy policy.json --digest sha256:...
python3 -m oci_catalog.provenance.provenance_cli material \\
    --catalog ... --prov ... --policy policy.json \\
    --uri https://mirror.example/dataset.tar.gz --sha256 <64hex>
python3 -m oci_catalog.provenance.provenance_cli evaluations --catalog ... --prov ...
python3 -m oci_catalog.provenance.provenance_cli failures    --catalog ... --prov ...
```

退出码：0 正常；2 导入存在失败文件；3 查询错误；4 策略不合法（未处理
任何证据）。

## 这些结论不能证明什么（重要限制）

* `trusted` 只表示**获授权的密钥签过这份绑定声明**，不证明镜像确实
  按声明执行过构建；签名密钥本身可能被盗用，声明内容可能不实；
* 材料命中只说明声明里登记了该输入材料，不说明构建过程真的使用了它；
* 本子系统不做密钥在线轮换、不做后台消费、不处理修订号竞争；策略
  变更通过换策略文件重新评价生效，历史结论按策略摘要留痕。
