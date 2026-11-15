# OCI 镜像交付发布器（`oci_catalog.pusher`）

执行节点要从机房镜像服务拉取下一批作业，交付人员手里只有本机对象仓
中的保留名称。本子系统把这个名称选中的镜像**真正送到远端仓库**：
从 `oci_catalog.blobstore` 的固定读者上下文取原字节，经受支持的
OCI Distribution 子集推送到目标服务，最后更新交付标签。命令可中断
后继续：运维人员第二次带上同一进度文件就能继续上次工作。

边界：

* **只读使用本机对象仓**（`open_reader` 固定根 + 分块读取）；不读写
  目录库、SBOM 库、文件视图库、关系加工库、证明库或公告库，也不
  扩展它们的查询/加工能力；
* 配置与层文件**保持原样**：不解包、不重压缩；清单以原字节 PUT，
  不重新序列化；
* 只处理选定闭包；失败时远端可能留下尚无交付标签引用的完整 blob
  或清单，本组件**不**尝试跨 HTTP 请求的整体回滚；
* 按单个交付命令串行使用一份进度文件，不要求多控制器竞争。

## 命令行

```bash
python3 -m oci_catalog.pusher.pusher_cli push \
    --store /srv/blobs --name delivery-a \
    --endpoint http://127.0.0.1:5000 --repo mirror/worker \
    --tag release-7 --progress ./progress.json \
    [--token TOKEN] [--chunk-size 1048576] [--max-attempts 3] \
    [--timeout 10] [--backoff 0.2]
```

六个必需参数：源仓位置、保留名称、目标服务地址、仓库路径、交付
标签、进度文件路径。**同一条命令带同一进度文件再次执行即可继续**。

退出码（三种结局可区分）：

| 退出码 | 含义 | 处置 |
|---|---|---|
| `0` | 交付完成：标签已确认指向本次根 | 无需处置 |
| `5` | 待继续：可重试故障额度用尽，进度已保存 | 带同一进度文件重跑同一命令 |
| `2` | 不可继续：源问题/进度损坏或绑定冲突/协议错误/鉴权拒绝 | 人工处置后重跑 |

## Python 接口

```python
from oci_catalog.pusher import PushConfig, push
from oci_catalog.pusher import RetryExhausted, SourceProblem, ProtocolProblem

config = PushConfig(
    store_path="/srv/blobs", name="delivery-a",
    endpoint="http://127.0.0.1:5000", repo="mirror/worker",
    tag="release-7", progress_path="./progress.json",
    token="...", chunk_size=1 << 20, max_attempts=3)
try:
    result = push(config)          # result.status == "completed"
except RetryExhausted:
    ...                            # 待继续：带同一进度文件重跑
except (SourceProblem, ProtocolProblem):
    ...                            # 不可继续：人工处置
```

## 受支持的 HTTP 子集

所有对象摘要为 sha256。范围外扩展（跨仓挂载、并行块、重定向、
token 协商）不实现；鉴权用调用者提供的固定 Bearer token，401/403
明确失败、不无限重试。

| 请求 | 成功 | 说明 |
|---|---|---|
| `HEAD /v2/<name>/blobs/<digest>` | 200（长度 + `Docker-Content-Digest`）/ 404 | 长度或摘要矛盾报错 |
| `POST /v2/<name>/blobs/uploads/` | 202 + `Location` | 创建空上传 |
| `PATCH <location>` | 202 + 新 `Location` + `Range: 0-<end>` | 带 `Content-Length`、`Content-Type: application/octet-stream`、`Content-Range: <start>-<end>`（含两端）；错位块 416 + 当前 `Range`/`Location` |
| `GET <location>` | 204 + 前缀 `Range`（空上传无 Range）/ 404 | 404 表示会话过期 |
| `PUT <location>?digest=<digest>`（空请求体） | 201 + `Docker-Content-Digest` | 完成对象；允许零字节 blob |
| `PUT /v2/<name>/manifests/<reference>` | 201 + `Docker-Content-Digest` | 原内容类型 + 原字节；接收端拒绝缺少直接依赖的清单 |
| `GET /v2/<name>/manifests/<reference>` | 200 原字节 + 摘要 / 404 | 检查已完成状态、消解发布回执丢失 |

协议纪律：

* **Location** 可为相对地址、可每次变化、可自带查询参数；客户端
  解析后完整保留，并限制在与配置端点**同一来源**——跨来源 Location
  一律拒绝，绝不向它发送数据或凭据；
* **Range** 必须是 `0-<end>` 前缀且 `end+1 <= 对象大小`；负数、非
  前缀、越过本对象大小都是不可能状态，一律拒绝；
* 网络异常与可重试 5xx 有**有限尝试额度与超时**（`--max-attempts`、
  `--timeout`、`--backoff`）；额度统计连续未获确认的写尝试（对账
  读成功不清零，写步骤被完整确认才清零），用尽即保留进度、以
  退出码 5 结束。

## 进度与源保护的有效期

进度文件绑定六元组：``(源仓, 保留名称, 精确根, 目标端点, 仓库路径,
交付标签)``。继续时任何一项与命令行参数冲突，都在**发送任何写请求
之前**拒绝。进度文件损坏（非法 JSON、格式标识不符、结构缺字段、
对象集合与固定闭包不一致）同样拒绝——不覆盖、不新建、不当作新任务。

**进度落盘与远端接受不是一个事务。** 进度中的 `confirmed` 只记录
已被服务端响应确认的字节前缀（保守下界）；每个写请求**发出前**
先把状态机推进到中间态（`uploading`/`completing`/`publishing`）
落盘。进程在"请求已发出但本地尚未确认"之间死亡时，恢复逻辑向
服务端对账而不是相信本地记录：

* blob：先 `HEAD` 对象（上次 PUT 可能已成功），再 `GET` 上传会话，
  以**服务端实际确认的前缀**继续——合法前缀即使落在上次块内部，
  也从它后面接上，不重复拼入前缀、不跳掉剩余字节；
* 会话过期（GET 404）且对象不存在：新开会话重新发送这个对象；
* 完成请求的响应丢失、会话也找不到：先查目标对象是否已存在，
  不直接判失败、不反复重传已完成对象；
* manifest/tag：PUT 回执丢失时 `GET` 读回核对，内容已一致即完成；
  交付标签写入后连接中断，再次继续时先核对它是否已经等于本次根。

**源保护的有效期**：进程间隔不承诺替用户永久保留本地对象。一次
运行内，`open_reader` 固定最初选中的根（本机名称中途被更新不会
让本次交付混入另一份镜像）；跨进程恢复时，源名称不再指向进度
绑定的根、或所需字节已不可读（被回收），都明确拒绝——不悄悄换用
新根。已有读者上下文与正常完整源可直接利用，不要求修复历史回收
功能。

## 交付顺序与标签安全

1. blob（config/layer，不透明原字节）逐个交付：`HEAD` 复用已有
   远端对象 → 上传会话分块 `PATCH` → `PUT` 完成。共享对象按
   digest 只向同一目标仓库交付一次；
2. blob 全部就绪后按依赖发布清单：子清单先于引用它的父索引
   （支持嵌套索引），`PUT /v2/<name>/manifests/<digest>` 用原内容
   类型和原字节；接收端拒绝缺少直接依赖的清单；
3. 全部清单就绪后，才把根原字节 `PUT` 到交付标签。**此前任何层
   或子清单失败，交付标签原有指向都不被本次作业改动**；
4. 对清单与完成请求的 201 摘要都核对 `Docker-Content-Digest`。

## 有界性

大层读取（`read_chunks` 分块）、HTTP 发送（`PATCH` 按
`--chunk-size` 分块）、恢复定位（按偏移跳读，不整层入内存）均有
上界；进度文件只记录摘要、偏移与状态，对象字节绝不编码进进度。

## 接收端（演示/测试用）

`oci_catalog.pusher.receiver` 是真实 HTTP 接收端：监听本地 HTTP，
把收到的字节、请求范围与清单发布顺序落盘（`requests.jsonl`），
上传会话持久化（重启不失），并支持控制文件故障注入（断连、回执
丢失、会话过期、非法 Range、跨来源 Location、错误摘要、500 等）。
演示与测试用它与发布器做真实跨进程网络交互，不 mock 客户端函数。

```bash
python3 -m oci_catalog.pusher.receiver --root /tmp/remote \
    --ready-file /tmp/ready.json [--token TOKEN]
```

## 演示与回归

```bash
# 端到端演示：真实跨进程交付 + 故障注入 + 中断恢复 + 新进程逐字节验收
python3 -I run_pusher_demo.py

# 发布子系统回归（纯标准库）
python3 -I -m unittest discover -s tests -p 'test_pusher_*.py' -v

# 全部回归（含既有子系统）
python3 -I -m unittest discover -s tests -p 'test_*.py'
```
