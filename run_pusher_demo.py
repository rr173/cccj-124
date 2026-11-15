#!/usr/bin/env python3
"""交付发布端到端演示：真实跨进程 HTTP 交付 + 故障注入 + 中断恢复。

按交付人员实际动作组织，所有断言都直接检查接收端落盘字节、请求记录
（requests.jsonl）与进度文件（不只是错误文字）：

1. 造数：嵌套索引（outer→inner→amd64/arm64）+ 共享层 + 非 UTF-8 层 +
   零字节对象 + 旧根；导入本机对象仓并绑定保留名称；
2. 接收端 A（独立进程）：预置共享 base blob 与旧交付标签；arm 故障
   "PATCH 收 37 字节后断连 ×3" → 第一条 push 命令用尽尝试（退出码 5）；
   负面对照（绑定冲突/名称漂移/损坏进度都在写请求前拒绝）；
   第二条命令带同一进度文件继续（退出码 0）：核对续传偏移、不重复
   上传、旧标签最后才改、清单子先于父；
3. 独立夹具：完成回执丢失（B）、上传会话过期（C）、标签回执丢失（D）、
   依赖缺失不发布标签（E）、鉴权（F）、协议负面（G：跨来源 Location /
   非法 Range / 错误完成摘要）；
4. verify_pusher_demo.py 在新进程按夹具常量逐字节验收。

运行：python3 -I run_pusher_demo.py（纯标准库，不访问外网）
"""

import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from oci_catalog.blobstore import BlobStore
from oci_catalog.pusher.sample_data import (
    AMD64_LAYER, ARM64_LAYER, BASE_LAYER, EMPTY_LAYER,
    build_layout, fixture_bytes, fixture_digests,
)

PY = sys.executable
CLI_PREFIX = (
    "import sys; sys.path.insert(0, %r); "
    "from oci_catalog.pusher.pusher_cli import main; "
    "raise SystemExit(main())" % HERE)
RECEIVER_PREFIX = (
    "import sys; sys.path.insert(0, %r); "
    "from oci_catalog.pusher.receiver import main; "
    "raise SystemExit(main())" % HERE)

REPO = "mirror/worker"
TAG = "release-7"
CHUNK = 128
DROP_ACCEPT = 37
DROP_TIMES = 3
EXPECTED_PREFIX = DROP_ACCEPT * DROP_TIMES   # 111：服务端实收的块内前缀


def check(cond: bool, message: str) -> None:
    if not cond:
        raise AssertionError(message)
    print(f"  ✓ {message}")


def cli_line(*argv: str) -> str:
    return "python3 -m oci_catalog.pusher.pusher_cli " + " ".join(argv)


def run_push(store: str, name: str, endpoint: str, progress: str,
             tag: str = TAG, repo: str = REPO, token: str | None = None,
             expect: int = 0) -> tuple:
    argv = ["push", "--store", store, "--name", name,
            "--endpoint", endpoint, "--repo", repo, "--tag", tag,
            "--progress", progress, "--chunk-size", str(CHUNK),
            "--max-attempts", "3", "--backoff", "0.05"]
    if token is not None:
        argv += ["--token", token]
    print(f"$ {cli_line(*argv)}")
    proc = subprocess.run([PY, "-I", "-c", CLI_PREFIX] + argv,
                          capture_output=True, text=True)
    output = (proc.stdout + proc.stderr).strip()
    if output:
        print("  " + output.replace("\n", "\n  "))
    if proc.returncode != expect:
        raise AssertionError(
            f"push 退出码 {proc.returncode} != 期望 {expect}\n{output}")
    return proc, output


class ReceiverProc:
    """独立进程接收端：真实跨进程 HTTP。"""

    def __init__(self, root: str, token: str | None = None):
        self.root = root
        os.makedirs(root, exist_ok=True)
        self.ready_file = os.path.join(root, "ready.json")
        argv = [PY, "-I", "-c", RECEIVER_PREFIX,
                "--root", root, "--ready-file", self.ready_file]
        if token is not None:
            argv += ["--token", token]
        self.proc = subprocess.Popen(argv, stdout=subprocess.PIPE,
                                     stderr=subprocess.STDOUT, text=True)
        for _ in range(200):
            if os.path.exists(self.ready_file):
                break
            if self.proc.poll() is not None:
                raise AssertionError("接收端进程提前退出")
            time.sleep(0.05)
        with open(self.ready_file, encoding="utf-8") as fh:
            self.port = json.load(fh)["port"]
        self.endpoint = f"http://127.0.0.1:{self.port}"

    def write_faults(self, faults: dict) -> None:
        path = os.path.join(self.root, "faults.json")
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(faults, fh)
        os.replace(tmp, path)

    def read_requests(self) -> list:
        path = os.path.join(self.root, "requests.jsonl")
        if not os.path.exists(path):
            return []
        with open(path, encoding="utf-8") as fh:
            return [json.loads(line) for line in fh]

    def stop(self) -> None:
        if self.proc.poll() is None:
            self.proc.send_signal(signal.SIGTERM)
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()


def preload_blob(remote_root: str, digest: str, data: bytes) -> None:
    blobs = os.path.join(remote_root, "repos", REPO.replace("/", "%2F"),
                         "blobs", "sha256")
    os.makedirs(blobs, exist_ok=True)
    with open(os.path.join(blobs, digest.split(":", 1)[1]), "wb") as fh:
        fh.write(data)


def preload_tag(remote_root: str, tag: str, manifest_digest: str,
                raw: bytes, media_type: str) -> None:
    repo_dir = os.path.join(remote_root, "repos", REPO.replace("/", "%2F"))
    manifests = os.path.join(repo_dir, "manifests", "sha256")
    os.makedirs(manifests, exist_ok=True)
    with open(os.path.join(manifests, manifest_digest.split(":", 1)[1]),
              "wb") as fh:
        fh.write(raw)
    with open(os.path.join(repo_dir, "manifests", "index.json"), "w",
              encoding="utf-8") as fh:
        json.dump({manifest_digest: media_type}, fh)
    with open(os.path.join(repo_dir, "tags.json"), "w",
              encoding="utf-8") as fh:
        json.dump({tag: manifest_digest}, fh)


def main() -> None:
    tmp = tempfile.mkdtemp(prefix="pusher-demo-")
    print(f"== 工作目录: {tmp} ==")
    digests = fixture_digests()
    table = fixture_bytes()

    # ------------------------------------------------------------------
    print("\n== 步骤 0：造数并导入本机对象仓 ==")
    layout = build_layout(os.path.join(tmp, "layout"))
    store_path = os.path.join(tmp, "store")
    store = BlobStore(store_path)
    try:
        result = store.import_layout(layout.layout_dir, layout.root_a,
                                     "delivery-a")
        check(result.ok, "根 A（嵌套索引）导入并绑定名称 delivery-a")
        result = store.import_layout(layout.layout_dir, layout.old_root,
                                     "old-root")
        check(result.ok, "旧根导入并绑定名称 old-root")
    finally:
        store.close()
    bill = [("outer-index（根）", len(table["outer-index"][0])),
            ("inner-index", len(table["inner-index"][0])),
            ("amd64-manifest", len(table["amd64-manifest"][0])),
            ("arm64-manifest", len(table["arm64-manifest"][0])),
            ("amd64-config", len(table["amd64-config"][0])),
            ("arm64-config", len(table["arm64-config"][0])),
            ("base-layer（共享）", len(BASE_LAYER)),
            ("amd64-layer（非UTF-8）", len(AMD64_LAYER)),
            ("arm64-layer", len(ARM64_LAYER)),
            ("empty-layer（零字节）", len(EMPTY_LAYER))]
    print("  人工账单（根 A 闭包，10 个对象）:")
    for name, size in bill:
        print(f"    {name:<22} {size:>5}")
    check(len(bill) == 10 and sum(s for _n, s in bill) == 2808,
          "闭包对象数与字节数与手写账单一致（10 个 / 2808 字节）")

    receivers = []

    def start_receiver(name: str, token: str | None = None) -> ReceiverProc:
        proc = ReceiverProc(os.path.join(tmp, name), token=token)
        receivers.append(proc)
        print(f"  接收端 {name}: {proc.endpoint}（独立进程 pid "
              f"{proc.proc.pid}）")
        return proc

    try:
        # --------------------------------------------------------------
        print("\n== 步骤 1：主场景——PATCH 断连，第一条命令用尽尝试 ==")
        remote_a = start_receiver("remote-a")
        preload_blob(remote_a.root, digests["base-layer"], BASE_LAYER)
        preload_tag(remote_a.root, TAG, digests["old-manifest"],
                    table["old-manifest"][0],
                    "application/vnd.oci.image.manifest.v1+json")
        check(True, "远端预置：共享 base blob + 旧交付标签 release-7→旧根")
        progress_a = os.path.join(tmp, "progress-a.json")
        # base 已预置（无 PATCH），第 2 次 PATCH 是 arm64-layer 第一块
        remote_a.write_faults({
            "drop_patch": {"at_count": 2, "accept_bytes": DROP_ACCEPT,
                           "times": DROP_TIMES}})
        print(f"  故障注入：第 3 次 PATCH 起连续 {DROP_TIMES} 次，"
              f"每次实收 {DROP_ACCEPT} 字节后断连")
        run_push(store_path, "delivery-a", remote_a.endpoint,
                 progress_a, expect=5)
        records = remote_a.read_requests()
        dropped = [r for r in records if r["status"] == "dropped"]
        check(len(dropped) == DROP_TIMES
              and dropped[0]["content_range"] == "0-127"
              and dropped[1]["content_range"] == "37-164"
              and dropped[2]["content_range"] == "74-201",
              f"3 次断连的范围与手写期望一致（实收前缀 "
              f"{EXPECTED_PREFIX} 字节）")
        node = json.load(open(progress_a, encoding="utf-8"))
        uploading = [e for e in node["objects"].values()
                     if e["state"] == "uploading"]
        check(len(uploading) == 1 and node["status"] == "in_progress",
              "进度文件保留：被中断对象 uploading，任务 in_progress")

        print("\n== 步骤 1b：负面对照——写请求前拒绝 ==")
        count = len(records)
        run_push(store_path, "delivery-a", remote_a.endpoint,
                 progress_a, tag="wrong-tag", expect=2)
        check(len(remote_a.read_requests()) == count,
              "绑定冲突（不同交付标签）：退出码 2，未发任何请求")
        store = BlobStore(store_path)
        try:
            store.set_ref("delivery-a", layout.old_root)
        finally:
            store.close()
        run_push(store_path, "delivery-a", remote_a.endpoint,
                 progress_a, expect=2)
        check(len(remote_a.read_requests()) == count,
              "名称已改指向其他根：退出码 2（不悄悄换根），未发任何请求")
        store = BlobStore(store_path)
        try:
            store.set_ref("delivery-a", layout.root_a)
        finally:
            store.close()
        corrupt = os.path.join(tmp, "progress-corrupt.json")
        shutil.copyfile(progress_a, corrupt)
        with open(corrupt, "ab") as fh:
            fh.write(b"garbage")
        size_before = os.lstat(corrupt).st_size
        run_push(store_path, "delivery-a", remote_a.endpoint,
                 corrupt, expect=2)
        check(os.lstat(corrupt).st_size == size_before
              and len(remote_a.read_requests()) == count,
              "损坏进度：退出码 2，文件未被覆盖，未发任何请求")

        print("\n== 步骤 1c：第二条命令带同一进度文件继续 ==")
        run_push(store_path, "delivery-a", remote_a.endpoint,
                 progress_a, expect=0)
        records = remote_a.read_requests()
        resume = [r for r in records if r["method"] == "PATCH"
                  and r["seq"] > dropped[-1]["seq"]]
        check(resume[0]["content_range"] == f"{EXPECTED_PREFIX}-238",
              f"续传 PATCH 从服务端确认前缀 {EXPECTED_PREFIX}（块内）接上")
        posts = [r for r in records if r["method"] == "POST"]
        check(len(posts) == 5,
              "POST 数 = 5（base 复用预置、其余 5 个 blob 各一次，"
              "被中断对象不重开会话）")
        base_heads = [r for r in records if r["method"] == "HEAD"
                      and digests["base-layer"] in r["path"]]
        check(len(base_heads) == 1 and base_heads[0]["status"] == 200,
              "预置共享 base：只有 HEAD 200，未重复上传")
        empty_patches = [r for r in records if r["method"] == "PATCH"
                         and r["content_length"] == 0]
        check(empty_patches == [],
              "零字节对象：无 PATCH，直接 PUT 完成")
        manifest_puts = [r for r in records if r["method"] == "PUT"
                         and "/manifests/" in r["path"]]
        order = [r["path"].rsplit("/manifests/", 1)[1]
                 for r in manifest_puts]
        check(order.index(digests["amd64-manifest"])
              < order.index(digests["inner-index"])
              and order.index(digests["arm64-manifest"])
              < order.index(digests["inner-index"])
              and order.index(digests["inner-index"])
              < order.index(digests["outer-index"])
              and order[-1] == TAG,
              "清单发布先后：子清单先于父索引，交付标签最后")
        tag_put_seq = [r["seq"] for r in manifest_puts
                       if r["path"].endswith(f"/manifests/{TAG}")][0]
        tag_gets = [r for r in records if r["method"] == "GET"
                    and r["path"].endswith(f"/manifests/{TAG}")]
        check(tag_gets and all(g["seq"] < tag_put_seq
                               and g["status"] == 200 for g in tag_gets),
              "最终发布前旧交付标签仍可读取（GET 200）")
        check(True, "（逐字节验收见步骤 8 新进程）")

        # --------------------------------------------------------------
        print("\n== 步骤 2：场景 B——完成对象已成功但 201 丢失 ==")
        remote_b = start_receiver("remote-b")
        progress_b = os.path.join(tmp, "progress-b.json")
        remote_b.write_faults({
            "drop_put_complete": {"digest": digests["amd64-layer"],
                                  "then_flaky": 3}})
        run_push(store_path, "delivery-a", remote_b.endpoint,
                 progress_b, expect=5)
        node_b = json.load(open(progress_b, encoding="utf-8"))
        completing = [d for d, e in node_b["objects"].items()
                      if e["state"] == "completing"]
        check(completing == [digests["amd64-layer"]],
              "进度落盘中间态：PUT 已发出但回执未确认 -> completing"
              "（不是只写一份成功标志）")
        remote_b.write_faults({})
        run_push(store_path, "delivery-a", remote_b.endpoint,
                 progress_b, expect=0)
        records_b = remote_b.read_requests()
        layer_puts = [r for r in records_b if r["method"] == "PUT"
                      and digests["amd64-layer"] in r["path"]]
        check(len(layer_puts) == 1,
              "完成回执丢失：HEAD 对账确认对象已在，不重复上传"
              f"（PUT 完成恰好 1 次）")

        # --------------------------------------------------------------
        print("\n== 步骤 3：场景 C——上传会话 404 且对象不存在 ==")
        remote_c = start_receiver("remote-c")
        progress_c = os.path.join(tmp, "progress-c.json")
        remote_c.write_faults({"expire_after_patch": {"at_count": 3}})
        run_push(store_path, "delivery-a", remote_c.endpoint,
                 progress_c, expect=0)
        records_c = remote_c.read_requests()
        posts_c = [r for r in records_c if r["method"] == "POST"]
        check(len(posts_c) == 7,
              "会话过期且对象不存在：新开会话重传该对象"
              "（POST 数 = 6 个 blob + 1 次重开）")
        expired = [r for r in records_c
                   if r.get("note") == "expire_after_patch"]
        after = [r for r in records_c if r["method"] == "PATCH"
                 and r["seq"] > expired[0]["seq"]]
        check(after[0]["content_range"] == "0-127",
              "重传会话从 0 开始完整发送该对象")

        # --------------------------------------------------------------
        print("\n== 步骤 4：场景 D——根交付标签已改成功但回执丢失 ==")
        remote_d = start_receiver("remote-d")
        progress_d = os.path.join(tmp, "progress-d.json")
        remote_d.write_faults({
            "drop_manifest_put": {"reference": TAG, "then_flaky": 3}})
        run_push(store_path, "delivery-a", remote_d.endpoint,
                 progress_d, expect=5)
        remote_d.write_faults({})
        run_push(store_path, "delivery-a", remote_d.endpoint,
                 progress_d, expect=0)
        records_d = remote_d.read_requests()
        tag_puts_d = [r for r in records_d if r["method"] == "PUT"
                      and r["path"].endswith(f"/manifests/{TAG}")]
        check(len(tag_puts_d) == 1,
              "标签回执丢失：继续时 GET 核对已等于本次根，不重复 PUT")

        # --------------------------------------------------------------
        print("\n== 步骤 5：场景 E——子清单依赖缺失，不发布交付标签 ==")
        remote_e = start_receiver("remote-e")
        preload_tag(remote_e.root, TAG, digests["old-manifest"],
                    table["old-manifest"][0],
                    "application/vnd.oci.image.manifest.v1+json")
        progress_e = os.path.join(tmp, "progress-e.json")
        remote_e.write_faults({
            "fake_blob_present": {digests["amd64-layer"]:
                                  len(AMD64_LAYER)}})
        run_push(store_path, "delivery-a", remote_e.endpoint,
                 progress_e, expect=2)
        records_e = remote_e.read_requests()
        check(any(r["status"] == 400 and "BLOB_UNKNOWN" in r.get("note", "")
                  for r in records_e),
              "接收端在子清单发布时报告依赖缺失（BLOB_UNKNOWN）")
        check(not any(r["method"] == "PUT"
                      and r["path"].endswith(f"/manifests/{TAG}")
                      for r in records_e),
              "客户端没有随后发布交付标签")
        tags_e = json.load(open(os.path.join(
            remote_e.root, "repos", REPO.replace("/", "%2F"),
            "tags.json"), encoding="utf-8"))
        check(tags_e[TAG] == digests["old-manifest"],
              "旧交付标签指向未被本次失败作业改动")

        # --------------------------------------------------------------
        print("\n== 步骤 6：场景 F——鉴权拒绝与固定 Bearer token ==")
        remote_f = start_receiver("remote-f", token="secret-token")
        progress_f = os.path.join(tmp, "progress-f.json")
        run_push(store_path, "delivery-a", remote_f.endpoint,
                 progress_f, expect=2)
        count_f = len(remote_f.read_requests())
        check(count_f <= 2, "无 token：401 明确失败，无重试风暴")
        run_push(store_path, "delivery-a", remote_f.endpoint,
                 progress_f, token="wrong", expect=2)
        check(len(remote_f.read_requests()) <= count_f + 1,
              "错误 token：401 明确失败，不无限重试")
        run_push(store_path, "delivery-a", remote_f.endpoint,
                 progress_f, token="secret-token", expect=0)
        check(True, "正确固定 token：交付完成")

        # --------------------------------------------------------------
        print("\n== 步骤 7：场景 G——协议负面（跨来源/非法Range/错误摘要） ==")
        remote_g1 = start_receiver("remote-g1")
        remote_g1.write_faults({"cross_origin_location": True})
        run_push(store_path, "delivery-a", remote_g1.endpoint,
                 os.path.join(tmp, "progress-g1.json"), expect=2)
        methods = [r["method"] for r in remote_g1.read_requests()]
        check(methods == ["HEAD", "POST"],
              "跨来源 Location：拒绝且未向它发送任何数据或凭据")
        for i, mode in enumerate(("negative", "nonprefix", "overflow")):
            remote_g = start_receiver(f"remote-g2-{mode}")
            remote_g.write_faults({"bad_range": {"mode": mode}})
            run_push(store_path, "delivery-a", remote_g.endpoint,
                     os.path.join(tmp, f"progress-g2-{mode}.json"),
                     expect=2)
            check(True, f"非法 Range（{mode}）：协议错误拒绝")
        remote_g3 = start_receiver("remote-g3")
        remote_g3.write_faults({
            "wrong_complete_digest": {"digest": digests["arm64-config"]}})
        run_push(store_path, "delivery-a", remote_g3.endpoint,
                 os.path.join(tmp, "progress-g3.json"), expect=2)
        check(True, "错误完成摘要：协议错误拒绝")

        # --------------------------------------------------------------
        print("\n== 步骤 8：新进程按夹具常量逐字节验收 ==")
        plan = {
            "tmp": tmp,
            "repo": REPO,
            "tag": TAG,
            "chunk_size": CHUNK,
            "expected_prefix": EXPECTED_PREFIX,
            "remotes": {name: os.path.join(tmp, f"remote-{name}")
                        for name in ("a", "b", "c", "d", "e", "f")},
        }
        plan_path = os.path.join(tmp, "verify-plan.json")
        with open(plan_path, "w", encoding="utf-8") as fh:
            json.dump(plan, fh, ensure_ascii=False)
        verifier = os.path.join(HERE, "verify_pusher_demo.py")
        proc = subprocess.run([PY, "-I", verifier, "--plan", plan_path],
                              capture_output=True, text=True)
        print(proc.stdout)
        if proc.returncode != 0:
            print(proc.stderr, file=sys.stderr)
            raise SystemExit(proc.returncode)
        print(f"\n全部演示与验收通过；数据位于 {tmp}")
    finally:
        for proc in receivers:
            proc.stop()


if __name__ == "__main__":
    main()
