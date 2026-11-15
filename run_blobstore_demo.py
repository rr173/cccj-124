#!/usr/bin/env python3
"""OCI 原始对象仓端到端演示：一次真实腾盘操作 + 并发/崩溃恢复。

按交付人员实际动作组织，所有断言都直接检查磁盘对象、SQLite 记录与
进程行为（不只是错误文字）：

1. 用代码生成真实字节的 OCI Image Layout（嵌套索引、两个平台、共享层、
   各自独有层、两个未命名垃圾闭包），先打印手写的根闭包与字节账单；
2. 导入两个名称闭包 + 两个垃圾闭包，统计唯一对象与物理字节；
3. **移走输入目录**，再从新进程用 CLI 导出含非 UTF-8 字节的 layer 并
   逐字节核对；
4. 让读者固定在旧引用上、暂停在读取第二个 layer 之前；管理进程替换并
   删除名称、生成并应用回收计划：读者仍能取全内容，无关垃圾消失；
5. 读者释放后再次回收：仅旧闭包独有对象消失，共享层保留；
6. 进程屏障：生成计划 -> 给部分候选新建保留引用 -> 应用旧计划；
   再演示计划生成后新导入的对象不在旧计划删除范围；
7. 活着但慢的读者、被强制结束的读者、两个回收者并发处理有交集的清单；
8. 导入发布前异常退出、回收删除中异常退出；
9. 缺对象、坏长度、坏摘要的导入与已有闭包缺损的回收以非零退出；
10. 新进程按手写期待值验收（集合与字节数来自人工常量表）。

运行：python3 -I run_blobstore_demo.py（纯标准库，不访问网络）
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from oci_catalog.blobstore import BlobStore
from oci_catalog.blobstore.sample_data import (
    AMD64_L2,
    BASE_LAYER,
    build_layout,
)

PY = sys.executable
CLI_PREFIX = (
    "import sys; sys.path.insert(0, %r); "
    "from oci_catalog.blobstore.blobstore_cli import main; "
    "raise SystemExit(main())" % HERE)


# ---------------------------------------------------------------------------
# 手写的期待账单（与 sample_data 的派生结果无关）
# ---------------------------------------------------------------------------
ROOT_BILL = {
    "A": [("index-outer", 237), ("index-inner", 491),
          ("manifest-amd64", 708), ("manifest-arm64", 554),
          ("config-amd64", 78), ("config-arm64", 78),
          ("base", 120), ("amd64-l2", 272), ("amd64-l3", 316),
          ("arm64-l2", 266)],
    "B": [("manifest-repack", 553), ("config-repack", 97),
          ("base", 120), ("repack-l2", 81)],
    "C": [("manifest-garbage", 399), ("config-garbage", 98),
          ("garbage-l2", 50)],
    "D": [("manifest-garbage2", 399), ("config-garbage2", 99),
          ("garbage2-l2", 43)],
}
A_BYTES = 3120
B_BYTES = 851
C_BYTES = 547
D_BYTES = 541
ALL_UNIQUE_BYTES = 4939      # A ∪ B ∪ C ∪ D（base 只算一次）
ALL_UNIQUE_OBJECTS = 19


def check(cond: bool, message: str) -> None:
    if not cond:
        raise AssertionError(message)
    print(f"  ✓ {message}")


def run_cli(store: str, *argv: str, expect: int = 0) -> str:
    proc = subprocess.run(
        [PY, "-I", "-c", CLI_PREFIX, "--store", store] + list(argv),
        capture_output=True, text=True)
    if proc.returncode != expect:
        raise AssertionError(
            f"CLI {argv} 退出码 {proc.returncode} != {expect}\n"
            f"stdout={proc.stdout}\nstderr={proc.stderr}")
    return proc.stdout


def run_py(code: str, *args: str, expect: int = 0) -> subprocess.CompletedProcess:
    proc = subprocess.run([PY, "-I", "-c", code] + list(args),
                          capture_output=True)
    if proc.returncode != expect:
        raise AssertionError(
            f"子进程退出码 {proc.returncode} != {expect}\n"
            f"stdout={proc.stdout!r}\nstderr={proc.stderr!r}")
    return proc


def cli_line(store: str, *argv: str) -> str:
    return "python3 -m oci_catalog.blobstore.blobstore_cli --store " + \
        store + " " + " ".join(argv)


def import_cli(store: str, layout: str, root: str,
               name: str | None, expect: int = 0) -> dict:
    argv = ["import", "--layout", layout, "--root", root]
    if name:
        argv += ["--name", name]
    print(f"$ {cli_line(store, *argv)}")
    return json.loads(run_cli(store, *argv, expect=expect))


def gc_apply(store: str, plan_id: str) -> dict:
    argv = ["gc", "apply", "--plan", plan_id]
    print(f"$ {cli_line(store, *argv)}")
    return json.loads(run_cli(store, *argv))


def gc_plan(store: str) -> dict:
    argv = ["gc", "plan"]
    print(f"$ {cli_line(store, *argv)}")
    return json.loads(run_cli(store, *argv))


def reader_process(store: str, name: str, first_layer: str,
                   second_layer: str, pause: float = 1.5):
    """新进程读者：读完第一层后打印 READY，暂停，再读第二层。"""
    code = '''
import sys, time
sys.path.insert(0, %r)
from oci_catalog.blobstore import BlobStore
store = BlobStore(sys.argv[1])
reader = store.open_reader(sys.argv[2])
import hashlib
first = b"".join(reader.read_chunks(sys.argv[3], 16))
second_iter = reader.read_chunks(sys.argv[4], 16)
print("READY", flush=True)
time.sleep(float(sys.argv[5]))
rest = b"".join(second_iter)
import sys as _sys
_sys.stdout.buffer.write(b"DATA:" + rest)
_sys.stdout.buffer.flush()
reader.close()
store.close()
''' % HERE
    return subprocess.Popen(
        [PY, "-I", "-c", code, store, name, first_layer, second_layer,
         str(pause)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def build_fixture(tmp: str) -> dict:
    print("\n== 步骤 0：生成真实字节布局并列出人工账单 ==")
    layout_dir = os.path.join(tmp, "incoming-delivery")
    info = build_layout(layout_dir)
    print("$ python3 -c 'build_layout(...)'")
    all_sizes = {}
    for root_key in ("A", "B", "C", "D"):
        bill = ROOT_BILL[root_key]
        total = sum(size for _name, size in bill)
        print(f"  根 {root_key}: {len(bill)} 个对象, 唯一字节 {total}")
        for name, size in bill:
            print(f"    {name:<18} {size:>5}")
        all_sizes[root_key] = total
    check(all_sizes == {"A": A_BYTES, "B": B_BYTES, "C": C_BYTES,
                        "D": D_BYTES},
          "四个根的闭包对象数与字节数与手写账单一致")
    check(A_BYTES + B_BYTES + C_BYTES + D_BYTES - len(BASE_LAYER)
          == ALL_UNIQUE_BYTES,
          f"共享 base 只计一次：全仓唯一物理字节 {ALL_UNIQUE_BYTES}")
    return {"layout": layout_dir, "info": info}


def main() -> None:
    tmp = tempfile.mkdtemp(prefix="blobstore-demo-")
    print(f"== 工作目录: {tmp} ==")
    fixture = build_fixture(tmp)
    layout_dir = fixture["layout"]
    info = fixture["info"]
    names = info.names
    roots = info.roots
    result: dict = {"tmp": tmp, "layout": layout_dir,
                    "names": names, "roots": roots}

    # ------------------------------------------------------------------
    # 步骤 1：导入两个名称闭包 + 两个垃圾闭包
    # ------------------------------------------------------------------
    print("\n== 步骤 1：导入闭包，按唯一对象计账 ==")
    main_store = os.path.join(tmp, "main-store")
    payload_a = import_cli(main_store, layout_dir, roots["A"], "delivery-a")
    check(payload_a["status"] == "imported"
          and payload_a["objects_added"] == 10
          and payload_a["bytes_added"] == A_BYTES,
          f"根 A 导入：10 个对象 / {A_BYTES} 字节")
    payload_b = import_cli(main_store, layout_dir, roots["B"], "delivery-b")
    check(payload_b["objects_added"] == 3
          and payload_b["objects_existing"] == 1
          and payload_b["bytes_added"] == B_BYTES - len(BASE_LAYER),
          "根 B 导入：共享 base 复用，只新增 3 个对象")
    import_cli(main_store, layout_dir, roots["C"], None)
    import_cli(main_store, layout_dir, roots["D"], None)
    stats = json.loads(run_cli(main_store, "stats"))
    print(f"$ {cli_line(main_store, 'stats')} -> {stats}")
    check(stats["object_count"] == ALL_UNIQUE_OBJECTS
          and stats["unique_bytes"] == ALL_UNIQUE_BYTES,
          f"仓内共 {ALL_UNIQUE_OBJECTS} 个唯一对象 / "
          f"{ALL_UNIQUE_BYTES} 物理字节")

    # ------------------------------------------------------------------
    # 步骤 2：移走输入目录，新进程导出非 UTF-8 层并逐字节核对
    # ------------------------------------------------------------------
    print("\n== 步骤 2：输入目录移走后仍可读取（对象仓自有字节副本） ==")
    moved = os.path.join(tmp, "input-moved-away")
    os.rename(layout_dir, moved)
    check(not os.path.exists(layout_dir), "原输入 layout 目录已移走")
    output = os.path.join(tmp, "amd64-l2.exported")
    argv = ["export", "--name", "delivery-a",
            "--digest", names["amd64-l2"], "--output", output]
    print(f"$ {cli_line(main_store, *argv)}")
    exported = json.loads(run_cli(main_store, *argv))
    with open(output, "rb") as fh:
        data = fh.read()
    check(data == AMD64_L2,
          f"新进程导出 layer 与人工字节表逐字节一致（{len(data)} 字节，"
          f"含 0x00-0xff 全字节）")
    check(exported["sha256"] == names["amd64-l2"],
          "导出结果摘要等于 layer digest")

    # ------------------------------------------------------------------
    # 步骤 3：读者固定旧引用，管理进程替换/删除名称并回收
    # ------------------------------------------------------------------
    print("\n== 步骤 3：旧读者受保护，同时回收无关垃圾 ==")
    proc = reader_process(main_store, "delivery-a", names["base"],
                          names["amd64-l2"], pause=2.0)
    ready = proc.stdout.readline()
    check(ready == b"READY\n", "读者已固定旧根并暂停在读取第二个 layer 之前")
    print("$ python3 -m ... name set --name delivery-a --root <B>")
    print(run_cli(main_store, "name", "set", "--name", "delivery-a",
                  "--root", roots["B"]).strip())
    print("$ python3 -m ... name delete --name delivery-a")
    print(run_cli(main_store, "name", "delete", "--name", "delivery-a").strip())
    plan = gc_plan(main_store)
    check(plan["object_count"] == 6
          and plan["unique_bytes"] == C_BYTES + D_BYTES,
          f"计划列出 {plan['object_count']} 个无引用对象 / "
          f"{plan['unique_bytes']} 字节（C+D）")
    run = gc_apply(main_store, plan["plan_id"])
    check(run["summary"]["deleted"] == 6 and run["freed_bytes"] == 1088,
          "旧读者保护下的 A 闭包不在候选内，C/D 垃圾实际删除")
    for key, digest in (("garbage-l2", names["garbage-l2"]),
                        ("garbage2-l2", names["garbage2-l2"])):
        path = os.path.join(main_store, "blobs", "sha256",
                            digest.split(":", 1)[1][:2],
                            digest.split(":", 1)[1])
        check(not os.path.exists(path), f"垃圾层 {key} 的字节文件已消失")
    check(os.path.exists(os.path.join(
        main_store, "blobs", "sha256",
        names["amd64-l2"].split(":", 1)[1][:2],
        names["amd64-l2"].split(":", 1)[1])),
        "被旧读者保护的 amd64-l2 字节仍在")
    out = proc.stdout.read()
    proc.wait(timeout=30)
    check(proc.returncode == 0 and out.startswith(b"DATA:"),
          "旧读者在名称替换+删除、GC 之后仍取全第二个 layer")
    check(out[5:] == AMD64_L2[16:] or out[5:] == AMD64_L2,
          "旧读者取到的剩余字节与原始 layer 一致")

    # ------------------------------------------------------------------
    # 步骤 4：读者释放后再回收，只删旧闭包独有对象
    # ------------------------------------------------------------------
    print("\n== 步骤 4：释放读者后回收旧闭包，共享对象保留 ==")
    plan2 = gc_plan(main_store)
    check(plan2["object_count"] == 9 and plan2["unique_bytes"] == 3000,
          "计划仅列旧闭包独有的 9 个对象 / 3000 字节")
    run2 = gc_apply(main_store, plan2["plan_id"])
    check(run2["freed_bytes"] == 3000, "旧闭包独有字节实际释放")
    base_path = os.path.join(main_store, "blobs", "sha256",
                             names["base"].split(":", 1)[1][:2],
                             names["base"].split(":", 1)[1])
    check(os.path.exists(base_path), "与 delivery-b 共享的 base 层保留")
    final_stats = json.loads(run_cli(main_store, "stats"))
    check(final_stats["object_count"] == 4
          and final_stats["unique_bytes"] == B_BYTES,
          "回收后仅剩 delivery-b 闭包：4 个对象 / 851 字节")
    resolve = json.loads(run_cli(main_store, "resolve", "--name",
                                 "delivery-b"))
    check(resolve["root"]["digest"] == roots["B"],
          "delivery-b 仍指向完整根 B")

    # ------------------------------------------------------------------
    # 步骤 5：屏障——计划后新建引用，整条闭包跳过，其他候选照删
    # ------------------------------------------------------------------
    print("\n== 步骤 5：进程屏障（计划 -> 新引用 -> 应用旧计划） ==")
    barrier_store = os.path.join(tmp, "barrier-store")
    layout2 = os.path.join(tmp, "incoming-2")
    info2 = build_layout(layout2)
    roots2, names2 = info2.roots, info2.names
    import_cli(barrier_store, layout2, roots2["A"], "delivery-a")
    import_cli(barrier_store, layout2, roots2["C"], None)
    import_cli(barrier_store, layout2, roots2["D"], None)
    plan = gc_plan(barrier_store)
    check(plan["object_count"] == 6 and plan["unique_bytes"] == 1088,
          "屏障计划含 C/D 两条垃圾闭包")
    print("$ ... name set --name keep-c --root <C>   （计划生成之后）")
    run_cli(barrier_store, "name", "set", "--name", "keep-c",
            "--root", roots2["C"])
    barrier_run = gc_apply(barrier_store, plan["plan_id"])
    outcomes = {item["digest"]: item for item in barrier_run["items"]}
    for key in ("manifest-garbage", "config-garbage", "garbage-l2"):
        item = outcomes[names2[key]]
        check(item["outcome"] == "skipped" and "可达" in item["reason"],
              f"新引用 keep-c 的 {key} 被跳过并说明原因")
    for key in ("manifest-garbage2", "config-garbage2", "garbage2-l2"):
        check(outcomes[names2[key]]["outcome"] == "deleted",
              f"无关垃圾 {key} 仍被删除")
    check(barrier_run["freed_bytes"] == D_BYTES,
          f"本次实际释放 {barrier_run['freed_bytes']} 字节")
    kept = json.loads(run_cli(barrier_store, "resolve", "--name", "keep-c"))
    check(kept["unique_bytes"] == C_BYTES, "keep-c 整条闭包保持完整可读")

    # ------------------------------------------------------------------
    # 步骤 6：计划生成后新导入对象不在旧计划删除范围
    # ------------------------------------------------------------------
    print("\n== 步骤 6：计划后新导入对象不受旧计划影响 ==")
    late_store = os.path.join(tmp, "late-store")
    import_cli(late_store, layout2, roots2["A"], "delivery-a")
    import_cli(late_store, layout2, roots2["C"], None)
    old_plan = gc_plan(late_store)
    check(old_plan["object_count"] == 3, "旧计划只含 C 闭包 3 个对象")
    print("$ ... import --root <D> --name delivery-late   （计划生成之后）")
    late_import = import_cli(late_store, layout2, roots2["D"],
                             "delivery-late")
    check(late_import["status"] == "imported", "计划后新导入成功")
    late_run = gc_apply(late_store, old_plan["plan_id"])
    check({item["digest"] for item in late_run["items"]}
          == {names2[key] for key in
              ("manifest-garbage", "config-garbage", "garbage-l2")},
          "旧计划只处理它列出的 C 闭包对象")
    for key in ("manifest-garbage2", "config-garbage2", "garbage2-l2"):
        check(late_run and os.path.exists(os.path.join(
            late_store, "blobs", "sha256",
            names2[key].split(":", 1)[1][:2],
            names2[key].split(":", 1)[1])),
            f"计划后导入的 D/{key} 字节未被顺带删除")
    check(json.loads(run_cli(late_store, "resolve", "--name",
                             "delivery-late"))["root"]["digest"]
          == roots2["D"], "delivery-late 仍指向完整根 D")

    # ------------------------------------------------------------------
    # 步骤 7：活着的慢读者 / 被强制结束的读者
    # ------------------------------------------------------------------
    print("\n== 步骤 7a：活着但慢的读者不被按时间判定失效 ==")
    slow_store = os.path.join(tmp, "slow-store")
    import_cli(slow_store, layout2, roots2["A"], "delivery-a")
    import_cli(slow_store, layout2, roots2["C"], None)
    slow = reader_process(slow_store, "delivery-a", names2["base"],
                          names2["amd64-l2"], pause=2.0)
    check(slow.stdout.readline() == b"READY\n", "慢读者已就绪并暂停")
    run_cli(slow_store, "name", "delete", "--name", "delivery-a")
    slow_plan = gc_plan(slow_store)
    check(slow_plan["object_count"] == 3
          and slow_plan["unique_bytes"] == C_BYTES,
          "慢读者仍活着：其闭包不在候选清单")
    slow_run = gc_apply(slow_store, slow_plan["plan_id"])
    check(slow_run["summary"]["deleted"] == 3, "无关垃圾正常回收")
    slow_out = slow.stdout.read()
    slow.wait(timeout=30)
    check(slow.returncode == 0, "慢读者完整读完并正常退出")

    print("\n== 步骤 7b：被强制结束的读者在下一次回收释放保护 ==")
    kill_store = os.path.join(tmp, "kill-store")
    import_cli(kill_store, layout2, roots2["A"], "delivery-a")
    import_cli(kill_store, layout2, roots2["C"], None)
    victim = reader_process(kill_store, "delivery-a", names2["base"],
                            names2["amd64-l2"], pause=30)
    check(victim.stdout.readline() == b"READY\n", "读者已打开上下文")
    run_cli(kill_store, "name", "delete", "--name", "delivery-a")
    victim.kill()
    victim.wait()
    print("$ kill -9 <reader pid>  （不删任何 pin 文件）")
    plan = gc_plan(kill_store)
    check(plan["object_count"] == 3 + 10
          and plan["unique_bytes"] == C_BYTES + A_BYTES,
          "下一次回收辨认死亡读者，把 A 闭包与 C 闭包都列为候选")
    run = gc_apply(kill_store, plan["plan_id"])
    check(run["freed_bytes"] == A_BYTES + C_BYTES,
          f"死亡读者的保护被释放，实际释放 {run['freed_bytes']} 字节")
    check(json.loads(run_cli(kill_store, "stats"))["object_count"] == 0,
          "所有无引用对象均已删除")

    # ------------------------------------------------------------------
    # 步骤 8：两个回收者并发处理有交集清单
    # ------------------------------------------------------------------
    print("\n== 步骤 8：两个回收者同时应用同一份清单 ==")
    conc_store = os.path.join(tmp, "conc-store")
    import_cli(conc_store, layout2, roots2["A"], "delivery-a")
    import_cli(conc_store, layout2, roots2["C"], None)
    import_cli(conc_store, layout2, roots2["D"], None)
    conc_plan = gc_plan(conc_store)
    check(conc_plan["object_count"] == 6, "交集清单含 6 个候选")
    code = '''
import sys, json
sys.path.insert(0, %r)
from oci_catalog.blobstore import BlobStore
store = BlobStore(sys.argv[1])
run = store.apply_gc(sys.argv[2])
print(json.dumps(run.to_dict()))
store.close()
''' % HERE
    procs = [subprocess.Popen([PY, "-I", "-c", code, conc_store,
                               conc_plan["plan_id"]],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)
             for _ in range(2)]
    runs = []
    for p in procs:
        out, err = p.communicate(timeout=60)
        check(p.returncode == 0, f"并发回收者退出码 0（stderr={err!r}）")
        runs.append(json.loads(out))
    deleted = [d for run in runs for d in
               [item["digest"] for item in run["items"]
                if item["outcome"] == "deleted"]]
    check(sorted(deleted) == sorted(
        names2[key] for key in ("manifest-garbage", "config-garbage",
                                "garbage-l2", "manifest-garbage2",
                                "config-garbage2", "garbage2-l2")),
        "6 个候选恰好各被一个回收者删除，另一个如实报告已删除")
    check(sum(run["freed_bytes"] for run in runs) == C_BYTES + D_BYTES,
          f"两次运行合计释放 {C_BYTES + D_BYTES} 字节，没有重复计数")

    # ------------------------------------------------------------------
    # 步骤 9：导入发布前 / 回收删除中异常退出
    # ------------------------------------------------------------------
    print("\n== 步骤 9a：导入发布前异常退出（暂存不被误认） ==")
    crash_store = os.path.join(tmp, "crash-store")
    import_cli(crash_store, layout2, roots2["A"], "delivery-a")
    crash_code = '''
import sys, time
sys.path.insert(0, %r)
import oci_catalog.blobstore.store as st
original = st.BlobStore._publish_closure
def slow_publish(self, *args, **kwargs):
    print("PUBLISHING", flush=True)
    time.sleep(60)
    return original(self, *args, **kwargs)
st.BlobStore._publish_closure = slow_publish
from oci_catalog.blobstore import BlobStore
s = BlobStore(sys.argv[1])
r = s.import_layout(sys.argv[2], sys.argv[3], "delivery-crash")
print(r.status)
''' % HERE
    crash = subprocess.Popen(
        [PY, "-I", "-c", crash_code, crash_store, layout2, roots2["B"]],
        stdout=subprocess.PIPE)
    check(crash.stdout.readline() == b"PUBLISHING\n",
          "子进程已把字节放进暂存但尚未发布")
    crash.kill()
    crash.wait()
    refs = json.loads(run_cli(crash_store, "refs"))["refs"]
    check([r["name"] for r in refs] == ["delivery-a"],
          "崩溃后没有出现半份名称，原 delivery-a 仍可用")
    health = json.loads(run_cli(crash_store, "status"))
    check(health["status"] == "ok", "仓库状态仍一致")
    staging_plan = gc_plan(crash_store)
    # 根 B 的 base 层已由 delivery-a 持有，暂存里只有 3 个新对象
    check(staging_plan["object_count"] == 3
          and staging_plan["unique_bytes"] == B_BYTES - len(BASE_LAYER),
          "未发布暂存字节被列为候选（不是可见对象）")
    staging_run = gc_apply(crash_store, staging_plan["plan_id"])
    check(staging_run["summary"]["deleted"] == 3,
          "未发布暂存可回收")
    check(json.loads(run_cli(crash_store, "resolve", "--name",
                             "delivery-a"))["unique_bytes"] == A_BYTES,
          "原名称闭包字节未受影响")

    print("\n== 步骤 9b：回收删除中途退出，重跑同一清单如实区分 ==")
    mid_store = os.path.join(tmp, "mid-store")
    import_cli(mid_store, layout2, roots2["A"], "delivery-a")
    import_cli(mid_store, layout2, roots2["C"], None)
    import_cli(mid_store, layout2, roots2["D"], None)
    mid_plan = gc_plan(mid_store)
    mid_code = '''
import sys
sys.path.insert(0, %r)
import oci_catalog.blobstore.store as st
original = st.BlobStore._apply_one_candidate
state = {"deleted": 0}
def crash_after_first(self, *args, **kwargs):
    item = original(self, *args, **kwargs)
    if item["outcome"] == "deleted":
        state["deleted"] += 1
        if state["deleted"] == 1:
            import os
            os._exit(9)
    return item
st.BlobStore._apply_one_candidate = crash_after_first
from oci_catalog.blobstore import BlobStore
s = BlobStore(sys.argv[1])
s.apply_gc(sys.argv[2])
''' % HERE
    mid = subprocess.run(
        [PY, "-I", "-c", mid_code, mid_store, mid_plan["plan_id"]],
        capture_output=True)
    check(mid.returncode == 9, "回收者删除一个候选后异常退出（退出码 9）")
    mid_run = gc_apply(mid_store, mid_plan["plan_id"])
    outcomes = {item["digest"]: item["outcome"] for item in mid_run["items"]}
    crashed_candidate = sorted(mid_plan["candidates"],
                               key=lambda item: item["digest"])[0]
    check(outcomes[crashed_candidate["digest"]] == "already_deleted",
          "已由上次中断删除的候选如实记为 already_deleted")
    check(sum(1 for value in outcomes.values() if value == "deleted") == 5,
          "其余 5 个候选在重跑中删除")
    check(mid_run["freed_bytes"] == 1088 - crashed_candidate["size"],
          f"重跑只计本次实际释放 {mid_run['freed_bytes']} 字节")
    mid_runs = json.loads(run_cli(mid_store, "gc", "runs"))["runs"]
    check(len(mid_runs) == 2, "两次运行记录都保留，不宣称整次事务从未发生")

    # ------------------------------------------------------------------
    # 步骤 10：失败导入与缺损回收都是非零退出
    # ------------------------------------------------------------------
    print("\n== 步骤 10：失败导入/缺损回收：非零退出且原状态不变 ==")
    fail_store = os.path.join(tmp, "fail-store")
    import_cli(fail_store, layout2, roots2["A"], "delivery-a")
    before_stats = json.loads(run_cli(fail_store, "stats"))
    before_root = json.loads(run_cli(fail_store, "resolve", "--name",
                                     "delivery-a"))["root"]["digest"]

    bad_layouts = {}
    for kind in ("missing", "badlen", "baddigest"):
        path = os.path.join(tmp, f"bad-{kind}")
        shutil.copytree(layout2, path)
        bad_layouts[kind] = path
    os.unlink(os.path.join(
        bad_layouts["missing"], "blobs", "sha256",
        names2["arm64-l2"].split(":", 1)[1]))
    target = os.path.join(bad_layouts["badlen"], "blobs", "sha256",
                          names2["base"].split(":", 1)[1])
    with open(target, "wb") as fh:
        fh.write(b"short")
    target = os.path.join(bad_layouts["baddigest"], "blobs", "sha256",
                          names2["base"].split(":", 1)[1])
    with open(target, "wb") as fh:
        fh.write(bytes([BASE_LAYER[0] ^ 0xFF]) + BASE_LAYER[1:])

    for kind, expect_code in (("missing", "missing_object"),
                              ("badlen", "size_mismatch"),
                              ("baddigest", "digest_mismatch")):
        result = import_cli(fail_store, bad_layouts[kind], roots2["A"],
                            "delivery-a", expect=2)
        check(result["status"] == "failed"
              and expect_code in [d["code"] for d in result["diagnostics"]],
              f"{kind} 导入以退出码 2 拒绝（诊断 {expect_code}）")
    after_stats = json.loads(run_cli(fail_store, "stats"))
    after_root = json.loads(run_cli(fail_store, "resolve", "--name",
                                    "delivery-a"))["root"]["digest"]
    check(after_root == before_root and after_stats == before_stats,
          "失败导入后原名称仍指向原根，对象账目不变")
    out = os.path.join(tmp, "still-readable.bin")
    run_cli(fail_store, "export", "--name", "delivery-a",
            "--digest", names2["amd64-l2"], "--output", out)
    with open(out, "rb") as fh:
        check(fh.read() == AMD64_L2, "失败导入后原闭包仍可逐字节读出")

    # 已有闭包缺损：回收必须先报状态异常，且不清理任何对象
    missing_store = os.path.join(tmp, "missing-store")
    import_cli(missing_store, layout2, roots2["A"], "delivery-a")
    import_cli(missing_store, layout2, roots2["C"], None)
    os.unlink(os.path.join(
        missing_store, "blobs", "sha256",
        names2["amd64-l3"].split(":", 1)[1][:2],
        names2["amd64-l3"].split(":", 1)[1]))
    corrupt_stats = json.loads(run_cli(missing_store, "stats"))
    plan_proc = subprocess.run(
        [PY, "-I", "-c", CLI_PREFIX, "--store", missing_store,
         "gc", "plan"], capture_output=True, text=True)
    check(plan_proc.returncode == 2
          and "仓库状态异常" in plan_proc.stderr,
          "闭包缺损时 gc plan 以退出码 2 报状态异常")
    check(json.loads(run_cli(missing_store, "stats")) == corrupt_stats,
          "状态异常时没有清理任何对象")
    check(os.path.exists(os.path.join(
        missing_store, "blobs", "sha256",
        names2["garbage-l2"].split(":", 1)[1][:2],
        names2["garbage-l2"].split(":", 1)[1])),
        "无引用的 C 闭包也未被顺带清理")

    # ------------------------------------------------------------------
    # 步骤 11：新进程按手写期待值验收
    # ------------------------------------------------------------------
    verify_plan = {
        "tmp": tmp,
        "stores": {
            "main": main_store,
            "barrier": barrier_store,
            "late": late_store,
            "conc": conc_store,
            "crash": crash_store,
            "mid": mid_store,
            "fail": fail_store,
            "missing": missing_store,
        },
        "roots": roots2,
        "names": names2,
        "main_root_b": roots["B"],
        "main_root_a": roots["A"],
        "plans": {
            "mid": mid_plan["plan_id"],
        },
        "mid_run_id": mid_run["run_id"],
        "mid_crashed_digest": crashed_candidate["digest"],
        "conc_run_ids": [run["run_id"] for run in runs],
    }
    plan_path = os.path.join(tmp, "verify-plan.json")
    with open(plan_path, "w", encoding="utf-8") as fh:
        json.dump(verify_plan, fh, ensure_ascii=False)
    print("\n== 步骤 11：新进程验收（集合与字节数来自手写常量表） ==")
    verifier = os.path.join(HERE, "verify_blobstore_demo.py")
    proc = subprocess.run([PY, "-I", verifier, "--plan", plan_path],
                          capture_output=True, text=True)
    print(proc.stdout)
    if proc.returncode != 0:
        print(proc.stderr, file=sys.stderr)
        raise SystemExit(proc.returncode)
    print(f"\n全部演示与验收通过；数据位于 {tmp}")


if __name__ == "__main__":
    main()
