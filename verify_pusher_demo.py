#!/usr/bin/env python3
"""新进程验收：按夹具常量逐字节核对交付结果。

本脚本被 ``run_pusher_demo.py`` 以独立子进程（``python3 -I``）启动。
期望的摘要、范围与发布先后直接来自夹具：digest 由
``oci_catalog.pusher.sample_data`` 的**字节常量**自算（不调用被测
发布器计算答案），续传前缀等关键偏移是演示脚本手写进 plan 的常量。
对远端只做直接观察：读接收端数据目录的字节文件与 requests.jsonl，
并用标准库 HTTP 客户端 GET 交付标签读回根字节。
"""

import argparse
import json
import os
import sys
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from oci_catalog.pusher.sample_data import (
    AMD64_LAYER, ARM64_LAYER, BASE_LAYER, EMPTY_LAYER,
    fixture_bytes, fixture_digests,
)

DIGESTS = fixture_digests()
TABLE = fixture_bytes()

# 手写期待（独立于被测发布器）
CLOSURE_NAMES = [  # 根 A 闭包的 10 个对象
    "outer-index", "inner-index", "amd64-manifest", "arm64-manifest",
    "amd64-config", "arm64-config", "base-layer", "amd64-layer",
    "arm64-layer", "empty-layer",
]
EXPECTED_MANIFEST_ORDER_AFTER = {  # 子清单必须先于引用它的父索引
    "amd64-manifest": ["inner-index"],
    "arm64-manifest": ["inner-index"],
    "inner-index": ["outer-index"],
}


def check(cond: bool, message: str) -> None:
    if not cond:
        raise AssertionError(message)
    print(f"  ✓ {message}")


def repo_dir(remote_root: str, repo: str) -> str:
    return os.path.join(remote_root, "repos", repo.replace("/", "%2F"))


def read_requests(remote_root: str) -> list:
    path = os.path.join(remote_root, "requests.jsonl")
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh]


def remote_object(remote_root: str, repo: str, name: str) -> bytes:
    digest = DIGESTS[name]
    sub = "manifests" if ("manifest" in name or "index" in name) else "blobs"
    path = os.path.join(repo_dir(remote_root, repo), sub, "sha256",
                        digest.split(":", 1)[1])
    with open(path, "rb") as fh:
        return fh.read()


def verify_closure_bytes(remote_root: str, repo: str, label: str) -> None:
    for name in CLOSURE_NAMES:
        got = remote_object(remote_root, repo, name)
        want = TABLE[name][0]
        check(got == want,
              f"[{label}] {name} 逐字节一致（{len(want)} 字节）")
    # 非 UTF-8 层显式逐字节
    check(remote_object(remote_root, repo, "amd64-layer") == AMD64_LAYER,
          f"[{label}] 非 UTF-8 层含 0x00-0xff 全字节")
    check(remote_object(remote_root, repo, "empty-layer") == b"",
          f"[{label}] 零字节对象存在且为空")


def http_get_tag(endpoint: str, repo: str, tag: str) -> tuple:
    url = f"{endpoint}/v2/{repo}/manifests/{tag}"
    with urllib.request.urlopen(url, timeout=10) as resp:
        return resp.read(), resp.headers.get("Docker-Content-Digest")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--plan", required=True)
    args = parser.parse_args()
    with open(args.plan, encoding="utf-8") as fh:
        plan = json.load(fh)
    repo = plan["repo"]
    tag = plan["tag"]
    remotes = plan["remotes"]
    prefix = plan["expected_prefix"]

    print("== A. 主场景：断连恢复后的完整交付 ==")
    verify_closure_bytes(remotes["a"], repo, "A")
    records = read_requests(remotes["a"])
    dropped = [r for r in records if r["status"] == "dropped"]
    check(len(dropped) == 3
          and [r["content_range"] for r in dropped]
          == ["0-127", "37-164", "74-201"],
          "3 次断连的范围与手写期望一致")
    resume = [r for r in records if r["method"] == "PATCH"
              and r["seq"] > dropped[-1]["seq"]]
    check(resume[0]["content_range"] == f"{prefix}-238",
          f"续传从服务端确认前缀 {prefix}（块内）接上")
    # 被中断对象的字节 = 原层（前缀不重复、剩余不跳）
    check(remote_object(remotes["a"], repo, "arm64-layer") == ARM64_LAYER,
          "被中断对象逐字节一致（不重复拼前缀、不跳剩余字节）")
    # 共享对象只交付一次：base 无 POST
    base_related = [r for r in records
                    if DIGESTS["base-layer"] in r["path"]]
    check(all(r["method"] == "HEAD" for r in base_related),
          "预置共享 base 只有 HEAD，没有上传请求")
    # 清单发布先后
    manifest_puts = [r for r in records if r["method"] == "PUT"
                     and "/manifests/" in r["path"]]
    order = [r["path"].rsplit("/manifests/", 1)[1] for r in manifest_puts]
    for child, parents in EXPECTED_MANIFEST_ORDER_AFTER.items():
        for parent in parents:
            check(order.index(DIGESTS[child]) < order.index(DIGESTS[parent]),
                  f"{child} 先于 {parent} 发布")
    check(order[-1] == tag, "交付标签最后发布")
    check(len(order) == 5, "4 份清单 + 1 次标签，各恰好一次")
    # 旧标签在最终发布前可读
    tag_put_seq = [r["seq"] for r in manifest_puts
                   if r["path"].endswith(f"/manifests/{tag}")][0]
    tag_gets = [r for r in records if r["method"] == "GET"
                and r["path"].endswith(f"/manifests/{tag}")]
    check(tag_gets and all(g["seq"] < tag_put_seq and g["status"] == 200
                           for g in tag_gets),
          "最终发布前旧交付标签仍可读取")
    # 交付标签最终指向本次根（HTTP GET 读回逐字节）
    endpoint = _endpoint_of(remotes["a"])
    raw, served = http_get_tag(endpoint, repo, tag)
    check(raw == TABLE["outer-index"][0] and served == DIGESTS["outer-index"],
          "GET 交付标签读回根字节逐字节一致、摘要相符")
    # 旧清单仍按 digest 可读（内容寻址不受标签覆盖影响）
    check(remote_object(remotes["a"], repo, "old-manifest")
          == TABLE["old-manifest"][0],
          "旧清单字节仍按 digest 可读")

    print("\n== B. 完成回执丢失：不重复上传 ==")
    verify_closure_bytes(remotes["b"], repo, "B")
    records_b = read_requests(remotes["b"])
    layer_puts = [r for r in records_b if r["method"] == "PUT"
                  and DIGESTS["amd64-layer"] in r["path"]]
    check(len(layer_puts) == 1, "amd64-layer 的 PUT 完成恰好一次")
    check(any(r["status"] == "dropped" for r in layer_puts),
          "那次 PUT 的回执确实丢失（dropped）")

    print("\n== C. 会话过期：重开会话重传该对象 ==")
    verify_closure_bytes(remotes["c"], repo, "C")
    records_c = read_requests(remotes["c"])
    posts_c = [r for r in records_c if r["method"] == "POST"]
    check(len(posts_c) == 7, "POST 数 = 6 个 blob + 1 次重开会话")
    expired = [r for r in records_c if r.get("note") == "expire_after_patch"]
    check(len(expired) == 1, "会话过期故障确实触发")
    after = [r for r in records_c if r["method"] == "PATCH"
             and r["seq"] > expired[0]["seq"]]
    check(after[0]["content_range"] == "0-127", "重传从 0 开始")

    print("\n== D. 标签回执丢失：不重复 PUT 标签 ==")
    verify_closure_bytes(remotes["d"], repo, "D")
    records_d = read_requests(remotes["d"])
    tag_puts_d = [r for r in records_d if r["method"] == "PUT"
                  and r["path"].endswith(f"/manifests/{tag}")]
    check(len(tag_puts_d) == 1, "交付标签 PUT 恰好一次")
    check(tag_puts_d[0]["status"] == "dropped", "那次 PUT 的回执确实丢失")
    tags_d = json.load(open(os.path.join(
        repo_dir(remotes["d"], repo), "tags.json"), encoding="utf-8"))
    check(tags_d[tag] == DIGESTS["outer-index"], "标签最终指向本次根")

    print("\n== E. 依赖缺失：交付标签未被改动 ==")
    records_e = read_requests(remotes["e"])
    check(any(r["status"] == 400 and "BLOB_UNKNOWN" in r.get("note", "")
              for r in records_e),
          "接收端报告了依赖缺失")
    check(not any(r["method"] == "PUT"
                  and r["path"].endswith(f"/manifests/{tag}")
                  for r in records_e),
          "客户端没有发布交付标签")
    tags_e = json.load(open(os.path.join(
        repo_dir(remotes["e"], repo), "tags.json"), encoding="utf-8"))
    check(tags_e[tag] == DIGESTS["old-manifest"],
          "旧交付标签仍指向旧根")

    print("\n== F. 鉴权场景：固定 token 交付完整 ==")
    verify_closure_bytes(remotes["f"], repo, "F")
    records_f = read_requests(remotes["f"])
    unauthorized = [r for r in records_f if r["status"] == 401]
    check(len(unauthorized) == 2, "两次未授权请求各得一次 401（无重试）")

    print("\n全部验收通过")


def _endpoint_of(remote_root: str) -> str:
    with open(os.path.join(remote_root, "ready.json"),
              encoding="utf-8") as fh:
        port = json.load(fh)["port"]
    return f"http://127.0.0.1:{port}"


if __name__ == "__main__":
    main()
