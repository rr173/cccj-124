"""可重建的公告关联演示样例：两个平台的 SBOM + 人工公告目录。

样例覆盖（全部由代码生成，无外部文件依赖；期待值在 verify_vuln_demo.py
中手写，不用正式区间判定器再算）：

* PyPI 同包不同版本：requests 2.31.0（amd64）与 2.32.3（arm64）；
* npm 带 scope 的预发行版本：@acme/widget 2.0.0-rc.2 与 2.0.0-rc.10；
* 同坐标在不同清单中的重复出现：requests 2.31.0 同时出现在 amd64 的
  CycloneDX 与 SPDX 两份清单中；
* 区间形态：引入—修复—再次引入（helper）、fixed/limit 排除端点
  （requests 2.32.3、utils 1.5.0）、last_affected 包含端点（helper 0.9.7）、
  PyPI dev/rc/post 次序（shoplib）、npm rc.2 与 rc.10、构建元数据
  （gadget 1.4.0+build.7）、精确版本列表与区间的并集（certifi）；
* 编号语义：VULN-AAAA/BBBB/CCCC 别名传递环（GHSA-GHOST-0000 无独立文件）、
  VULN-DDDD 仅 related 不并组、GHOST-0001 已撤回不贡献范围、
  PACK-AAAA/BBBB 同组不同包不串范围；
* 无法判断一律不写成安全：GIT 区间、PyPI 上的 SEMVER 区间、缺版本 purl、
  无 purl、generic 生态、空版本集合、未知与确定不命中不混用。
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# 目录内容（喂给 FakeRegistry 采集后得到 image manifest digest）
# ---------------------------------------------------------------------------
IMAGE_AMD64_DIGEST = "sha256:" + "aa" * 32
IMAGE_ARM64_DIGEST = "sha256:" + "bb" * 32
IMAGE_QUIET_DIGEST = "sha256:" + "cc" * 32   # 无 SBOM 的镜像（单独说明用例）
CONFIG_DIGEST = "sha256:" + "c0" * 32
LAYER_AMD64 = "sha256:" + "d1" * 32
LAYER_ARM64 = "sha256:" + "d2" * 32
LAYER_QUIET = "sha256:" + "d3" * 32

REGISTRY_IMAGES = [
    ("vendor/shop", IMAGE_AMD64_DIGEST, [LAYER_AMD64],
     {"architecture": "amd64", "os": "linux"}),
    ("vendor/edge", IMAGE_ARM64_DIGEST, [LAYER_ARM64],
     {"architecture": "arm64", "os": "linux", "variant": "v8"}),
    ("vendor/quiet", IMAGE_QUIET_DIGEST, [LAYER_QUIET],
     {"architecture": "amd64", "os": "linux"}),
]

# ---------------------------------------------------------------------------
# SBOM 样例 1：CycloneDX（绑定 amd64 镜像）
# ---------------------------------------------------------------------------
def shop_cdx() -> dict:
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": "urn:uuid:vuln-demo-shop-0001",
        "version": 1,
        "components": [
            {
                "bom-ref": "SPDXRef-app",
                "type": "application",
                "name": "shop-app",
                "version": "4.0.0",
            },
            {
                "bom-ref": "SPDXRef-requests",
                "type": "library",
                "name": "requests",
                "version": "2.31.0",
                "purl": "pkg:pypi/requests@2.31.0",
            },
            {
                "bom-ref": "SPDXRef-shoplib",
                "type": "library",
                "name": "shoplib",
                "version": "1.0rc1",
                "purl": "pkg:pypi/shoplib@1.0rc1",
            },
            {
                "bom-ref": "SPDXRef-certifi",
                "type": "library",
                "name": "certifi",
                "version": "2024.2.2",
                "purl": "pkg:pypi/certifi@2024.2.2",
            },
            {
                "bom-ref": "SPDXRef-widget",
                "type": "library",
                "name": "@acme/widget",
                "version": "2.0.0-rc.2",
                "purl": "pkg:npm/%40acme/widget@2.0.0-rc.2",
            },
            {
                # 构建元数据：purl 中 '+' 规范编码为 %2B
                "bom-ref": "SPDXRef-gadget",
                "type": "library",
                "name": "@acme/gadget",
                "version": "1.4.0+build.7",
                "purl": "pkg:npm/%40acme/gadget@1.4.0%2Bbuild.7",
            },
            {
                "bom-ref": "SPDXRef-utils",
                "type": "library",
                "name": "utils",
                "version": "1.5.0",
                "purl": "pkg:pypi/utils@1.5.0",
            },
            {
                "bom-ref": "SPDXRef-helper",
                "type": "library",
                "name": "helper",
                "version": "0.9.7",
                "purl": "pkg:pypi/helper@0.9.7",
            },
        ],
        "dependencies": [
            {"ref": "SPDXRef-app", "dependsOn": [
                "SPDXRef-requests", "SPDXRef-shoplib", "SPDXRef-certifi",
                "SPDXRef-widget", "SPDXRef-gadget", "SPDXRef-utils",
                "SPDXRef-helper"]},
        ],
    }


# ---------------------------------------------------------------------------
# SBOM 样例 2：SPDX（同样绑定 amd64 镜像；含与样例 1 相同的坐标）
# ---------------------------------------------------------------------------
def shop_spdx() -> dict:
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "shop-attribution",
        "documentNamespace": "https://vendor.example/spdx/shop-attribution",
        "creationInfo": {"creators": ["Tool: sample-generator"]},
        "packages": [
            {
                # 同坐标在不同清单中的重复出现（与 shop.cdx.json 同 purl）
                "SPDXID": "SPDXRef-requests-spdx",
                "name": "requests",
                "versionInfo": "2.31.0",
                "externalRefs": [{
                    "referenceType": "purl",
                    "referenceLocator": "pkg:pypi/requests@2.31.0",
                    "referenceCategory": "PACKAGE-MANAGER",
                }],
            },
            {
                # 无版本 purl：公告目录有该包声明，但安装版本缺失
                "SPDXID": "SPDXRef-legacylib",
                "name": "legacylib",
                "versionInfo": "1.0",
                "externalRefs": [{
                    "referenceType": "purl",
                    "referenceLocator": "pkg:pypi/legacylib",
                    "referenceCategory": "PACKAGE-MANAGER",
                }],
            },
            {
                # 不支持生态（generic）：不能写成安全
                "SPDXID": "SPDXRef-openssl",
                "name": "openssl",
                "versionInfo": "3.0.13",
                "externalRefs": [{
                    "referenceType": "purl",
                    "referenceLocator": "pkg:generic/openssl@3.0.13?distro=debian",
                    "referenceCategory": "PACKAGE-MANAGER",
                }],
            },
            {
                # 无 purl：只保留文件内身份
                "SPDXID": "SPDXRef-internal-blob",
                "name": "internal-blob",
                "versionInfo": "0.1",
            },
            {
                # 带 qualifiers 的安装项：按生态+包名匹配，qualifiers 原样带回
                "SPDXID": "SPDXRef-qualpkg",
                "name": "qualpkg",
                "versionInfo": "3.1.0",
                "externalRefs": [{
                    "referenceType": "purl",
                    "referenceLocator":
                        "pkg:pypi/qualpkg@3.1.0?repo=main&arch=%41MD64",
                    "referenceCategory": "PACKAGE-MANAGER",
                }],
            },
        ],
        "relationships": [
            {"spdxElementId": "SPDXRef-DOCUMENT",
             "relationshipType": "DESCRIBES",
             "relatedSpdxElement": "SPDXRef-requests-spdx"},
        ],
    }


# ---------------------------------------------------------------------------
# SBOM 样例 3：CycloneDX（绑定 arm64 镜像）
# ---------------------------------------------------------------------------
def edge_cdx() -> dict:
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": "urn:uuid:vuln-demo-edge-0002",
        "version": 1,
        "components": [
            {"bom-ref": "SPDXRef-edge-app", "type": "application",
             "name": "edge-gateway", "version": "2.1.0"},
            {"bom-ref": "SPDXRef-requests", "type": "library",
             "name": "requests", "version": "2.32.3",
             "purl": "pkg:pypi/requests@2.32.3"},
            {"bom-ref": "SPDXRef-shoplib", "type": "library",
             "name": "shoplib", "version": "1.0.post1",
             "purl": "pkg:pypi/shoplib@1.0.post1"},
            {"bom-ref": "SPDXRef-widget", "type": "library",
             "name": "@acme/widget", "version": "2.0.0-rc.10",
             "purl": "pkg:npm/%40acme/widget@2.0.0-rc.10"},
            {"bom-ref": "SPDXRef-ghostpkg", "type": "library",
             "name": "ghostpkg", "version": "5.0",
             "purl": "pkg:pypi/ghostpkg@5.0"},
            {"bom-ref": "SPDXRef-alphalib", "type": "library",
             "name": "alphalib", "version": "1.5",
             "purl": "pkg:pypi/alphalib@1.5"},
            {"bom-ref": "SPDXRef-betalib", "type": "library",
             "name": "betalib", "version": "1.5",
             "purl": "pkg:pypi/betalib@1.5"},
            {"bom-ref": "SPDXRef-oddpkg", "type": "library",
             "name": "oddpkg", "version": "1.0",
             "purl": "pkg:pypi/oddpkg@1.0"},
            {"bom-ref": "SPDXRef-mystery", "type": "library",
             "name": "mystery", "version": "3.0.0",
             "purl": "pkg:npm/mystery@3.0.0"},
            {"bom-ref": "SPDXRef-emptyset", "type": "library",
             "name": "emptyset", "version": "9.9",
             "purl": "pkg:pypi/emptyset@9.9"},
            {"bom-ref": "SPDXRef-mixedpkg", "type": "library",
             "name": "mixedpkg", "version": "3.0",
             "purl": "pkg:pypi/mixedpkg@3.0"},
            {"bom-ref": "SPDXRef-toolkit", "type": "library",
             "name": "@acme/toolkit", "version": "7.7.7",
             "purl": "pkg:npm/%40acme/toolkit@7.7.7"},
            {"bom-ref": "SPDXRef-helper", "type": "library",
             "name": "helper", "version": "0.9.4",
             "purl": "pkg:pypi/helper@0.9.4"},
        ],
        "dependencies": [
            {"ref": "SPDXRef-edge-app", "dependsOn": [
                "SPDXRef-requests", "SPDXRef-widget", "SPDXRef-toolkit"]},
        ],
    }


# ---------------------------------------------------------------------------
# 人工公告目录（OSV 风格子集；文件名 -> 公告对象）
# ---------------------------------------------------------------------------
def advisories() -> dict[str, dict]:
    """返回 {文件名: 公告对象}；坏公告样例单独提供（见模块尾部）。"""
    return {
        # requests：单区间，fixed 排除端点（2.32.3 恰好是端点）
        "PYSEC-FAKE-0001.json": {
            "id": "PYSEC-FAKE-0001",
            "summary": "requests demo advisory",
            "affected": [{
                "package": {"ecosystem": "PyPI", "name": "requests"},
                "ranges": [{
                    "type": "ECOSYSTEM",
                    "events": [{"introduced": "2.31.0"},
                               {"fixed": "2.32.3"}],
                }],
            }],
        },
        # shoplib：PyPI dev/rc/post 次序（1.0.dev1 <= 1.0rc1 < 1.0 < 1.0.post1）
        "PYSEC-FAKE-0002.json": {
            "id": "PYSEC-FAKE-0002",
            "affected": [{
                "package": {"ecosystem": "PyPI", "name": "shoplib"},
                "ranges": [{
                    "type": "ECOSYSTEM",
                    "events": [{"introduced": "1.0.dev1"},
                               {"fixed": "1.0"}],
                }],
            }],
        },
        # certifi：别名传递环 A->B->C->A，外加无独立文件的别名 GHSA-GHOST-0000；
        # versions 精确列表与区间并集（命中来自 versions）
        "VULN-AAAA.json": {
            "id": "VULN-AAAA",
            "aliases": ["VULN-BBBB", "GHSA-GHOST-0000"],
            "affected": [{
                "package": {"ecosystem": "PyPI", "name": "certifi"},
                "versions": ["2024.2.2"],
                "ranges": [{
                    "type": "ECOSYSTEM",
                    "events": [{"introduced": "2030.1.1"},
                               {"last_affected": "2030.12.31"}],
                }],
            }],
        },
        "VULN-BBBB.json": {
            "id": "VULN-BBBB",
            "aliases": ["VULN-CCCC"],
            "affected": [{
                "package": {"ecosystem": "PyPI", "name": "certifi"},
                "ranges": [{
                    "type": "ECOSYSTEM",
                    "events": [{"introduced": "2025.0.0"},
                               {"fixed": "2025.6.1"}],
                }],
            }],
        },
        "VULN-CCCC.json": {
            "id": "VULN-CCCC",
            "aliases": ["VULN-AAAA"],   # 关闭传递环
        },
        # 仅 related：不并组，仍是独立漏洞
        "VULN-DDDD.json": {
            "id": "VULN-DDDD",
            "related": ["VULN-AAAA"],
            "affected": [{
                "package": {"ecosystem": "PyPI", "name": "certifi"},
                "ranges": [{
                    "type": "ECOSYSTEM",
                    "events": [{"introduced": "2024.0.0"},
                               {"fixed": "2024.1.1"}],
                }],
            }],
        },
        # certifi 的 GIT 区间：不支持 -> unknown，但不抹掉 VULN-AAAA 的命中
        "CERTIFI-GIT.json": {
            "id": "CERTIFI-GIT",
            "affected": [{
                "package": {"ecosystem": "PyPI", "name": "certifi"},
                "ranges": [{
                    "type": "GIT",
                    "events": [{"introduced": "deadbeef"}],
                }],
            }],
        },
        # @acme/widget：npm 预发行数字段按数字比较（rc.2 < rc.10）
        "NPM-WIDGET.json": {
            "id": "NPM-WIDGET",
            "affected": [{
                "package": {"ecosystem": "npm", "name": "@acme/widget"},
                "ranges": [{
                    "type": "SEMVER",
                    "events": [{"introduced": "2.0.0-rc.1"},
                               {"fixed": "2.0.0-rc.10"}],
                }],
            }],
        },
        # @acme/gadget：构建元数据不影响区间先后；versions 精确列表按文本
        # 匹配，"1.4.0" 不等于安装的 "1.4.0+build.7"
        "NPM-GADGET.json": {
            "id": "NPM-GADGET",
            "affected": [{
                "package": {"ecosystem": "npm", "name": "@acme/gadget"},
                "versions": ["1.4.0"],
                "ranges": [{
                    "type": "SEMVER",
                    "events": [{"introduced": "1.3.0"},
                               {"fixed": "1.4.0"}],
                }],
            }],
        },
        # utils：introduced "0"（从所有版本之前开始）+ limit 排除端点
        "PYSEC-FAKE-0010.json": {
            "id": "PYSEC-FAKE-0010",
            "affected": [{
                "package": {"ecosystem": "PyPI", "name": "utils"},
                "ranges": [{
                    "type": "ECOSYSTEM",
                    "events": [{"introduced": "0"},
                               {"limit": "1.5.0"}],
                }],
            }],
        },
        # helper：引入—修复—再次引入，last_affected 包含端点
        "PYSEC-FAKE-0011.json": {
            "id": "PYSEC-FAKE-0011",
            "affected": [{
                "package": {"ecosystem": "PyPI", "name": "helper"},
                "ranges": [{
                    "type": "ECOSYSTEM",
                    "events": [{"introduced": "0.9.0"},
                               {"fixed": "0.9.3"},
                               {"introduced": "0.9.5"},
                               {"last_affected": "0.9.7"}],
                }],
            }],
        },
        # legacylib：有声明但安装 purl 无版本 -> unknown
        "PYSEC-FAKE-0012.json": {
            "id": "PYSEC-FAKE-0012",
            "affected": [{
                "package": {"ecosystem": "PyPI", "name": "legacylib"},
                "ranges": [{
                    "type": "ECOSYSTEM",
                    "events": [{"introduced": "1.0"},
                               {"fixed": "2.0"}],
                }],
            }],
        },
        # qualpkg：fixed 排除端点（3.1.0 恰好是端点）
        "PYSEC-FAKE-0013.json": {
            "id": "PYSEC-FAKE-0013",
            "affected": [{
                "package": {"ecosystem": "PyPI", "name": "qualpkg"},
                "ranges": [{
                    "type": "ECOSYSTEM",
                    "events": [{"introduced": "3.0.0"},
                               {"fixed": "3.1.0"}],
                }],
            }],
        },
        # ghostpkg：已撤回，范围不贡献命中；别名仍保留作编号解释
        "GHOST-0001.json": {
            "id": "GHOST-0001",
            "aliases": ["CVE-GHOST-0001"],
            "withdrawn": "2024-01-15T00:00:00Z",
            "affected": [{
                "package": {"ecosystem": "PyPI", "name": "ghostpkg"},
                "ranges": [{
                    "type": "ECOSYSTEM",
                    "events": [{"introduced": "1.0"},
                               {"fixed": "9.9"}],
                }],
            }],
        },
        # alphalib / betalib：同组不同包，范围不互串
        "PACK-AAAA.json": {
            "id": "PACK-AAAA",
            "affected": [{
                "package": {"ecosystem": "PyPI", "name": "alphalib"},
                "ranges": [{
                    "type": "ECOSYSTEM",
                    "events": [{"introduced": "1.0"},
                               {"fixed": "2.0"}],
                }],
            }],
        },
        "PACK-BBBB.json": {
            "id": "PACK-BBBB",
            "aliases": ["PACK-AAAA"],
            "affected": [{
                "package": {"ecosystem": "PyPI", "name": "betalib"},
                "ranges": [{
                    "type": "ECOSYSTEM",
                    "events": [{"introduced": "3.0"},
                               {"fixed": "4.0"}],
                }],
            }],
        },
        # mystery：npm 的 GIT 区间 -> unknown
        "NPM-MYSTERY.json": {
            "id": "NPM-MYSTERY",
            "affected": [{
                "package": {"ecosystem": "npm", "name": "mystery"},
                "ranges": [{
                    "type": "GIT",
                    "events": [{"introduced": "deadbeef"}],
                }],
            }],
        },
        # oddpkg：PyPI 上的 SEMVER 区间 -> unknown
        "PYSEC-FAKE-0014.json": {
            "id": "PYSEC-FAKE-0014",
            "affected": [{
                "package": {"ecosystem": "PyPI", "name": "oddpkg"},
                "ranges": [{
                    "type": "SEMVER",
                    "events": [{"introduced": "1.0.0"},
                               {"fixed": "2.0.0"}],
                }],
            }],
        },
        # emptyset：空 versions 且无 ranges -> 缺少可用版本集合 -> unknown
        "PYSEC-FAKE-0015.json": {
            "id": "PYSEC-FAKE-0015",
            "affected": [{
                "package": {"ecosystem": "PyPI", "name": "emptyset"},
                "versions": [],
            }],
        },
        # mixedpkg：一条可判定不命中 + 一条不支持区间 -> unknown（不混用）
        "PYSEC-FAKE-0016.json": {
            "id": "PYSEC-FAKE-0016",
            "affected": [{
                "package": {"ecosystem": "PyPI", "name": "mixedpkg"},
                "ranges": [{
                    "type": "ECOSYSTEM",
                    "events": [{"introduced": "1.0"},
                               {"fixed": "2.0"}],
                }],
            }],
        },
        "PYSEC-FAKE-0017.json": {
            "id": "PYSEC-FAKE-0017",
            "affected": [{
                "package": {"ecosystem": "PyPI", "name": "mixedpkg"},
                "ranges": [{
                    "type": "GIT",
                    "events": [{"introduced": "cafe"}],
                }],
            }],
        },
    }


# ---------------------------------------------------------------------------
# 坏公告样例（每一个都必须让整次作业失败，并定位文件与字段）
# ---------------------------------------------------------------------------
def bad_regress() -> dict:
    """fixed 端点低于 introduced：区间倒退。"""
    return {
        "id": "BAD-REGRESS",
        "affected": [{
            "package": {"ecosystem": "PyPI", "name": "requests"},
            "ranges": [{
                "type": "ECOSYSTEM",
                "events": [{"introduced": "2.0.0"},
                           {"fixed": "1.0.0"}],
            }],
        }],
    }


def bad_overlap() -> dict:
    """后段 introduced 低于前段 fixed 端点：区间重叠。"""
    return {
        "id": "BAD-OVERLAP",
        "affected": [{
            "package": {"ecosystem": "PyPI", "name": "requests"},
            "ranges": [{
                "type": "ECOSYSTEM",
                "events": [{"introduced": "1.0.0"},
                           {"fixed": "2.0.0"},
                           {"introduced": "1.5.0"},
                           {"fixed": "3.0.0"}],
            }],
        }],
    }


def bad_duplicate_id() -> dict:
    """与 PYSEC-FAKE-0001 重复的 id。"""
    return {"id": "PYSEC-FAKE-0001",
            "affected": [{
                "package": {"ecosystem": "PyPI", "name": "utils"},
                "versions": ["1.0"]}]}


def bad_structure() -> dict:
    """affected 缺少 package.name：字段结构错误。"""
    return {
        "id": "BAD-STRUCTURE",
        "affected": [{
            "package": {"ecosystem": "PyPI"},
            "versions": ["1.0"],
        }],
    }


# 重复 JSON 键（必须以原始文本写出，对象构造无法表达）
BAD_DUP_KEY_TEXT = (
    '{\n'
    '  "id": "BAD-DUP-KEY",\n'
    '  "id": "BAD-DUP-KEY-AGAIN",\n'
    '  "affected": []\n'
    '}\n'
)
