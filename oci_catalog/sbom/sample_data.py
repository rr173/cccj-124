"""可重建的演示样例：相互关联的供应商 SBOM 与配套目录内容。

样例刻意覆盖数据契约中的关键情形（全部由代码生成，无外部文件依赖）：

* 同一组件在两种格式中用不同写法出现（CycloneDX 的 ``Flask_Core.Ext`` 与
  SPDX 的 ``flask-core-ext`` 经 PEP 503 归一后是同一 pypi 坐标）；
* 镜像 ``sha256:11...`` 同时绑定两份来源清单，且两份文件**故意复用相同
  引用名** ``SPDXRef-urllib3``（一个是 CycloneDX bom-ref，一个是 SPDXID），
  证明跨文件节点不会被接在一起；
* 另一个平台 ``sha256:22...`` 使用同名但不同版本的组件
  （requests 2.32.3 vs 2.31.0、urllib3 1.26.18 vs 2.2.1）；
* 菱形依赖（app -> requests -> {urllib3, certifi} 与 app -> urllib3）、
  根可达环（utils <-> helper）以及与根不连通的环岛屿（iso-a <-> iso-b）；
* 两个不同 bom-ref 指向同一 purl（cyclonedx 内重复身份，出现记录各自保留）；
* 坏坐标、悬空引用、重复 bom-ref、非法镜像绑定各一份，用于验证拒绝语义。
"""

from __future__ import annotations

import copy

# ---------------------------------------------------------------------------
# 目录内容（喂给 FakeRegistry 采集后得到 image manifest digest）
# ---------------------------------------------------------------------------
# 固定摘要字节模式，便于在文档与断言中直接引用
IMAGE_AMD64_DIGEST = "sha256:" + "11" * 32
IMAGE_ARM64_DIGEST = "sha256:" + "22" * 32
CONFIG_DIGEST = "sha256:" + "c0" * 32
LAYER_AMD64 = "sha256:" + "d1" * 32
LAYER_ARM64 = "sha256:" + "d2" * 32
INDEX_DIGEST_PLACEHOLDER = "index"  # 由 registry 计算，构建时回填

REGISTRY_IMAGES = [
    # (repository, image_digest, layers, platform)
    ("vendor/shop", IMAGE_AMD64_DIGEST, [LAYER_AMD64],
     {"architecture": "amd64", "os": "linux"}),
    ("vendor/edge", IMAGE_ARM64_DIGEST, [LAYER_ARM64],
     {"architecture": "arm64", "os": "linux", "variant": "v8"}),
]

# ---------------------------------------------------------------------------
# 样例 1：CycloneDX（绑定 amd64 镜像）
# ---------------------------------------------------------------------------
def cyclonedx_shop() -> dict:
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": "urn:uuid:cyclonedx-shop-0001",
        "version": 1,
        "components": [
            {
                "bom-ref": "SPDXRef-app",
                "type": "application",
                "name": "shop-app",
                "version": "4.0.0",
                "supplier": {"name": "Shop Platform Team"},
                "licenses": [{"license": {"id": "Apache-2.0"}}],
                "components": [
                    {
                        # 嵌套 component：位置必须可追溯
                        "bom-ref": "SPDXRef-helper",
                        "type": "library",
                        "name": "shop-helper",
                        "version": "0.9.0",
                        "licenses": [{"expression": "MIT OR Apache-2.0"}],
                    },
                ],
            },
            {
                # PyPI 名称写法 1：连字符/下划线/点混合
                "bom-ref": "SPDXRef-flask",
                "type": "library",
                "name": "Flask_Core.Ext",
                "version": "3.0.2",
                "purl": "pkg:pypi/Flask_Core.Ext@3.0.2",
                "supplier": {"name": "Pallets"},
                "licenses": [{"license": {"id": "BSD-3-Clause"}}],
            },
            {
                "bom-ref": "SPDXRef-requests",
                "type": "library",
                "name": "requests",
                "version": "2.32.3",
                "purl": "pkg:pypi/requests@2.32.3",
                "supplier": "PSF",
                "licenses": [{"license": {"id": "Apache-2.0"}}],
            },
            {
                "bom-ref": "SPDXRef-urllib3",
                "type": "library",
                "name": "urllib3",
                "version": "1.26.18",
                # qualifier 乱序 + 大写编码，验证排序与百分号编码归一
                "purl": "pkg:pypi/urllib3@1.26.18?repo=main&arch=%41MD64",
                "licenses": [{"license": {"id": "MIT"}}],
            },
            {
                # 与 SPDXRef-urllib3 不同 bom-ref、同一 purl（去掉 qualifier
                # 后故意不同坐标，这里构造真正同 purl 的两个出现）
                "bom-ref": "SPDXRef-urllib3-dup",
                "type": "library",
                "name": "urllib3-vendored-copy",
                "version": "1.26.18",
                "purl": "pkg:pypi/urllib3@1.26.18?arch=AMD64&repo=main",
                "licenses": [{"license": {"name": "MIT License"}}],
            },
            {
                "bom-ref": "SPDXRef-certifi",
                "type": "library",
                "name": "certifi",
                "version": "2024.2.2",
                "purl": "pkg:pypi/certifi@2024.2.2",
                "licenses": [{"license": {"id": "MPL-2.0"}}],
            },
            {
                # npm scope + 编码字符
                "bom-ref": "SPDXRef-angular",
                "type": "library",
                "name": "@angular/animation",
                "version": "17.0.0",
                "purl": "pkg:npm/%40angular/animation@17.0.0",
                "supplier": "Google",
            },
            {
                "bom-ref": "SPDXRef-openssl",
                "type": "library",
                "name": "openssl",
                "version": "3.0.13",
                "purl": "pkg:generic/openssl@3.0.13?distro=debian",
                "supplier": "OpenSSL Project",
                "licenses": [{"license": {"id": "Apache-2.0"}}],
            },
            {
                # 无 purl 组件：只保留文件内身份，不臆造全局坐标
                "bom-ref": "SPDXRef-internal-blob",
                "type": "library",
                "name": "internal-secret-sauce",
                "version": "0.1",
                "licenses": [{"license": {"name": "Proprietary"}}],
            },
            {
                # 根可达环的另一侧 + 环岛屿
                "bom-ref": "SPDXRef-utils",
                "type": "library",
                "name": "shop-utils",
                "version": "1.4.0",
                "purl": "pkg:generic/shop-utils@1.4.0",
            },
            {
                "bom-ref": "SPDXRef-iso-a",
                "type": "library",
                "name": "isolated-a",
                "version": "9",
            },
            {
                "bom-ref": "SPDXRef-iso-b",
                "type": "library",
                "name": "isolated-b",
                "version": "9",
            },
        ],
        "dependencies": [
            # 菱形：urllib3 同时经 requests 与 flask 两条同长路径可达；
            # app 不直接依赖 urllib3，保证最短路径恰有两条、按引用名定序
            {"ref": "SPDXRef-app", "dependsOn": [
                "SPDXRef-requests", "SPDXRef-flask",
                "SPDXRef-angular", "SPDXRef-utils"]},
            {"ref": "SPDXRef-requests", "dependsOn": [
                "SPDXRef-urllib3", "SPDXRef-certifi"]},
            {"ref": "SPDXRef-flask", "dependsOn": [
                "SPDXRef-helper", "SPDXRef-urllib3"]},
            # 根可达环：utils -> helper -> utils（flask 也指向 helper）
            {"ref": "SPDXRef-utils", "dependsOn": ["SPDXRef-helper"]},
            {"ref": "SPDXRef-helper", "dependsOn": ["SPDXRef-utils"]},
            # 与根不连通的环岛屿
            {"ref": "SPDXRef-iso-a", "dependsOn": ["SPDXRef-iso-b"]},
            {"ref": "SPDXRef-iso-b", "dependsOn": ["SPDXRef-iso-a"]},
        ],
    }


# ---------------------------------------------------------------------------
# 样例 2：SPDX（同样绑定 amd64 镜像；复用引用名 SPDXRef-urllib3）
# ---------------------------------------------------------------------------
def spdx_shop() -> dict:
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "shop-app-spdx",
        "documentNamespace": "https://vendor.example/spdx/shop",
        "creationInfo": {"creators": ["Tool: sample-generator"]},
        "packages": [
            {
                "SPDXID": "SPDXRef-DOCUMENT-root",
                "name": "shop-app-oss-attribution",
                "versionInfo": "4.0.0",
                "supplier": "Organization: Shop Platform Team",
                "licenseDeclared": "Apache-2.0",
                "licenseConcluded": "Apache-2.0",
            },
            {
                # PyPI 名称写法 2：与 CycloneDX 的 Flask_Core.Ext 归一为同一坐标
                "SPDXID": "SPDXRef-flask-spdx",
                "name": "flask-core-ext",
                "versionInfo": "3.0.2",
                "supplier": "Organization: Pallets",
                "licenseDeclared": "BSD-3-Clause",
                "externalRefs": [{
                    "referenceType": "purl",
                    "referenceLocator": "pkg:pypi/flask-core-ext@3.0.2",
                    "referenceCategory": "PACKAGE-MANAGER",
                }],
            },
            {
                # 故意复用 CycloneDX 文件里的 bom-ref 字符串
                "SPDXID": "SPDXRef-urllib3",
                "name": "urllib3",
                "versionInfo": "1.26.18",
                "licenseDeclared": "MIT",
                "externalRefs": [{
                    "referenceType": "purl",
                    "referenceLocator": "pkg:pypi/urllib3@1.26.18",
                    "referenceCategory": "PACKAGE-MANAGER",
                }],
            },
            {
                "SPDXID": "SPDXRef-ldap",
                "name": "python-ldap",
                "versionInfo": "3.4.4",
                "licenseDeclared": "Python-2.0",
            },
        ],
        "relationships": [
            {"spdxElementId": "SPDXRef-DOCUMENT",
             "relationshipType": "DESCRIBES",
             "relatedSpdxElement": "SPDXRef-DOCUMENT-root"},
            # 正向 DEPENDS_ON
            {"spdxElementId": "SPDXRef-DOCUMENT-root",
             "relationshipType": "DEPENDS_ON",
             "relatedSpdxElement": "SPDXRef-flask-spdx"},
            # 反向 DEPENDENCY_OF：A DEPENDENCY_OF B => B 依赖 A
            {"spdxElementId": "SPDXRef-urllib3",
             "relationshipType": "DEPENDENCY_OF",
             "relatedSpdxElement": "SPDXRef-DOCUMENT-root"},
            {"spdxElementId": "SPDXRef-ldap",
             "relationshipType": "DEPENDENCY_OF",
             "relatedSpdxElement": "SPDXRef-flask-spdx"},
            # 非依赖关系：必须被忽略，不能产生边
            {"spdxElementId": "SPDXRef-flask-spdx",
             "relationshipType": "CONTAINS",
             "relatedSpdxElement": "SPDXRef-urllib3"},
        ],
    }


# ---------------------------------------------------------------------------
# 样例 3：CycloneDX（绑定 arm64 镜像；同名不同版本，再次复用引用名）
# ---------------------------------------------------------------------------
def cyclonedx_edge() -> dict:
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": "urn:uuid:cyclonedx-edge-0002",
        "version": 1,
        "components": [
            {
                "bom-ref": "SPDXRef-edge-app",
                "type": "application",
                "name": "edge-gateway",
                "version": "2.1.0",
                "purl": "pkg:generic/edge-gateway@2.1.0",
            },
            {
                # 同名不同版本：requests 2.31.0，不可与 shop 的 2.32.3 合并
                "bom-ref": "SPDXRef-requests",
                "type": "library",
                "name": "requests",
                "version": "2.31.0",
                "purl": "pkg:pypi/requests@2.31.0",
            },
            {
                # 再次复用 shop 清单里的 bom-ref 字符串
                "bom-ref": "SPDXRef-urllib3",
                "type": "library",
                "name": "urllib3",
                "version": "2.2.1",
                "purl": "pkg:pypi/urllib3@2.2.1",
            },
            {
                "bom-ref": "SPDXRef-certifi",
                "type": "library",
                "name": "certifi",
                "version": "2024.2.2",
                "purl": "pkg:pypi/certifi@2024.2.2",
            },
        ],
        "dependencies": [
            {"ref": "SPDXRef-edge-app", "dependsOn": ["SPDXRef-requests"]},
            {"ref": "SPDXRef-requests", "dependsOn": [
                "SPDXRef-urllib3", "SPDXRef-certifi"]},
        ],
    }


# ---------------------------------------------------------------------------
# 坏样例（全部必须被拒绝，且不留下可查询记录）
# ---------------------------------------------------------------------------
def bad_invalid_purl() -> dict:
    doc = cyclonedx_shop()
    doc = copy.deepcopy(doc)
    doc["serialNumber"] = "urn:uuid:bad-invalid-purl"
    doc["components"][2]["purl"] = "not-a-purl://bad"  # requests 节点
    return doc


def bad_dangling_ref() -> dict:
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": [
            {"bom-ref": "A", "name": "a", "version": "1"},
        ],
        "dependencies": [
            {"ref": "A", "dependsOn": ["GHOST"]},
        ],
    }


def bad_duplicate_bomref() -> dict:
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": [
            {"bom-ref": "DUP", "name": "first", "version": "1"},
            {"bom-ref": "DUP", "name": "second", "version": "2"},
        ],
    }
