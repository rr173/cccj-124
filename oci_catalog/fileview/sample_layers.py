"""可重建的演示样例：多平台镜像的三层本地归档（全部由代码生成）。

场景覆盖交付验收需要演示的全部语义：

* **vendor/dataproc:amd64**（三层：gzip + gzip + 未压缩 tar）
  覆盖、删除（``.wh.``）、不透明目录（``.wh..wh..opq``）、新增内容、
  前向硬链接、复用低层文件的硬链接、符号链接、非 UTF-8 文件字节；
* **vendor/dataproc:arm64**（两层 gzip）另一套生效内容，并演示
  “下一层替换链接目标，已建立的硬链接保持旧内容”；
* **vendor/dataproc-repacked:amd64** 与 amd64 同内容，但第二层把
  白标记移到归档末尾（字节不同、digest 不同），归并结果必须一致；
* **vendor/hostile:traversal** 层内含 ``..`` 路径成员（必须拒绝）；
* **vendor/broken:{corrupt,zstd,hardlink}** 分别是损坏归档、
  不支持的压缩格式、不可解析硬链接（都必须拒绝并留诊断）。
"""

from __future__ import annotations

import gzip
import io
import tarfile
from dataclasses import dataclass

from ..digest import sha256_digest

# layer media type（与目录库登记值一致）
MEDIA_TAR = "application/vnd.oci.image.layer.v1.tar"
MEDIA_TAR_GZ = "application/vnd.oci.image.layer.v1.tar+gzip"
MEDIA_ZSTD = "application/vnd.oci.image.layer.v1.tar+zstd"

IMAGE_MEDIA = "application/vnd.oci.image.manifest.v1+json"
INDEX_MEDIA = "application/vnd.oci.image.index.v1+json"
CONFIG_DIGEST = "sha256:" + "cf" * 32

# ---------------------------------------------------------------------------
# 文件内容常量（验收脚本中手写同样字节做独立核对）
# ---------------------------------------------------------------------------
APP_CONF_V1 = b"[server]\nport=8080\nmode=base\n"
APP_CONF_V2 = b"[server]\nport=9090\nmode=v2\n"
APP_CONF_V3 = b"[server]\nport=9090\nmode=v3-final\n"
APP_CONF_ARM = b"[server]\nport=7070\narch=arm64\n"
REGISTRY_DAT = b"legacy-registry-v1\n"
LEGACY_OLD = b"old-legacy-content\n"
LEGACY_NEW = b"fresh-legacy\n"
DB_NOTES = b"db-notes\n"
MOTD_BASE = b"base motd\n"
MOTD_PATCHED = b"patched motd\n"
# 含非 UTF-8 字节的二进制文件（\xff \xfe \x89 都不是合法 UTF-8 序列）
BLOB_BIN = b"\xff\xfe\x00\x01BINARY\x89PNG\r\n\x00end"
README_V2 = b"readme-v2\n"
LOG_CURRENT = b"log-data-v1\n"
LOG_LATER = b"later-log-content\n"
ARM_TARGET_V1 = b"arm-target-v1\n"
ARM_TARGET_V2 = b"arm-target-v2\n"
ARM_ONLY = b"arm-specific\n"
HOSTILE_OK = b"ok\n"


# ---------------------------------------------------------------------------
# 成员规格 -> tar 字节
# ---------------------------------------------------------------------------
def f(path: str, content: bytes, mode: int = 0o644):
    return ("file", path, content, mode)


def d(path: str, mode: int = 0o755):
    return ("dir", path, mode)


def sym(path: str, target: str):
    return ("symlink", path, target)


def hard(path: str, target: str):
    return ("hardlink", path, target)


def wh(target_path: str):
    """白标记：删除低层 target_path。"""
    return ("whiteout", target_path)


def opq(dir_path: str):
    """不透明目录标记：遮蔽低层 dir_path 下的全部内容。"""
    return ("opaque", dir_path)


def tar_bytes(members: list, gzip_compress: bool) -> bytes:
    """把成员规格序列化成 tar（可选 gzip）。确定性输出（mtime=0）。"""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for spec in members:
            kind = spec[0]
            if kind == "file":
                _, path, content, mode = spec
                info = tarfile.TarInfo(path)
                info.size = len(content)
                info.mode = mode
                info.mtime = 0
                tf.addfile(info, io.BytesIO(content))
            elif kind == "dir":
                _, path, mode = spec
                info = tarfile.TarInfo(path)
                info.type = tarfile.DIRTYPE
                info.mode = mode
                info.mtime = 0
                tf.addfile(info)
            elif kind == "symlink":
                _, path, target = spec
                info = tarfile.TarInfo(path)
                info.type = tarfile.SYMTYPE
                info.linkname = target
                info.mode = 0o777
                info.mtime = 0
                tf.addfile(info)
            elif kind == "hardlink":
                _, path, target = spec
                info = tarfile.TarInfo(path)
                info.type = tarfile.LNKTYPE
                info.linkname = target
                info.mode = 0o644
                info.mtime = 0
                tf.addfile(info)
            elif kind == "whiteout":
                _, target = spec
                parent, _, base = target.rpartition("/")
                name = (parent + "/" if parent else "") + ".wh." + base
                info = tarfile.TarInfo(name)
                info.size = 0
                info.mode = 0o644
                info.mtime = 0
                tf.addfile(info, io.BytesIO(b""))
            elif kind == "opaque":
                _, dir_path = spec
                info = tarfile.TarInfo(dir_path + "/.wh..wh..opq")
                info.size = 0
                info.mode = 0o644
                info.mtime = 0
                tf.addfile(info, io.BytesIO(b""))
            else:  # pragma: no cover - 样例构造错误
                raise ValueError(f"未知成员规格: {spec!r}")
    raw = buf.getvalue()
    return gzip.compress(raw, mtime=0) if gzip_compress else raw


# ---------------------------------------------------------------------------
# 演示层集合
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class DemoLayer:
    """一层：本地归档字节 + media type（digest 由字节得出）。"""

    key: str
    media_type: str
    data: bytes

    @property
    def digest(self) -> str:
        return sha256_digest(self.data)

    @property
    def filename(self) -> str:
        suffix = ".tar.gz" if self.media_type == MEDIA_TAR_GZ else ".tar"
        if self.media_type not in (MEDIA_TAR, MEDIA_TAR_GZ):
            suffix = ".bin"
        return self.key + suffix


def build_demo_layers() -> dict[str, DemoLayer]:
    """构造全部演示层（键 -> DemoLayer）。"""
    layers: dict[str, DemoLayer] = {}

    def add(key: str, media_type: str, data: bytes) -> None:
        layers[key] = DemoLayer(key, media_type, data)

    # ---- amd64 三层 ----
    add("amd64-l1", MEDIA_TAR_GZ, tar_bytes([
        d("data"),
        f("data/app.conf", APP_CONF_V1),
        f("data/registry.dat", REGISTRY_DAT),          # L2 删除
        d("data/legacy"),
        f("data/legacy/old.txt", LEGACY_OLD),          # L2 不透明遮蔽
        f("database/notes.txt", DB_NOTES),             # /data 前缀边界对照
        f("etc/motd", MOTD_BASE),
        f("data/bin/blob.bin", BLOB_BIN),              # 非 UTF-8 字节
    ], gzip_compress=True))
    amd64_l2_members = [
        f("data/app.conf", APP_CONF_V2),               # 覆盖 v1
        wh("data/registry.dat"),                       # 删除
        opq("data/legacy"),                            # 不透明目录
        f("data/legacy/new.txt", LEGACY_NEW),          # 同层内容保留
        d("data/docs"),
        f("data/docs/readme.txt", README_V2),          # 新增
    ]
    add("amd64-l2", MEDIA_TAR_GZ, tar_bytes(amd64_l2_members,
                                            gzip_compress=True))
    # 同内容、白标记移到归档末尾：digest 不同，归并结果必须一致
    repacked_members = [m for m in amd64_l2_members
                        if m[0] not in ("whiteout", "opaque")]
    repacked_members += [m for m in amd64_l2_members
                         if m[0] in ("whiteout", "opaque")]
    add("amd64-l2-repacked", MEDIA_TAR_GZ, tar_bytes(repacked_members,
                                                     gzip_compress=True))
    add("amd64-l3", MEDIA_TAR, tar_bytes([             # 未压缩 tar
        f("data/app.conf", APP_CONF_V3),               # 最终生效版本
        f("etc/motd", MOTD_PATCHED),
        f("data/logs/current.log", LOG_CURRENT),
        hard("data/logs/alias.log", "data/logs/current.log"),
        # 前向硬链接：目标在同层靠后的成员中
        hard("data/logs/forward.log", "data/logs/later.log"),
        f("data/logs/later.log", LOG_LATER),
        # 复用低层（L2）文件的硬链接
        hard("data/docs/readme-copy.txt", "data/docs/readme.txt"),
        sym("data/latest", "docs/readme.txt"),
    ], gzip_compress=False))

    # ---- arm64 两层（不同生效内容 + 链接目标被下一层替换） ----
    add("arm64-l1", MEDIA_TAR_GZ, tar_bytes([
        d("data"),
        f("data/app.conf", APP_CONF_ARM),
        f("data/target.txt", ARM_TARGET_V1),
        hard("data/pinned.txt", "data/target.txt"),    # 链接在此建立
        f("data/arm-only.txt", ARM_ONLY),
    ], gzip_compress=True))
    add("arm64-l2", MEDIA_TAR_GZ, tar_bytes([
        f("data/target.txt", ARM_TARGET_V2),           # 替换链接目标
        wh("data/arm-only.txt"),                       # 删除
    ], gzip_compress=True))

    # ----  hostile / broken ----
    add("hostile-l1", MEDIA_TAR_GZ, tar_bytes([
        f("../escape.txt", b"must-not-land\n"),        # .. 路径：拒绝
        f("data/ok.txt", HOSTILE_OK),
    ], gzip_compress=True))
    add("broken-corrupt-l1", MEDIA_TAR_GZ,
        b"this is not a tar archive at all")           # 损坏归档
    add("broken-zstd-l1", MEDIA_ZSTD, tar_bytes([      # 不支持的压缩格式
        f("data/ok.txt", HOSTILE_OK),
    ], gzip_compress=False))
    add("broken-hardlink-l1", MEDIA_TAR_GZ, tar_bytes([
        hard("data/dangling.txt", "data/missing.txt"),  # 目标不存在
    ], gzip_compress=True))
    return layers


# 镜像 -> 层键（按 manifest 层序）
IMAGE_LAYER_KEYS = {
    "amd64": ["amd64-l1", "amd64-l2", "amd64-l3"],
    "arm64": ["arm64-l1", "arm64-l2"],
    "repacked": ["amd64-l1", "amd64-l2-repacked", "amd64-l3"],
    "hostile": ["hostile-l1"],
    "corrupt": ["broken-corrupt-l1"],
    "zstd": ["broken-zstd-l1"],
    "hardlink": ["broken-hardlink-l1"],
}

# 演示仓库布局：repo -> tag -> 镜像键（"index" 表示多平台索引）
REPO_LAYOUT = {
    "vendor/dataproc": {"amd64": "amd64", "arm64": "arm64",
                        "latest": "index"},
    "vendor/dataproc-repacked": {"amd64": "repacked"},
    "vendor/hostile": {"traversal": "hostile"},
    "vendor/broken": {"corrupt": "corrupt", "zstd": "zstd",
                      "hardlink": "hardlink"},
}

PLATFORMS = {
    "amd64": {"architecture": "amd64", "os": "linux"},
    "arm64": {"architecture": "arm64", "os": "linux", "variant": "v8"},
}


def image_manifest_dict(layers: list[DemoLayer]) -> dict:
    """按层序生成 image manifest（digest/size 取自真实归档字节）。"""
    return {
        "schemaVersion": 2,
        "mediaType": IMAGE_MEDIA,
        "config": {"mediaType":
                   "application/vnd.oci.image.config.v1+json",
                   "digest": CONFIG_DIGEST, "size": 2},
        "layers": [
            {"mediaType": layer.media_type, "digest": layer.digest,
             "size": len(layer.data)}
            for layer in layers
        ],
    }


def index_manifest_dict(child_digests: list[tuple[str, str]]) -> dict:
    """生成多平台索引；``child_digests`` 为 [(image_key, digest)]。"""
    return {
        "schemaVersion": 2,
        "mediaType": INDEX_MEDIA,
        "manifests": [
            {"mediaType": IMAGE_MEDIA, "digest": digest, "size": 1000,
             "platform": PLATFORMS[key]}
            for key, digest in child_digests
        ],
    }
