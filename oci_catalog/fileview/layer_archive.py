"""镜像层归档解析与层序归并（纯内存，不写任何存储）。

本模块是“镜像层文件视图”的数据接入边界：

* 输入是**本地归档文件的原始字节**与目录库中登记的 layer media type；
  不访问网络、不执行镜像中的任何代码、不写文件系统。
* 支持未压缩 tar 与 gzip tar；其他压缩格式（zstd 等）按
  ``unsupported_layer_media`` 诊断拒绝。
* 归档原始字节的 sha256 必须与 manifest 登记的 layer digest 一致，
  否则 ``digest_mismatch``。
* 成员路径归一化：拒绝 ``..``、绝对路径、空路径与非 UTF-8 名称
  （``unsafe_member_path``），绝不把成员写到视图树之外。

归并语义（overlay 规则，按 manifest 层序逐层应用）：

* 后一层的普通文件替换前层同路径内容；目录与非目录相互替换时，
  其子树随最终类型收敛（非目录没有子节点，目录替换非目录时
  原位置成为目录）。
* 白标记 ``.wh.<name>`` 删除低层同路径条目（含子树）；不透明目录标记
  ``.wh..wh..opq`` 遮蔽低层该目录下的全部内容。**只遮蔽低层**：
  同一层自己带来的内容保留，结果不取决于白标记在 tar 中的先后位置。
  白标记本身永远不会作为条目进入归并结果。
* 同一归档内归一后路径相同的多个成员：**归档中靠后的成员胜出**
  （与 tar 顺序解包语义一致），胜出成员在归档中的位置（member_index）
  随条目保留，可追溯判定依据。
* 硬链接目标可以出现在同层靠后的成员中，也可以复用低层文件；
  链接在归并时解析为目标内容的快照——后续层覆盖目标路径不影响
  已建立的链接。无法解析或成环的硬链接明确拒绝。
"""

from __future__ import annotations

import io
import tarfile
from dataclasses import dataclass
from typing import Optional

# ---------------------------------------------------------------------------
# 条目类型
# ---------------------------------------------------------------------------
ENTRY_FILE = "file"
ENTRY_DIR = "dir"
ENTRY_SYMLINK = "symlink"
ENTRY_HARDLINK = "hardlink"

ENTRY_TYPES = frozenset({ENTRY_FILE, ENTRY_DIR, ENTRY_SYMLINK, ENTRY_HARDLINK})

# ---------------------------------------------------------------------------
# layer media type -> 解包方式（按目录库中登记的 media type 解读，不嗅探）
# ---------------------------------------------------------------------------
LAYER_MEDIA_TAR = frozenset({
    "application/vnd.oci.image.layer.v1.tar",
    "application/vnd.docker.image.rootfs.diff.tar",
})
LAYER_MEDIA_TAR_GZ = frozenset({
    "application/vnd.oci.image.layer.v1.tar+gzip",
    "application/vnd.docker.image.rootfs.diff.tar.gzip",
})
SUPPORTED_LAYER_MEDIA = LAYER_MEDIA_TAR | LAYER_MEDIA_TAR_GZ

# 白标记命名（OCI image spec / overlayfs）
WHITEOUT_PREFIX = ".wh."
OPAQUE_MARKER = ".wh..wh..opq"

# 隐式目录（由文件路径推出来的中间目录）的默认模式
IMPLICIT_DIR_MODE = 0o755


# ---------------------------------------------------------------------------
# 诊断
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class ViewDiagnostic:
    """层接入/归并诊断：必须能定位到镜像与层。"""

    code: str
    message: str
    image_digest: str = ""
    layer_digest: str = ""
    member_name: str = ""

    def to_dict(self) -> dict:
        return {
            "code": self.code,
            "message": self.message,
            "image_digest": self.image_digest,
            "layer_digest": self.layer_digest,
            "member_name": self.member_name,
        }


# 诊断错误码
MISSING_LAYER_ARCHIVE = "missing_layer_archive"
UNREADABLE_ARCHIVE = "unreadable_archive"
DIGEST_MISMATCH = "digest_mismatch"
UNSUPPORTED_LAYER_MEDIA = "unsupported_layer_media"
CORRUPT_LAYER_ARCHIVE = "corrupt_layer_archive"
UNSAFE_MEMBER_PATH = "unsafe_member_path"
UNSUPPORTED_MEMBER_TYPE = "unsupported_member_type"
UNRESOLVABLE_HARDLINK = "unresolvable_hardlink"
CYCLIC_HARDLINK = "cyclic_hardlink"


class LayerIngestError(Exception):
    """单层接入失败：携带该层的全部诊断。"""

    def __init__(self, diagnostics: list[ViewDiagnostic]):
        self.diagnostics = diagnostics
        summary = "; ".join(d.message for d in diagnostics)
        super().__init__(summary)


# ---------------------------------------------------------------------------
# 路径归一化
# ---------------------------------------------------------------------------
class UnsafePathError(ValueError):
    """成员路径无法安全表示（..、绝对路径、空路径、非 UTF-8）。"""


def _has_surrogate(text: str) -> bool:
    return any(0xD800 <= ord(ch) <= 0xDFFF for ch in text)


def normalize_member_path(name: str) -> str:
    """把 tar 成员名归一成视图内绝对路径（``/a/b``）。

    规则：去掉前导 ``./`` 与重复斜杠；``.`` 段忽略；拒绝绝对路径、
    ``..`` 段、空结果与含代理区字符（非 UTF-8 字节被 tarfile 转义）的名称。
    """
    if not name:
        raise UnsafePathError("成员名为空")
    if _has_surrogate(name):
        raise UnsafePathError(f"成员名不是有效 UTF-8: {name!r}")
    if name.startswith("/"):
        raise UnsafePathError(f"绝对路径成员不允许: {name!r}")
    parts: list[str] = []
    for segment in name.split("/"):
        if segment in ("", "."):
            continue
        if segment == "..":
            raise UnsafePathError(f"成员路径含 '..' 段: {name!r}")
        parts.append(segment)
    if not parts:
        raise UnsafePathError(f"成员路径归一后为空: {name!r}")
    return "/" + "/".join(parts)


def parent_path(path: str) -> str:
    """归一路径的父目录（``/a/b`` -> ``/a``，``/a`` -> ``/``）。"""
    idx = path.rfind("/")
    return path[:idx] if idx > 0 else "/"


def base_name(path: str) -> str:
    return path[path.rfind("/") + 1:]


# ---------------------------------------------------------------------------
# 归档成员（解析结果）
# ---------------------------------------------------------------------------
@dataclass
class ArchiveMember:
    """单个 tar 成员的解析结果。"""

    index: int               # 在归档中的位置（0 起，按 tarfile 迭代顺序）
    name: str                # tar 中的原始成员名
    path: str                # 归一后的视图路径
    entry_type: str          # ENTRY_*
    mode: int
    size: int
    link_target: str = ""    # symlink：原始链接目标；hardlink：归一后的目标路径
    content: bytes = b""     # 仅普通文件


# tarfile 的元数据成员类型（不作为文件树条目）
_METADATA_TYPES = frozenset({
    tarfile.XHDTYPE, tarfile.XGLTYPE, tarfile.SOLARIS_XHDTYPE,
})


def parse_layer_archive(raw: bytes, media_type: str, image_digest: str,
                        layer_digest: str) -> list[ArchiveMember]:
    """按 media type 解读归档字节，返回成员列表（归档顺序）。

    任何解析问题都汇总为 :class:`LayerIngestError` 中的诊断，
    诊断携带镜像 digest、层 digest 与成员名。
    """
    def diag(code: str, message: str, member_name: str = "") -> ViewDiagnostic:
        return ViewDiagnostic(code, message, image_digest, layer_digest,
                              member_name)

    if media_type in LAYER_MEDIA_TAR:
        mode = "r:"
    elif media_type in LAYER_MEDIA_TAR_GZ:
        mode = "r:gz"
    else:
        raise LayerIngestError([diag(
            UNSUPPORTED_LAYER_MEDIA,
            f"不支持的 layer media type（仅支持 tar 与 tar+gzip）: "
            f"{media_type!r}")])

    members: list[ArchiveMember] = []
    try:
        with tarfile.open(fileobj=io.BytesIO(raw), mode=mode) as tf:
            for index, info in enumerate(tf):
                if info.type in _METADATA_TYPES:
                    continue  # pax 扩展头：tarfile 已应用到相邻成员
                members.append(_convert_member(index, info, tf, diag))
    except LayerIngestError:
        raise
    except (tarfile.TarError, EOFError, OSError, ValueError) as exc:
        raise LayerIngestError([diag(
            CORRUPT_LAYER_ARCHIVE,
            f"归档无法按 {media_type!r} 解读: {exc}")]) from exc
    return members


def _convert_member(index: int, info: tarfile.TarInfo, tf,
                    diag) -> ArchiveMember:
    """把 TarInfo 转成 ArchiveMember；路径/类型问题抛 LayerIngestError。"""
    try:
        path = normalize_member_path(info.name)
    except UnsafePathError as exc:
        raise LayerIngestError([diag(UNSAFE_MEMBER_PATH, str(exc),
                                     _safe_repr_name(info.name))]) from exc

    mode = info.mode & 0o7777
    if info.isreg():
        try:
            extracted = tf.extractfile(info)
            content = extracted.read() if extracted is not None else b""
        except (tarfile.TarError, EOFError, OSError) as exc:
            raise LayerIngestError([diag(
                CORRUPT_LAYER_ARCHIVE,
                f"成员内容读取失败: {exc}", info.name)]) from exc
        return ArchiveMember(index, info.name, path, ENTRY_FILE, mode,
                             len(content), content=content)
    if info.isdir():
        return ArchiveMember(index, info.name, path, ENTRY_DIR, mode, 0)
    if info.issym():
        link = info.linkname or ""
        if _has_surrogate(link):
            raise LayerIngestError([diag(
                UNSAFE_MEMBER_PATH,
                f"符号链接目标不是有效 UTF-8: {link!r}", info.name)])
        return ArchiveMember(index, info.name, path, ENTRY_SYMLINK, mode, 0,
                             link_target=link)
    if info.islnk():
        try:
            target = normalize_member_path(info.linkname or "")
        except UnsafePathError as exc:
            raise LayerIngestError([diag(
                UNSAFE_MEMBER_PATH,
                f"硬链接目标无法安全表示: {exc}", info.name)]) from exc
        return ArchiveMember(index, info.name, path, ENTRY_HARDLINK, mode, 0,
                             link_target=target)
    raise LayerIngestError([diag(
        UNSUPPORTED_MEMBER_TYPE,
        f"不支持的成员类型 type={info.type!r}（字符/块设备、FIFO 等"
        f"不进入文件视图）", info.name)])


def _safe_repr_name(name: str) -> str:
    """成员名含代理区字符时 SQLite 无法存储，诊断里用转义形式。"""
    return name.encode("utf-8", "backslashreplace").decode("ascii")


# ---------------------------------------------------------------------------
# 归并结果条目
# ---------------------------------------------------------------------------
@dataclass
class MergedEntry:
    """归并树中的一个条目（内存形态，由存储层落库）。"""

    path: str
    entry_type: str
    mode: int
    size: int
    layer_digest: str        # 最近改变该路径的层
    member_name: str         # 判定所依据的 tar 成员名
    member_index: int        # 该成员在其归档中的位置
    link_target: str = ""
    content: Optional[bytes] = None   # file/hardlink 的内容字节
    implicit: bool = False            # 隐式目录（由成员路径推出）

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "entry_type": self.entry_type,
            "mode": self.mode,
            "size": self.size,
            "layer_digest": self.layer_digest,
            "member_name": self.member_name,
            "member_index": self.member_index,
            "link_target": self.link_target,
            "implicit": self.implicit,
        }


# ---------------------------------------------------------------------------
# 层序归并
# ---------------------------------------------------------------------------
class TreeMerge:
    """按 manifest 层序把各层成员归并成最终文件树。

    用法：对每一层调用 :meth:`apply_layer`（顺序即 manifest layers 顺序），
    全部应用后 :attr:`entries` 就是最终视图。每层一个独立调用，
    同一层被多个镜像引用时各自走各自的层序，互不影响。
    """

    def __init__(self, image_digest: str = "") -> None:
        self.image_digest = image_digest
        self.entries: dict[str, MergedEntry] = {}

    # ------------------------------------------------------------------
    def apply_layer(self, layer_digest: str,
                    members: list[ArchiveMember]) -> None:
        """应用一层。成员顺序即归档顺序；白标记位置不影响结果。"""
        body: dict[str, ArchiveMember] = {}       # path -> 胜出成员（后者胜）
        whiteouts: list[str] = []                 # 待删除的低层目标路径
        opaques: list[tuple[str, ArchiveMember]] = []  # 不透明目录
        hardlinks: dict[str, ArchiveMember] = {}  # path -> 硬链接成员

        for member in members:
            base = base_name(member.path)
            if base == OPAQUE_MARKER:
                opaques.append((parent_path(member.path), member))
                continue
            if base.startswith(WHITEOUT_PREFIX):
                target_name = base[len(WHITEOUT_PREFIX):]
                if not target_name:
                    raise LayerIngestError([ViewDiagnostic(
                        UNSAFE_MEMBER_PATH,
                        f"白标记缺少目标名: {member.name!r}",
                        image_digest=self.image_digest,
                        layer_digest=layer_digest,
                        member_name=_safe_repr_name(member.name))])
                parent = parent_path(member.path)
                target = ("/" + target_name) if parent == "/" \
                    else parent + "/" + target_name
                whiteouts.append(target)
                continue
            if member.entry_type == ENTRY_HARDLINK:
                hardlinks[member.path] = member
                continue
            # 同层归一路径重复：归档中靠后的成员胜出（dict 覆盖即后者胜）
            body[member.path] = member

        # 1. 白标记只作用于低层状态（此时 self.entries 尚未应用本层内容）
        for target in whiteouts:
            self._remove_subtree(target)
        # 2. 不透明目录：遮蔽低层该目录下的全部内容，目录本身保留
        for dir_path, marker in opaques:
            self._apply_opaque(dir_path, layer_digest, marker)
        # 3. 应用本层常规条目（按归档位置排序，保证行为确定）
        for path in sorted(body, key=lambda p: body[p].index):
            self._apply_member(body[path], layer_digest)
        # 4. 硬链接最后解析：目标可能在同层靠后的成员中，也可能在低层
        for path in sorted(hardlinks, key=lambda p: hardlinks[p].index):
            self._apply_hardlink(hardlinks[path], layer_digest, hardlinks)

    # ------------------------------------------------------------------
    # 白标记 / 不透明目录
    # ------------------------------------------------------------------
    def _remove_subtree(self, path: str) -> None:
        """删除路径及其全部后代（不存在则为空操作）。"""
        prefix = path + "/"
        for key in [k for k in self.entries
                    if k == path or k.startswith(prefix)]:
            del self.entries[key]

    def _apply_opaque(self, dir_path: str, layer_digest: str,
                      marker: ArchiveMember) -> None:
        """遮蔽低层该目录下的全部内容；目录本身保留（不存在则建隐式目录）。"""
        prefix = dir_path + "/" if dir_path != "/" else "/"
        for key in [k for k in self.entries if k.startswith(prefix)]:
            del self.entries[key]
        if dir_path != "/" and dir_path not in self.entries:
            self._ensure_dir(dir_path, layer_digest, marker)

    # ------------------------------------------------------------------
    # 常规条目
    # ------------------------------------------------------------------
    def _apply_member(self, member: ArchiveMember,
                      layer_digest: str) -> None:
        self._ensure_parents(member.path, layer_digest, member)
        existing = self.entries.get(member.path)
        if existing is not None and existing.entry_type == ENTRY_DIR \
                and member.entry_type != ENTRY_DIR:
            # 目录被非目录替换：子树随最终类型收敛
            self._remove_subtree(member.path)
        entry = MergedEntry(
            path=member.path,
            entry_type=member.entry_type,
            mode=member.mode,
            size=member.size,
            layer_digest=layer_digest,
            member_name=member.name,
            member_index=member.index,
            link_target=member.link_target,
            content=member.content if member.entry_type == ENTRY_FILE else None,
        )
        self.entries[member.path] = entry

    def _ensure_parents(self, path: str, layer_digest: str,
                        member: ArchiveMember) -> None:
        """补齐路径的全部祖先目录；祖先位置的非目录被隐式目录替换。"""
        ancestors: list[str] = []
        cursor = parent_path(path)
        while cursor and cursor != "/":
            ancestors.append(cursor)
            cursor = parent_path(cursor)
        for ancestor in reversed(ancestors):  # 自顶向下
            existing = self.entries.get(ancestor)
            if existing is None:
                self.entries[ancestor] = self._implicit_dir(
                    ancestor, layer_digest, member)
            elif existing.entry_type != ENTRY_DIR:
                # 非目录（含符号链接）被路径穿越：替换为目录，不跟随链接
                self.entries[ancestor] = self._implicit_dir(
                    ancestor, layer_digest, member)

    def _ensure_dir(self, path: str, layer_digest: str,
                    member: ArchiveMember) -> None:
        """确保 path 是目录（不透明标记的父目录）。"""
        self._ensure_parents(path, layer_digest, member)
        existing = self.entries.get(path)
        if existing is None or existing.entry_type != ENTRY_DIR:
            self.entries[path] = self._implicit_dir(path, layer_digest, member)

    @staticmethod
    def _implicit_dir(path: str, layer_digest: str,
                      member: ArchiveMember) -> MergedEntry:
        return MergedEntry(
            path=path, entry_type=ENTRY_DIR, mode=IMPLICIT_DIR_MODE, size=0,
            layer_digest=layer_digest, member_name=member.name,
            member_index=member.index, implicit=True)

    # ------------------------------------------------------------------
    # 硬链接
    # ------------------------------------------------------------------
    def _apply_hardlink(self, member: ArchiveMember, layer_digest: str,
                        hardlinks: dict[str, ArchiveMember]) -> None:
        """解析并应用一个硬链接成员。

        目标查找顺序：同层常规条目（已应用）-> 同层硬链接（递归）-> 低层树。
        解析结果是内容快照：目标路径日后被覆盖不影响本链接。
        """
        target = self._resolve_hardlink(member.link_target, layer_digest,
                                        member, hardlinks, visiting=set())
        self._ensure_parents(member.path, layer_digest, member)
        existing = self.entries.get(member.path)
        if existing is not None and existing.entry_type == ENTRY_DIR:
            self._remove_subtree(member.path)
        if target.entry_type == ENTRY_SYMLINK:
            # 硬链接指向符号链接：复刻链接本身（与文件系统语义一致）
            entry = MergedEntry(
                path=member.path, entry_type=ENTRY_SYMLINK, mode=member.mode,
                size=0, layer_digest=layer_digest, member_name=member.name,
                member_index=member.index, link_target=target.link_target)
        else:
            content = target.content if target.content is not None else b""
            entry = MergedEntry(
                path=member.path, entry_type=ENTRY_HARDLINK, mode=member.mode,
                size=len(content), layer_digest=layer_digest,
                member_name=member.name, member_index=member.index,
                link_target=member.link_target, content=content)
        self.entries[member.path] = entry

    def _resolve_hardlink(self, target_path: str, layer_digest: str,
                          member: ArchiveMember,
                          hardlinks: dict[str, ArchiveMember],
                          visiting: set[str]) -> MergedEntry:
        """把硬链接目标解析为文件/符号链接条目；失败抛 LayerIngestError。"""
        def reject(code: str, message: str) -> LayerIngestError:
            return LayerIngestError([ViewDiagnostic(
                code, message, image_digest=self.image_digest,
                layer_digest=layer_digest,
                member_name=_safe_repr_name(member.name))])

        if target_path in visiting:
            raise reject(CYCLIC_HARDLINK,
                         f"硬链接成环（经由 {target_path} 回到自身）")
        # 同层硬链接目标：递归解析（允许目标在同层靠后的成员中）
        chained = hardlinks.get(target_path)
        if chained is not None:
            visiting.add(target_path)
            return self._resolve_hardlink(chained.link_target, layer_digest,
                                          member, hardlinks, visiting)
        target = self.entries.get(target_path)
        if target is None:
            raise reject(UNRESOLVABLE_HARDLINK,
                         f"硬链接目标不存在: {target_path}")
        if target.entry_type == ENTRY_DIR:
            raise reject(UNRESOLVABLE_HARDLINK,
                         f"硬链接目标是目录: {target_path}")
        return target
