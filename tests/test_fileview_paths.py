"""成员路径与查询路径安全：..、绝对路径、非 UTF-8、危险成员类型。"""

import io
import tarfile
import unittest

from fileview_fixtures import MEDIA_TAR, MEDIA_TAR_GZ, f, tar_bytes
from oci_catalog.fileview.layer_archive import (
    CORRUPT_LAYER_ARCHIVE,
    UNSAFE_MEMBER_PATH,
    UNSUPPORTED_LAYER_MEDIA,
    UNSUPPORTED_MEMBER_TYPE,
    LayerIngestError,
    TreeMerge,
    normalize_member_path,
    parse_layer_archive,
)
from oci_catalog.fileview.fileview_queries import (
    ViewPathError,
    normalize_query_path,
)

L1 = "sha256:" + "11" * 32


def parse(members, media=MEDIA_TAR):
    raw = tar_bytes(members, gzip_compress=(media == MEDIA_TAR_GZ))
    return parse_layer_archive(raw, media, "img", L1)


class TestMemberPathNormalization(unittest.TestCase):

    def test_dot_and_duplicate_slashes_stripped(self):
        self.assertEqual(normalize_member_path("./a//b/./c.txt"), "/a/b/c.txt")

    def test_parent_reference_rejected(self):
        for name in ("../x", "a/../../x", "a/../b"):
            with self.assertRaises(ValueError):
                normalize_member_path(name)

    def test_absolute_path_rejected(self):
        with self.assertRaises(ValueError):
            normalize_member_path("/etc/passwd")

    def test_empty_and_root_rejected(self):
        for name in ("", ".", "./", "/"):
            with self.assertRaises(ValueError):
                normalize_member_path(name)

    def test_non_utf8_name_rejected(self):
        with self.assertRaises(ValueError):
            normalize_member_path("bad\udcff.txt")


class TestArchiveMemberSafety(unittest.TestCase):

    def _unsafe(self, members):
        with self.assertRaises(LayerIngestError) as ctx:
            parse(members)
        self.assertEqual(ctx.exception.diagnostics[0].code,
                         UNSAFE_MEMBER_PATH)
        return ctx.exception.diagnostics[0]

    def test_dotdot_member_rejected(self):
        diag = self._unsafe([f("../escape.txt", b"x")])
        self.assertEqual(diag.layer_digest, L1)

    def test_absolute_member_rejected(self):
        self._unsafe([f("/abs.txt", b"x")])

    def test_nested_dotdot_member_rejected(self):
        self._unsafe([f("a/../../escape.txt", b"x")])

    def test_non_utf8_member_name_rejected(self):
        # 构造含原始非 UTF-8 字节名的 tar 成员
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tf:
            info = tarfile.TarInfo(b"bad-\xff.txt".decode(
                "utf-8", "surrogateescape"))
            info.size = 1
            tf.addfile(info, io.BytesIO(b"x"))
        with self.assertRaises(LayerIngestError) as ctx:
            parse_layer_archive(buf.getvalue(), MEDIA_TAR, "img", L1)
        self.assertEqual(ctx.exception.diagnostics[0].code,
                         UNSAFE_MEMBER_PATH)

    def test_hardlink_target_with_dotdot_rejected(self):
        from fileview_fixtures import hard
        self._unsafe([f("a/ok.txt", b"x"), hard("a/l", "../escape")])

    def test_whiteout_without_target_rejected(self):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tf:
            info = tarfile.TarInfo("a/.wh.")
            info.size = 0
            tf.addfile(info, io.BytesIO(b""))
        merge = TreeMerge("img")
        members = parse_layer_archive(buf.getvalue(), MEDIA_TAR, "img", L1)
        with self.assertRaises(LayerIngestError) as ctx:
            merge.apply_layer(L1, members)
        self.assertEqual(ctx.exception.diagnostics[0].code,
                         UNSAFE_MEMBER_PATH)

    def test_device_and_fifo_members_rejected(self):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tf:
            info = tarfile.TarInfo("dev/null")
            info.type = tarfile.CHRTYPE
            info.devmajor, info.devminor = 1, 3
            tf.addfile(info)
        with self.assertRaises(LayerIngestError) as ctx:
            parse_layer_archive(buf.getvalue(), MEDIA_TAR, "img", L1)
        self.assertEqual(ctx.exception.diagnostics[0].code,
                         UNSUPPORTED_MEMBER_TYPE)


class TestArchiveFormats(unittest.TestCase):

    def test_unsupported_media_type(self):
        raw = tar_bytes([f("a.txt", b"x")], gzip_compress=False)
        with self.assertRaises(LayerIngestError) as ctx:
            parse_layer_archive(
                raw, "application/vnd.oci.image.layer.v1.tar+zstd",
                "img", L1)
        diag = ctx.exception.diagnostics[0]
        self.assertEqual(diag.code, UNSUPPORTED_LAYER_MEDIA)
        self.assertEqual(diag.layer_digest, L1)

    def test_corrupt_gzip_rejected(self):
        with self.assertRaises(LayerIngestError) as ctx:
            parse_layer_archive(b"not a gzip stream", MEDIA_TAR_GZ, "img", L1)
        self.assertEqual(ctx.exception.diagnostics[0].code,
                         CORRUPT_LAYER_ARCHIVE)

    def test_gzip_bytes_as_plain_tar_rejected(self):
        raw = tar_bytes([f("a.txt", b"x")], gzip_compress=True)
        with self.assertRaises(LayerIngestError) as ctx:
            parse_layer_archive(raw, MEDIA_TAR, "img", L1)
        self.assertEqual(ctx.exception.diagnostics[0].code,
                         CORRUPT_LAYER_ARCHIVE)

    def test_truncated_tar_rejected(self):
        raw = tar_bytes([f("a.txt", b"x" * 100)], gzip_compress=False)
        with self.assertRaises(LayerIngestError) as ctx:
            parse_layer_archive(raw[:200], MEDIA_TAR, "img", L1)
        self.assertEqual(ctx.exception.diagnostics[0].code,
                         CORRUPT_LAYER_ARCHIVE)


class TestQueryPathNormalization(unittest.TestCase):

    def test_root_and_normalization(self):
        self.assertEqual(normalize_query_path("/"), "/")
        self.assertEqual(normalize_query_path("/data//logs/"), "/data/logs")
        self.assertEqual(normalize_query_path("/a/./b"), "/a/b")

    def test_relative_query_rejected(self):
        with self.assertRaises(ViewPathError):
            normalize_query_path("data/logs")

    def test_dotdot_query_rejected(self):
        with self.assertRaises(ViewPathError):
            normalize_query_path("/data/../etc/passwd")


if __name__ == "__main__":
    unittest.main()
