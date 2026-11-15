"""文件视图查询：前缀边界、符号链接安全、原始字节、错误语义。"""

import unittest

from fileview_fixtures import FileViewFixture, d, f, hard, sym, tar_bytes, wh
from oci_catalog.fileview.fileview_queries import (
    UnknownViewError,
    ViewPathError,
    list_tree,
    read_file_bytes,
    stat_path,
)
from oci_catalog.fileview.sample_layers import MEDIA_TAR_GZ

BLOB = b"\xff\xfe\x00\x01binary\x89\x00"


class QueryFixture(FileViewFixture):

    def setUp(self):
        super().setUp()
        layers = [
            (tar_bytes([
                d("data"),
                f("data/app.conf", b"conf-v1"),
                f("data/bin/blob.bin", BLOB),
                f("database/notes.txt", b"db"),
                f("data/docs/readme.txt", b"readme"),
                sym("data/latest", "docs/readme.txt"),
            ], gzip_compress=True), MEDIA_TAR_GZ),
            (tar_bytes([
                f("data/app.conf", b"conf-v2"),
                hard("data/docs/copy.txt", "data/docs/readme.txt"),
                wh("database/notes.txt"),
            ], gzip_compress=True), MEDIA_TAR_GZ),
        ]
        self.layer_digests = []
        from oci_catalog.digest import sha256_digest
        for data, _ in layers:
            self.layer_digests.append(sha256_digest(data))
        self.image, self.mapping = self.add_image_with_files(layers)
        result = self.store.build_view(self.image, self.mapping)
        assert result.ok, result.to_dict()


class TestListTree(QueryFixture):

    def test_prefix_segment_boundary(self):
        listing = list_tree(self.store, self.image, "/data")
        paths = {e["path"] for e in listing["entries"]}
        self.assertIn("/data/app.conf", paths)
        self.assertNotIn("/database", paths)
        self.assertNotIn("/database/notes.txt", paths)

    def test_deleted_path_absent(self):
        listing = list_tree(self.store, self.image, "/")
        paths = {e["path"] for e in listing["entries"]}
        self.assertNotIn("/database/notes.txt", paths)
        self.assertIn("/database", paths)  # 隐式目录仍在（由 L1 成员推出）

    def test_root_lists_everything(self):
        listing = list_tree(self.store, self.image, "/")
        paths = {e["path"] for e in listing["entries"]}
        self.assertIn("/data", paths)
        self.assertIn("/database", paths)

    def test_entries_carry_type_layer_member(self):
        listing = list_tree(self.store, self.image, "/data")
        by_path = {e["path"]: e for e in listing["entries"]}
        app = by_path["/data/app.conf"]
        self.assertEqual(app["entry_type"], "file")
        self.assertEqual(app["layer_digest"], self.layer_digests[1])
        self.assertEqual(app["member_name"], "data/app.conf")
        self.assertEqual(app["size"], len(b"conf-v2"))
        link = by_path["/data/latest"]
        self.assertEqual(link["entry_type"], "symlink")
        self.assertEqual(link["link_target"], "docs/readme.txt")
        hl = by_path["/data/docs/copy.txt"]
        self.assertEqual(hl["entry_type"], "hardlink")
        self.assertEqual(hl["link_target"], "/data/docs/readme.txt")

    def test_missing_prefix_raises(self):
        with self.assertRaises(ViewPathError):
            list_tree(self.store, self.image, "/no-such-dir")

    def test_unknown_image_raises(self):
        with self.assertRaises(UnknownViewError):
            list_tree(self.store, "sha256:" + "9f" * 32, "/")

    def test_prefix_with_dotdot_rejected(self):
        with self.assertRaises(ViewPathError):
            list_tree(self.store, self.image, "/data/../database")


class TestStatPath(QueryFixture):

    def test_stat_reports_origin_layer(self):
        entry = stat_path(self.store, self.image, "/data/app.conf")["entry"]
        self.assertEqual(entry["layer_digest"], self.layer_digests[1])
        self.assertEqual(entry["entry_type"], "file")

    def test_stat_symlink_link_info_only(self):
        entry = stat_path(self.store, self.image, "/data/latest")["entry"]
        self.assertEqual(entry["entry_type"], "symlink")
        self.assertEqual(entry["link_target"], "docs/readme.txt")

    def test_stat_missing_path(self):
        with self.assertRaises(ViewPathError):
            stat_path(self.store, self.image, "/data/ghost.txt")


class TestReadFileBytes(QueryFixture):

    def test_exact_bytes_roundtrip(self):
        data = read_file_bytes(self.store, self.image, "/data/bin/blob.bin")
        self.assertIsInstance(data, bytes)
        self.assertEqual(data, BLOB)

    def test_hardlink_bytes(self):
        self.assertEqual(
            read_file_bytes(self.store, self.image, "/data/docs/copy.txt"),
            b"readme")

    def test_symlink_not_followed(self):
        with self.assertRaises(ViewPathError) as ctx:
            read_file_bytes(self.store, self.image, "/data/latest")
        self.assertIn("符号链接", str(ctx.exception))

    def test_path_through_symlink_rejected(self):
        with self.assertRaises(ViewPathError) as ctx:
            read_file_bytes(self.store, self.image,
                            "/data/latest/readme.txt")
        self.assertIn("符号链接", str(ctx.exception))

    def test_directory_has_no_bytes(self):
        with self.assertRaises(ViewPathError):
            read_file_bytes(self.store, self.image, "/data")

    def test_missing_path(self):
        with self.assertRaises(ViewPathError):
            read_file_bytes(self.store, self.image, "/data/ghost")


if __name__ == "__main__":
    unittest.main()
