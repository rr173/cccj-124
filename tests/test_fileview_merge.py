"""层序归并语义：覆盖、类型替换、白标记、不透明目录、同层重复成员。"""

import unittest

from fileview_fixtures import MEDIA_TAR, MEDIA_TAR_GZ, d, f, hard, opq, sym, \
    tar_bytes, wh
from oci_catalog.fileview.layer_archive import (
    ENTRY_DIR,
    ENTRY_FILE,
    ENTRY_HARDLINK,
    ENTRY_SYMLINK,
    TreeMerge,
    parse_layer_archive,
)


def merge_layers(specs):
    """specs: [(members, media_type, layer_digest), ...] -> TreeMerge"""
    merge = TreeMerge("sha256:" + "aa" * 32)
    for members, media, digest in specs:
        raw = tar_bytes(members, gzip_compress=(media == MEDIA_TAR_GZ))
        parsed = parse_layer_archive(raw, media, "img", digest)
        merge.apply_layer(digest, parsed)
    return merge


L1 = "sha256:" + "11" * 32
L2 = "sha256:" + "22" * 32
L3 = "sha256:" + "33" * 32


class TestLayerOverlay(unittest.TestCase):

    def test_later_layer_file_replaces_earlier(self):
        merge = merge_layers([
            ([f("a/x.txt", b"v1")], MEDIA_TAR, L1),
            ([f("a/x.txt", b"v2-longer")], MEDIA_TAR, L2),
        ])
        entry = merge.entries["/a/x.txt"]
        self.assertEqual(entry.content, b"v2-longer")
        self.assertEqual(entry.layer_digest, L2)
        self.assertEqual(entry.size, len(b"v2-longer"))

    def test_dir_replaced_by_file_drops_subtree(self):
        merge = merge_layers([
            ([d("a"), f("a/inner/x.txt", b"x"), f("a/y.txt", b"y")],
             MEDIA_TAR, L1),
            ([f("a", b"now-a-file")], MEDIA_TAR, L2),
        ])
        self.assertEqual(merge.entries["/a"].entry_type, ENTRY_FILE)
        self.assertNotIn("/a/inner/x.txt", merge.entries)
        self.assertNotIn("/a/inner", merge.entries)
        self.assertNotIn("/a/y.txt", merge.entries)

    def test_file_replaced_by_dir_via_child(self):
        merge = merge_layers([
            ([f("a", b"was-a-file")], MEDIA_TAR, L1),
            ([f("a/b/c.txt", b"deep")], MEDIA_TAR, L2),
        ])
        self.assertEqual(merge.entries["/a"].entry_type, ENTRY_DIR)
        self.assertTrue(merge.entries["/a"].implicit)
        self.assertEqual(merge.entries["/a/b"].entry_type, ENTRY_DIR)
        self.assertEqual(merge.entries["/a/b/c.txt"].content, b"deep")

    def test_explicit_dir_updates_implicit_mode_and_layer(self):
        merge = merge_layers([
            ([f("a/x.txt", b"x")], MEDIA_TAR, L1),
            ([d("a", 0o700)], MEDIA_TAR, L2),
        ])
        entry = merge.entries["/a"]
        self.assertFalse(entry.implicit)
        self.assertEqual(entry.mode, 0o700)
        self.assertEqual(entry.layer_digest, L2)
        # 显式目录替换不丢孩子
        self.assertIn("/a/x.txt", merge.entries)

    def test_symlink_replaced_by_child_path_becomes_dir(self):
        merge = merge_layers([
            ([sym("link", "/etc")], MEDIA_TAR, L1),
            ([f("link/real.txt", b"real")], MEDIA_TAR, L2),
        ])
        # 不跟随符号链接：上层在链接位置建目录，而不是写到 /etc
        self.assertEqual(merge.entries["/link"].entry_type, ENTRY_DIR)
        self.assertEqual(merge.entries["/link/real.txt"].content, b"real")
        self.assertNotIn("/etc", merge.entries)


class TestWhiteouts(unittest.TestCase):

    def test_whiteout_deletes_lower_file(self):
        merge = merge_layers([
            ([f("a/gone.txt", b"x"), f("a/kept.txt", b"y")], MEDIA_TAR, L1),
            ([wh("a/gone.txt")], MEDIA_TAR, L2),
        ])
        self.assertNotIn("/a/gone.txt", merge.entries)
        self.assertIn("/a/kept.txt", merge.entries)

    def test_whiteout_marker_never_exported(self):
        merge = merge_layers([
            ([f("a/gone.txt", b"x")], MEDIA_TAR, L1),
            ([wh("a/gone.txt"), opq("a")], MEDIA_TAR, L2),
        ])
        for path in merge.entries:
            self.assertNotIn(".wh.", path)

    def test_whiteout_of_missing_path_is_noop(self):
        merge = merge_layers([
            ([wh("a/never-existed.txt"), f("a/x.txt", b"x")], MEDIA_TAR, L1),
        ])
        self.assertEqual(merge.entries["/a/x.txt"].content, b"x")

    def test_whiteout_deletes_whole_subtree(self):
        merge = merge_layers([
            ([d("a"), f("a/b/c.txt", b"c"), f("a/b/d.txt", b"d")],
             MEDIA_TAR, L1),
            ([wh("a/b")], MEDIA_TAR, L2),
        ])
        self.assertNotIn("/a/b", merge.entries)
        self.assertNotIn("/a/b/c.txt", merge.entries)
        self.assertIn("/a", merge.entries)

    def test_whiteout_only_shadows_lower_same_layer_content_stays(self):
        # 白标记与重建内容同层：无论标记写在前还是后，结果一致
        lower = ([f("a/x.txt", b"lower")], MEDIA_TAR, L1)
        first = merge_layers([
            lower,
            ([wh("a/x.txt"), f("a/x.txt", b"upper")], MEDIA_TAR, L2),
        ])
        last = merge_layers([
            lower,
            ([f("a/x.txt", b"upper"), wh("a/x.txt")], MEDIA_TAR, L2),
        ])
        for merge in (first, last):
            entry = merge.entries["/a/x.txt"]
            self.assertEqual(entry.content, b"upper")
            self.assertEqual(entry.layer_digest, L2)

    def test_opaque_dir_hides_lower_children_keeps_same_layer(self):
        merge = merge_layers([
            ([d("a"), f("a/old1.txt", b"1"), f("a/sub/old2.txt", b"2"),
              f("a/keep-dir/x.txt", b"x")], MEDIA_TAR, L1),
            ([opq("a"), f("a/new.txt", b"new")], MEDIA_TAR, L2),
        ])
        self.assertNotIn("/a/old1.txt", merge.entries)
        self.assertNotIn("/a/sub", merge.entries)
        self.assertNotIn("/a/keep-dir/x.txt", merge.entries)
        self.assertEqual(merge.entries["/a/new.txt"].content, b"new")
        self.assertIn("/a", merge.entries)  # 目录本身保留

    def test_opaque_dir_order_independent(self):
        lower = ([d("a"), f("a/old.txt", b"old")], MEDIA_TAR, L1)
        first = merge_layers([
            lower, ([opq("a"), f("a/new.txt", b"n")], MEDIA_TAR, L2)])
        last = merge_layers([
            lower, ([f("a/new.txt", b"n"), opq("a")], MEDIA_TAR, L2)])
        self.assertEqual(set(first.entries), set(last.entries))
        self.assertEqual(first.entries["/a/new.txt"].content, b"n")

    def test_opaque_on_file_position_turns_it_into_dir(self):
        merge = merge_layers([
            ([f("a", b"was-file"), f("a-other.txt", b"o")], MEDIA_TAR, L1),
            ([opq("a"), f("a/x.txt", b"x")], MEDIA_TAR, L2),
        ])
        self.assertEqual(merge.entries["/a"].entry_type, ENTRY_DIR)
        self.assertEqual(merge.entries["/a/x.txt"].content, b"x")


class TestDuplicateMembers(unittest.TestCase):

    def test_same_normalized_path_later_member_wins(self):
        # "a/x.txt"、"./a/x.txt"、"a//x.txt" 归一后同路径：归档中靠后者胜
        merge = merge_layers([
            ([f("a/x.txt", b"first"), f("./a/x.txt", b"second"),
              f("a//x.txt", b"third")], MEDIA_TAR, L1),
        ])
        entry = merge.entries["/a/x.txt"]
        self.assertEqual(entry.content, b"third")
        # 判定所依据的归档成员位置被保留
        self.assertEqual(entry.member_index, 2)
        self.assertEqual(entry.member_name, "a//x.txt")

    def test_dir_then_file_same_path_in_one_layer(self):
        merge = merge_layers([
            ([d("a/x"), f("a/x", b"file-wins")], MEDIA_TAR, L1),
        ])
        self.assertEqual(merge.entries["/a/x"].entry_type, ENTRY_FILE)


class TestHardlinks(unittest.TestCase):

    def test_same_layer_target_earlier(self):
        merge = merge_layers([
            ([f("a/src.txt", b"data"), hard("a/link.txt", "a/src.txt")],
             MEDIA_TAR, L1),
        ])
        link = merge.entries["/a/link.txt"]
        self.assertEqual(link.entry_type, ENTRY_HARDLINK)
        self.assertEqual(link.content, b"data")
        self.assertEqual(link.link_target, "/a/src.txt")

    def test_forward_hardlink_target_later_in_same_layer(self):
        merge = merge_layers([
            ([hard("a/link.txt", "a/src.txt"), f("a/src.txt", b"data")],
             MEDIA_TAR, L1),
        ])
        self.assertEqual(merge.entries["/a/link.txt"].content, b"data")

    def test_hardlink_reuses_lower_layer_file(self):
        merge = merge_layers([
            ([f("a/src.txt", b"lower-data")], MEDIA_TAR, L1),
            ([hard("b/link.txt", "a/src.txt")], MEDIA_TAR, L2),
        ])
        link = merge.entries["/b/link.txt"]
        self.assertEqual(link.content, b"lower-data")
        self.assertEqual(link.layer_digest, L2)

    def test_hardlink_chain_resolves_transitively(self):
        merge = merge_layers([
            ([f("a/f.txt", b"payload"), hard("a/l1", "a/f.txt"),
              hard("a/l2", "a/l1")], MEDIA_TAR, L1),
        ])
        self.assertEqual(merge.entries["/a/l2"].content, b"payload")

    def test_hardlink_snapshot_survives_later_target_overwrite(self):
        merge = merge_layers([
            ([f("a/src.txt", b"v1"), hard("a/pinned.txt", "a/src.txt")],
             MEDIA_TAR, L1),
            ([f("a/src.txt", b"v2")], MEDIA_TAR, L2),
        ])
        self.assertEqual(merge.entries["/a/src.txt"].content, b"v2")
        self.assertEqual(merge.entries["/a/pinned.txt"].content, b"v1")

    def test_cyclic_hardlink_rejected(self):
        from oci_catalog.fileview.layer_archive import (
            CYCLIC_HARDLINK, LayerIngestError)
        with self.assertRaises(LayerIngestError) as ctx:
            merge_layers([
                ([hard("a/l1", "a/l2"), hard("a/l2", "a/l1")],
                 MEDIA_TAR, L1),
            ])
        self.assertEqual(ctx.exception.diagnostics[0].code, CYCLIC_HARDLINK)

    def test_unresolvable_hardlink_rejected(self):
        from oci_catalog.fileview.layer_archive import (
            UNRESOLVABLE_HARDLINK, LayerIngestError)
        with self.assertRaises(LayerIngestError) as ctx:
            merge_layers([([hard("a/l", "a/ghost")], MEDIA_TAR, L1)])
        self.assertEqual(ctx.exception.diagnostics[0].code,
                         UNRESOLVABLE_HARDLINK)

    def test_hardlink_to_directory_rejected(self):
        from oci_catalog.fileview.layer_archive import (
            UNRESOLVABLE_HARDLINK, LayerIngestError)
        with self.assertRaises(LayerIngestError) as ctx:
            merge_layers([([d("a/dir"), hard("a/l", "a/dir")], MEDIA_TAR, L1)])
        self.assertEqual(ctx.exception.diagnostics[0].code,
                         UNRESOLVABLE_HARDLINK)

    def test_hardlink_to_symlink_replicates_link(self):
        merge = merge_layers([
            ([sym("a/s", "target/x"), hard("a/l", "a/s")], MEDIA_TAR, L1),
        ])
        link = merge.entries["/a/l"]
        self.assertEqual(link.entry_type, ENTRY_SYMLINK)
        self.assertEqual(link.link_target, "target/x")

    def test_whiteout_of_lower_target_makes_hardlink_unresolvable(self):
        from oci_catalog.fileview.layer_archive import (
            UNRESOLVABLE_HARDLINK, LayerIngestError)
        with self.assertRaises(LayerIngestError) as ctx:
            merge_layers([
                ([f("a/src.txt", b"v1")], MEDIA_TAR, L1),
                ([wh("a/src.txt"), hard("a/l", "a/src.txt")], MEDIA_TAR, L2),
            ])
        self.assertEqual(ctx.exception.diagnostics[0].code,
                         UNRESOLVABLE_HARDLINK)


class TestEntryMetadata(unittest.TestCase):

    def test_attribution_fields_present(self):
        merge = merge_layers([
            ([d("a", 0o750), f("a/x.txt", b"hello", 0o600)], MEDIA_TAR, L1),
        ])
        entry = merge.entries["/a/x.txt"]
        self.assertEqual((entry.entry_type, entry.size, entry.mode),
                         (ENTRY_FILE, 5, 0o600))
        self.assertEqual(entry.layer_digest, L1)
        self.assertEqual(entry.member_name, "a/x.txt")
        self.assertEqual(entry.member_index, 1)
        dir_entry = merge.entries["/a"]
        self.assertEqual((dir_entry.mode, dir_entry.implicit), (0o750, False))

    def test_gzip_and_plain_tar_both_supported(self):
        merge = merge_layers([
            ([f("a.gz.txt", b"gz")], MEDIA_TAR_GZ, L1),
            ([f("b.tar.txt", b"plain")], MEDIA_TAR, L2),
        ])
        self.assertEqual(merge.entries["/a.gz.txt"].content, b"gz")
        self.assertEqual(merge.entries["/b.tar.txt"].content, b"plain")


if __name__ == "__main__":
    unittest.main()
