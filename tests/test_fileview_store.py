"""文件视图存储：绑定校验、单镜像事务、失败无残留、逐镜像层序。"""

import json
import unittest

from fileview_fixtures import (
    MEDIA_TAR,
    MEDIA_TAR_GZ,
    FileViewFixture,
    d,
    f,
    tar_bytes,
    wh,
)
from oci_catalog.digest import sha256_digest
from oci_catalog.fileview.fileview_store import (
    BINDING_NOT_DIGEST,
    BINDING_NOT_IMAGE,
    BINDING_UNKNOWN_DIGEST,
    BUILT,
    FAILED,
    REPLACED,
)
from oci_catalog.fileview.layer_archive import (
    CORRUPT_LAYER_ARCHIVE,
    DIGEST_MISMATCH,
    MISSING_LAYER_ARCHIVE,
    UNREADABLE_ARCHIVE,
    UNSAFE_MEMBER_PATH,
    UNSUPPORTED_LAYER_MEDIA,
)


def gz(members):
    return (tar_bytes(members, gzip_compress=True), MEDIA_TAR_GZ)


def tar(members):
    return (tar_bytes(members, gzip_compress=False), MEDIA_TAR)


class TestBindingValidation(FileViewFixture):

    def setUp(self):
        super().setUp()
        self.image, self.mapping = self.add_image_with_files(
            [gz([f("a.txt", b"a")])])

    def test_valid_image_binding_passes(self):
        self.assertEqual(self.store.validate_binding(self.image), [])

    def test_tag_string_rejected(self):
        diags = self.store.validate_binding("latest")
        self.assertEqual(diags[0].code, BINDING_NOT_DIGEST)

    def test_index_digest_rejected(self):
        index = self.add_index(self.image)
        diags = self.store.validate_binding(index)
        self.assertEqual(diags[0].code, BINDING_NOT_IMAGE)

    def test_unknown_digest_rejected(self):
        diags = self.store.validate_binding("sha256:" + "9f" * 32)
        self.assertEqual(diags[0].code, BINDING_UNKNOWN_DIGEST)

    def test_malformed_digest_rejected(self):
        diags = self.store.validate_binding("not-a-digest")
        self.assertEqual(diags[0].code, BINDING_NOT_DIGEST)


class TestBuildTransactions(FileViewFixture):

    def test_build_success_persists_view(self):
        layers = [gz([d("data"), f("data/x.txt", b"x")]),
                  tar([f("data/y.txt", b"y")])]
        image, mapping = self.add_image_with_files(layers)
        result = self.store.build_view(image, mapping)
        self.assertEqual(result.status, BUILT)
        self.assertEqual(result.layer_count, 2)
        view = self.store.get_view(image)
        self.assertIsNotNone(view)
        rows = self.store.conn.execute(
            "SELECT path FROM entries WHERE view_id = ? ORDER BY path",
            (view["view_id"],)).fetchall()
        self.assertEqual([r["path"] for r in rows],
                         ["/data", "/data/x.txt", "/data/y.txt"])
        layer_rows = self.store.list_view_layers(view["view_id"])
        self.assertEqual([r["position"] for r in layer_rows], [0, 1])
        self.assertEqual(layer_rows[0]["media_type"], MEDIA_TAR_GZ)
        self.assertEqual(layer_rows[1]["media_type"], MEDIA_TAR)

    def test_rebuild_replaces_view(self):
        layers = [gz([f("a/old.txt", b"old")])]
        image, mapping = self.add_image_with_files(layers)
        first = self.store.build_view(image, mapping)
        # 同镜像重建（换一批归档内容，但层 digest 由目录库固定，
        # 这里模拟同一 manifest 重新交付：映射不变，结果应 replaced）
        second = self.store.build_view(image, mapping)
        self.assertEqual(second.status, REPLACED)
        self.assertEqual(self.store.conn.execute(
            "SELECT COUNT(*) AS c FROM image_views").fetchone()["c"], 1)
        view = self.store.get_view(image)
        self.assertNotEqual(view["view_id"], first.view_id)

    def test_missing_layer_mapping_fails_without_view(self):
        layers = [gz([f("a.txt", b"a")]), gz([f("b.txt", b"b")])]
        image = self.add_image(layers)
        only_first = self.layer_mapping(layers[:1], "only")
        result = self.store.build_view(image, only_first)
        self.assertEqual(result.status, FAILED)
        diag = result.diagnostics[0]
        self.assertEqual(diag.code, MISSING_LAYER_ARCHIVE)
        self.assertEqual(diag.image_digest, image)
        self.assertEqual(diag.layer_digest, sha256_digest(layers[1][0]))
        self._assert_no_view(image)

    def test_digest_mismatch_names_image_and_layer(self):
        layers = [gz([f("a.txt", b"a")])]
        image = self.add_image(layers)
        wrong = tar_bytes([f("evil.txt", b"e")], gzip_compress=True)
        mapping = {sha256_digest(layers[0][0]): self.write_layer("w", wrong)}
        result = self.store.build_view(image, mapping)
        self.assertEqual(result.status, FAILED)
        diag = result.diagnostics[0]
        self.assertEqual(diag.code, DIGEST_MISMATCH)
        self.assertEqual(diag.image_digest, image)
        self.assertEqual(diag.layer_digest, sha256_digest(layers[0][0]))
        self.assertIn("expected=", diag.message)
        self._assert_no_view(image)

    def test_unreadable_archive_file(self):
        layers = [gz([f("a.txt", b"a")])]
        image = self.add_image(layers)
        mapping = {sha256_digest(layers[0][0]): "/nonexistent/layer.tar"}
        result = self.store.build_view(image, mapping)
        self.assertEqual(result.status, FAILED)
        self.assertEqual(result.diagnostics[0].code, UNREADABLE_ARCHIVE)
        self._assert_no_view(image)

    def test_corrupt_archive_rejected(self):
        garbage = b"definitely not a tar"
        layers = [(garbage, MEDIA_TAR_GZ)]
        image = self.add_image(layers)
        mapping = {sha256_digest(garbage): self.write_layer("g.bin", garbage)}
        result = self.store.build_view(image, mapping)
        self.assertEqual(result.status, FAILED)
        self.assertEqual(result.diagnostics[0].code, CORRUPT_LAYER_ARCHIVE)
        self._assert_no_view(image)

    def test_unsupported_compression_rejected(self):
        data = tar_bytes([f("a.txt", b"a")], gzip_compress=False)
        layers = [(data, "application/vnd.oci.image.layer.v1.tar+zstd")]
        image = self.add_image(layers)
        mapping = {sha256_digest(data): self.write_layer("z.bin", data)}
        result = self.store.build_view(image, mapping)
        self.assertEqual(result.status, FAILED)
        self.assertEqual(result.diagnostics[0].code,
                         UNSUPPORTED_LAYER_MEDIA)
        self._assert_no_view(image)

    def test_unsafe_member_path_rejected(self):
        layers = [gz([f("../escape.txt", b"x"), f("data/ok.txt", b"ok")])]
        image, mapping = self.add_image_with_files(layers)
        result = self.store.build_view(image, mapping)
        self.assertEqual(result.status, FAILED)
        self.assertEqual(result.diagnostics[0].code, UNSAFE_MEMBER_PATH)
        self._assert_no_view(image)

    def test_failure_recorded_with_diagnostics(self):
        layers = [gz([f("../x", b"x")])]
        image, mapping = self.add_image_with_files(layers)
        self.store.build_view(image, mapping)
        failures = self.store.list_failures()
        self.assertEqual(len(failures), 1)
        self.assertEqual(failures[0]["image_digest"], image)
        diags = json.loads(failures[0]["diagnostics_json"])
        self.assertEqual(diags[0]["code"], UNSAFE_MEMBER_PATH)
        self.assertTrue(diags[0]["layer_digest"])

    def test_failed_build_does_not_touch_existing_view(self):
        layers = [gz([f("a.txt", b"a")])]
        image, mapping = self.add_image_with_files(layers)
        self.assertTrue(self.store.build_view(image, mapping).ok)
        # 后续失败构建（缺映射）不破坏已有成功视图
        result = self.store.build_view(image, {})
        self.assertEqual(result.status, FAILED)
        self.assertIsNotNone(self.store.get_view(image))

    def _assert_no_view(self, image: str) -> None:
        self.assertIsNone(self.store.get_view(image))
        self.assertEqual(self.store.conn.execute(
            "SELECT COUNT(*) AS c FROM entries").fetchone()["c"], 0)


class TestPerImageLayerOrder(FileViewFixture):

    def test_shared_layer_not_skipped_across_images(self):
        # 同一层被两个镜像以不同层序引用：各自归并，结果不同
        layer_a = tar_bytes([f("x.txt", b"from-a")], gzip_compress=False)
        layer_b = tar_bytes([f("x.txt", b"from-b")], gzip_compress=False)
        img1 = self.add_image([(layer_a, MEDIA_TAR), (layer_b, MEDIA_TAR)])
        img2 = self.add_image([(layer_b, MEDIA_TAR), (layer_a, MEDIA_TAR)])
        mapping = self.layer_mapping(
            [(layer_a, MEDIA_TAR), (layer_b, MEDIA_TAR)])
        r1 = self.store.build_view(img1, mapping)
        r2 = self.store.build_view(img2, mapping)
        self.assertTrue(r1.ok and r2.ok)
        self.assertNotEqual(r1.view_id, r2.view_id)

        def content_of(image):
            view = self.store.get_view(image)
            row = self.store.conn.execute(
                "SELECT c.data FROM entries e JOIN contents c "
                "ON c.content_id = e.content_id "
                "WHERE e.view_id = ? AND e.path = '/x.txt'",
                (view["view_id"],)).fetchone()
            return bytes(row["data"])

        self.assertEqual(content_of(img1), b"from-b")  # b 在上层
        self.assertEqual(content_of(img2), b"from-a")  # a 在上层
        # 两个镜像的层序各自记录
        layers1 = [r["layer_digest"] for r in
                   self.store.list_view_layers(r1.view_id)]
        layers2 = [r["layer_digest"] for r in
                   self.store.list_view_layers(r2.view_id)]
        self.assertEqual(layers1, [sha256_digest(layer_a),
                                   sha256_digest(layer_b)])
        self.assertEqual(layers2, [sha256_digest(layer_b),
                                   sha256_digest(layer_a)])

    def test_identical_content_deduped_across_views(self):
        payload = b"shared-payload"
        layer1 = tar_bytes([f("a.txt", payload)], gzip_compress=False)
        layer2 = tar_bytes([f("b.txt", payload)], gzip_compress=False)
        img1 = self.add_image([(layer1, MEDIA_TAR)])
        img2 = self.add_image([(layer2, MEDIA_TAR)])
        m1 = {sha256_digest(layer1): self.write_layer("l1", layer1)}
        m2 = {sha256_digest(layer2): self.write_layer("l2", layer2)}
        self.assertTrue(self.store.build_view(img1, m1).ok)
        self.assertTrue(self.store.build_view(img2, m2).ok)
        self.assertEqual(self.store.conn.execute(
            "SELECT COUNT(*) AS c FROM contents").fetchone()["c"], 1)


class TestCatalogIsolation(FileViewFixture):

    def test_catalog_untouched_and_tables_separate(self):
        before_events = self.catalog.conn.execute(
            "SELECT COUNT(*) AS c FROM tag_events").fetchone()["c"]
        before_manifests = self.catalog.conn.execute(
            "SELECT COUNT(*) AS c FROM manifests").fetchone()["c"]
        layers = [gz([f("a.txt", b"a"), wh("a.txt")])]
        image, mapping = self.add_image_with_files(layers)
        self.assertTrue(self.store.build_view(image, mapping).ok)
        after_events = self.catalog.conn.execute(
            "SELECT COUNT(*) AS c FROM tag_events").fetchone()["c"]
        after_manifests = self.catalog.conn.execute(
            "SELECT COUNT(*) AS c FROM manifests").fetchone()["c"]
        self.assertEqual(before_events, after_events)
        # 只有 add_image 登记的一条 manifest 增量，构建本身不写目录库
        self.assertEqual(after_manifests, before_manifests + 1)
        catalog_tables = {r[0] for r in self.catalog.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        views_tables = {r[0] for r in self.store.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        self.assertNotIn("image_views", catalog_tables)
        self.assertNotIn("entries", catalog_tables)
        self.assertNotIn("tag_events", views_tables)
        self.assertNotIn("manifests", views_tables)


if __name__ == "__main__":
    unittest.main()
