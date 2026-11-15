"""文件视图 CLI：退出码、JSON 输出、cat 原始字节直写 stdout。"""

import contextlib
import io
import json
import sys
import unittest

from fileview_fixtures import FileViewFixture, d, f, sym, tar_bytes
from oci_catalog.digest import sha256_digest
from oci_catalog.fileview.fileview_cli import main as cli_main
from oci_catalog.fileview.sample_layers import MEDIA_TAR_GZ

BLOB = b"\xff\xfe\x00\x01bin\x89"


class _FakeStdout:
    """同时捕获文本 JSON 与二进制 buffer 的 stdout 替身。"""

    def __init__(self):
        self.buffer = io.BytesIO()
        self.text = io.StringIO()

    def write(self, s):
        self.text.write(s)

    def flush(self):
        pass


class CliFixture(FileViewFixture):

    def setUp(self):
        super().setUp()
        self.layers = [
            (tar_bytes([d("data"), f("data/x.txt", b"x-content"),
                        f("data/blob.bin", BLOB),
                        sym("data/link", "x.txt")],
                       gzip_compress=True), MEDIA_TAR_GZ),
        ]
        self.image, self.mapping = self.add_image_with_files(self.layers)
        self.layer_digest = sha256_digest(self.layers[0][0])

    def run_cli(self, argv):
        stdout, stderr = _FakeStdout(), io.StringIO()
        old = sys.stdout
        sys.stdout = stdout
        try:
            with contextlib.redirect_stderr(stderr):
                rc = cli_main(
                    ["--catalog", self.catalog_db, "--views", self.views_db]
                    + argv)
        finally:
            sys.stdout = old
        return rc, stdout, stderr.getvalue()

    def build(self):
        rc, out, err = self.run_cli(
            ["build", "--image", self.image,
             "--layer", f"{self.layer_digest}={self.mapping[self.layer_digest]}"])
        self.assertEqual(rc, 0, err)


class TestCliBuild(CliFixture):

    def test_build_success_exit_0(self):
        self.build()
        rc, out, _ = self.run_cli(["layers", "--image", self.image])
        self.assertEqual(rc, 0)
        payload = json.loads(out.text.getvalue())
        self.assertEqual(len(payload["layers"]), 1)
        self.assertEqual(payload["layers"][0]["layer_digest"],
                         self.layer_digest)

    def test_build_failure_exit_2(self):
        rc, out, _ = self.run_cli(["build", "--image", self.image])  # 缺层映射
        self.assertEqual(rc, 2)
        payload = json.loads(out.text.getvalue())
        self.assertEqual(payload["status"], "failed")
        self.assertEqual(payload["diagnostics"][0]["code"],
                         "missing_layer_archive")
        # 失败不留可查询视图
        rc, out, err = self.run_cli(["list", "--image", self.image])
        self.assertEqual(rc, 3)


class TestCliQueries(CliFixture):

    def setUp(self):
        super().setUp()
        self.build()

    def test_list_exit_0_json(self):
        rc, out, _ = self.run_cli(
            ["list", "--image", self.image, "--prefix", "/data"])
        self.assertEqual(rc, 0)
        payload = json.loads(out.text.getvalue())
        paths = {e["path"] for e in payload["entries"]}
        self.assertIn("/data/x.txt", paths)
        self.assertIn("/data/link", paths)

    def test_stat_exit_0(self):
        rc, out, _ = self.run_cli(
            ["stat", "--image", self.image, "--path", "/data/x.txt"])
        self.assertEqual(rc, 0)
        entry = json.loads(out.text.getvalue())["entry"]
        self.assertEqual(entry["entry_type"], "file")
        self.assertEqual(entry["layer_digest"], self.layer_digest)

    def test_cat_writes_raw_bytes(self):
        rc, out, _ = self.run_cli(
            ["cat", "--image", self.image, "--path", "/data/blob.bin"])
        self.assertEqual(rc, 0)
        self.assertEqual(out.buffer.getvalue(), BLOB)  # 字节不重编码

    def test_cat_symlink_exit_3(self):
        rc, out, err = self.run_cli(
            ["cat", "--image", self.image, "--path", "/data/link"])
        self.assertEqual(rc, 3)
        self.assertEqual(out.buffer.getvalue(), b"")
        self.assertIn("符号链接", err)

    def test_unknown_image_exit_3(self):
        rc, _, err = self.run_cli(
            ["list", "--image", "sha256:" + "9f" * 32])
        self.assertEqual(rc, 3)
        self.assertIn("error", err)

    def test_failures_listing(self):
        self.run_cli(["build", "--image", self.image])  # 制造一次失败
        rc, out, _ = self.run_cli(["failures"])
        self.assertEqual(rc, 0)
        payload = json.loads(out.text.getvalue())
        self.assertEqual(len(payload["failures"]), 1)
        self.assertEqual(payload["failures"][0]["diagnostics"][0]["code"],
                         "missing_layer_archive")


if __name__ == "__main__":
    unittest.main()
