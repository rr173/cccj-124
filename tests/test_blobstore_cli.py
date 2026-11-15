"""命令行入口：导入/名称/导出/回收/状态，退出码与真实行为。"""

import json
import os
import subprocess
import sys
import unittest

from blobstore_fixtures import BlobStoreFixture
from oci_catalog.blobstore.blobstore_cli import main
from oci_catalog.blobstore.sample_data import AMD64_L2


class TestCli(BlobStoreFixture):

    def run_cli(self, *argv: str) -> tuple[int, str, str]:
        import io
        from contextlib import redirect_stdout, redirect_stderr
        out, err = io.StringIO(), io.StringIO()
        code = 0
        with redirect_stdout(out), redirect_stderr(err):
            try:
                code = main(["--store", self.store_path] + list(argv))
            except SystemExit as exc:  # argparse 参数错误
                code = exc.code
        return code, out.getvalue(), err.getvalue()

    def test_import_and_refs(self):
        code, out, _ = self.run_cli(
            "import", "--layout", self.layout.layout_dir,
            "--root", self.layout.roots["A"], "--name", "delivery-a")
        self.assertEqual(code, 0)
        payload = json.loads(out)
        self.assertEqual(payload["status"], "imported")
        code, out, _ = self.run_cli("refs")
        self.assertEqual(code, 0)
        refs = json.loads(out)["refs"]
        self.assertEqual([r["name"] for r in refs], ["delivery-a"])

    def test_import_failure_exit_code_2(self):
        bad = self.copy_layout("bad")
        self.remove_blob(bad, self.layout.names["base"])
        code, out, _ = self.run_cli(
            "import", "--layout", bad, "--root", self.layout.roots["A"])
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(out)["status"], "failed")
        code, out, _ = self.run_cli("refs")
        self.assertEqual(json.loads(out)["refs"], [])

    def test_export_layer_bytes_to_file(self):
        self.run_cli("import", "--layout", self.layout.layout_dir,
                     "--root", self.layout.roots["A"], "--name", "a")
        output = os.path.join(self.tmpdir, "layer.bin")
        code, out, _ = self.run_cli(
            "export", "--name", "a",
            "--digest", self.layout.names["amd64-l2"],
            "--output", output)
        self.assertEqual(code, 0)
        with open(output, "rb") as fh:
            self.assertEqual(fh.read(), AMD64_L2)
        # 已存在文件拒绝覆盖
        code, _, err = self.run_cli(
            "export", "--name", "a",
            "--digest", self.layout.names["amd64-l2"],
            "--output", output)
        self.assertEqual(code, 2)
        self.assertIn("拒绝覆盖", err)

    def test_export_outside_closure_rejected(self):
        self.run_cli("import", "--layout", self.layout.layout_dir,
                     "--root", self.layout.roots["A"], "--name", "a")
        self.run_cli("import", "--layout", self.layout.layout_dir,
                     "--root", self.layout.roots["B"], "--name", "b")
        output = os.path.join(self.tmpdir, "layer.bin")
        code, _, err = self.run_cli(
            "export", "--name", "a",
            "--digest", self.layout.names["repack-l2"], "--output", output)
        self.assertEqual(code, 2)
        self.assertIn("不包含", err)
        self.assertFalse(os.path.exists(output))

    def test_name_delete_and_missing_name(self):
        self.run_cli("import", "--layout", self.layout.layout_dir,
                     "--root", self.layout.roots["A"], "--name", "a")
        code, out, _ = self.run_cli("name", "delete", "--name", "a")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["status"], "deleted")
        code, _, _ = self.run_cli("name", "delete", "--name", "a")
        self.assertEqual(code, 3)
        code, _, _ = self.run_cli("resolve", "--name", "a")
        self.assertEqual(code, 3)

    def test_gc_plan_and_apply_json(self):
        self.run_cli("import", "--layout", self.layout.layout_dir,
                     "--root", self.layout.roots["A"], "--name", "a")
        self.run_cli("import", "--layout", self.layout.layout_dir,
                     "--root", self.layout.roots["C"])
        code, out, _ = self.run_cli("gc", "plan")
        self.assertEqual(code, 0)
        plan = json.loads(out)
        self.assertEqual(plan["object_count"], 3)
        code, out, _ = self.run_cli("gc", "apply", "--plan", plan["plan_id"])
        self.assertEqual(code, 0)
        run = json.loads(out)
        self.assertEqual(run["summary"]["deleted"], 3)
        self.assertEqual(run["freed_bytes"], 547)
        code, _, _ = self.run_cli("gc", "apply", "--plan", "nope")
        self.assertEqual(code, 4)

    def test_status_reports_corruption_with_exit_2(self):
        self.run_cli("import", "--layout", self.layout.layout_dir,
                     "--root", self.layout.roots["A"], "--name", "a")
        os.unlink(self.store.blob_path(self.layout.names["base"]))
        code, out, _ = self.run_cli("status")
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(out)["status"], "corrupt")

    def test_stats(self):
        self.run_cli("import", "--layout", self.layout.layout_dir,
                     "--root", self.layout.roots["A"], "--name", "a")
        code, out, _ = self.run_cli("stats")
        payload = json.loads(out)
        self.assertEqual(payload["object_count"], 10)
        self.assertEqual(payload["unique_bytes"], 3120)

    def test_cli_runs_as_module_in_new_process(self):
        here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        code = (
            "import sys; sys.path.insert(0, %r); "
            "from oci_catalog.blobstore.blobstore_cli import main; "
            "raise SystemExit(main())" % here)
        proc = subprocess.run(
            [sys.executable, "-I", "-c", code,
             "--store", self.store_path, "import",
             "--layout", self.layout.layout_dir,
             "--root", self.layout.roots["A"], "--name", "a"],
            capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(json.loads(proc.stdout)["status"], "imported")


if __name__ == "__main__":
    unittest.main()
