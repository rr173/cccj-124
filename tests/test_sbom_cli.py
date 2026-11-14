"""sbom_cli 批量导入与查询入口测试（含退出码语义）。"""

import io
import json
import contextlib

from sbom_fixtures import SBOMFixture
from oci_catalog.sbom.sbom_cli import main as cli_main


def cdx(refs, deps=None):
    return {"bomFormat": "CycloneDX", "specVersion": "1.5",
            "components": [{"bom-ref": r, "name": r.lower(), "version": "1",
                            "purl": f"pkg:generic/{r.lower()}@1"} for r in refs],
            "dependencies": deps or []}


class TestCli(SBOMFixture):

    def _run(self, *argv):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = cli_main(list(argv))
        return rc, out.getvalue()

    def test_import_success_and_failure_exit_codes(self):
        good = self.write_sbom("good.json", cdx(["A", "B"]))
        bad = self.write_sbom("bad.json",
                              cdx(["A"], [{"ref": "A", "dependsOn": ["Z"]}]))
        rc, output = self._run(
            "--catalog", self.catalog_db, "--sbom", self.sbom_db, "import",
            "--bind", f"{good}={self.image_amd64}",
            "--bind", f"{bad}={self.image_amd64}")
        self.assertEqual(rc, 2)  # 存在失败文件
        payload = json.loads(output)
        statuses = [r["status"] for r in payload["results"]]
        self.assertEqual(statuses, ["imported", "failed"])

    def test_all_success_exit_zero(self):
        good = self.write_sbom("good.json", cdx(["A"]))
        rc, _ = self._run(
            "--catalog", self.catalog_db, "--sbom", self.sbom_db, "import",
            "--bind", f"{good}={self.image_amd64}")
        self.assertEqual(rc, 0)

    def test_image_subcommand(self):
        good = self.write_sbom("good.json", cdx(["A"]))
        self._run("--catalog", self.catalog_db, "--sbom", self.sbom_db,
                  "import", "--bind", f"{good}={self.image_amd64}")
        rc, output = self._run(
            "--catalog", self.catalog_db, "--sbom", self.sbom_db,
            "image", "--digest", self.image_amd64)
        self.assertEqual(rc, 0)
        payload = json.loads(output)
        self.assertEqual(payload["image_digest"], self.image_amd64)
        self.assertEqual(len(payload["files"][0]["occurrences"]), 1)

    def test_component_subcommand_and_missing_coordinate(self):
        good = self.write_sbom("good.json", cdx(["A"]))
        self._run("--catalog", self.catalog_db, "--sbom", self.sbom_db,
                  "import", "--bind", f"{good}={self.image_amd64}")
        rc, output = self._run(
            "--catalog", self.catalog_db, "--sbom", self.sbom_db,
            "component", "--purl", "pkg:generic/a@1")
        self.assertEqual(rc, 0)
        self.assertIn(self.image_amd64, json.loads(output)["images"][0]["image_digest"])

        rc, _ = self._run(
            "--catalog", self.catalog_db, "--sbom", self.sbom_db,
            "component", "--purl", "pkg:generic/missing@9")
        self.assertEqual(rc, 3)

    def test_bad_bind_syntax(self):
        with self.assertRaises(SystemExit):
            self._run("--catalog", self.catalog_db, "--sbom", self.sbom_db,
                      "import", "--bind", "no-equals-sign")
