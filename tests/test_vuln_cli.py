"""命令行入口：退出码、报告写出、按编号查询与失败语义。"""

import json
import os
import unittest

from vuln_fixtures import (
    VERSIONS_AVAILABLE,
    VulnFixture,
    advisory,
    cdx_component,
    cdx_doc,
    ev,
    pypi_claim,
)

from oci_catalog.vuln.vuln_cli import main as cli_main


@unittest.skipUnless(VERSIONS_AVAILABLE,
                     "需要 packaging 与 semantic_version 包")
class TestVulnCli(VulnFixture):

    def _setup_sbom(self):
        self.import_sbom(cdx_doc([
            cdx_component("R", "requests", "2.31.0",
                          "pkg:pypi/requests@2.31.0")]),
            self.image_amd64, "test.cdx.json")

    def _base_argv(self, advisory_dir=None):
        return ["--catalog", self.catalog_db, "--sbom", self.sbom_db,
                "--advisories", advisory_dir or self.advisory_dir]

    def test_report_exit_zero_and_output_file(self):
        self._setup_sbom()
        self.write_advisories({
            "a.json": advisory("ADV-1", [pypi_claim(
                "requests", events=ev(("introduced", "2.31.0"),
                                      ("fixed", "2.32.3")))])})
        output = os.path.join(self.tmpdir, "report.json")
        rc = cli_main(self._base_argv() + [
            "report", "--digest", self.image_amd64, "--output", output])
        self.assertEqual(rc, 0)
        with open(output, encoding="utf-8") as fh:
            report = json.load(fh)
        self.assertEqual(report["report_kind"], "vuln-correlation/v1")
        self.assertEqual(report["summary"]["affected"], 1)

    def test_report_no_sbom_exit_3(self):
        self.write_advisories({"a.json": advisory("ADV-1", [])})
        rc = cli_main(self._base_argv() + [
            "report", "--digest", self.image_quiet])
        self.assertEqual(rc, 3)

    def test_report_missing_sbom_db_exit_3(self):
        self.write_advisories({"a.json": advisory("ADV-1", [])})
        rc = cli_main(["--catalog", self.catalog_db,
                       "--sbom", os.path.join(self.tmpdir, "absent.db"),
                       "--advisories", self.advisory_dir,
                       "report", "--digest", self.image_amd64])
        self.assertEqual(rc, 3)

    def test_bad_digest_exit_3(self):
        self.write_advisories({"a.json": advisory("ADV-1", [])})
        rc = cli_main(self._base_argv() + ["report", "--digest", "latest"])
        self.assertEqual(rc, 3)

    def test_invalid_advisory_dir_exit_2(self):
        self._setup_sbom()
        self.write_advisories({
            "bad.json": advisory("BAD", [pypi_claim(
                "requests", events=ev(("introduced", "2.0.0"),
                                      ("fixed", "1.0.0")))])})
        rc = cli_main(self._base_argv() + [
            "report", "--digest", self.image_amd64])
        self.assertEqual(rc, 2)

    def test_advisory_query_exit_zero(self):
        self._setup_sbom()
        self.write_advisories({
            "a.json": advisory("ADV-1", [pypi_claim(
                "requests", events=ev(("introduced", "2.31.0"),
                                      ("fixed", "2.32.3")))],
                aliases=["ALIAS-1"])})
        rc = cli_main(self._base_argv() + [
            "advisory", "--digest", self.image_amd64, "--id", "ALIAS-1"])
        self.assertEqual(rc, 0)

    def test_advisory_query_unknown_id_exit_3(self):
        self._setup_sbom()
        self.write_advisories({"a.json": advisory("ADV-1", [])})
        rc = cli_main(self._base_argv() + [
            "advisory", "--digest", self.image_amd64, "--id", "NOPE-1"])
        self.assertEqual(rc, 3)


if __name__ == "__main__":
    unittest.main()
