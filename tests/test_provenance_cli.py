"""命令行入口：导入、按策略核验、镜像查询、材料反查与退出码。"""

import contextlib
import io
import json
import os
import unittest

from provenance_fixtures import (
    CRYPTO_AVAILABLE,
    ProvenanceFixture,
    make_envelope,
    make_policy,
    make_statement,
)

from oci_catalog.provenance.provenance_cli import main as cli_main


@unittest.skipUnless(CRYPTO_AVAILABLE, "需要 cryptography 包")
class TestProvenanceCLI(ProvenanceFixture):

    def setUp(self):
        super().setUp()
        self.envelope_path = os.path.join(self.tmpdir, "env.json")
        envelope = make_envelope(make_statement(self.image_amd64),
                                 self.signers("key-a", "key-b"))
        with open(self.envelope_path, "wb") as fh:
            fh.write(envelope)
        self.policy_path = os.path.join(self.tmpdir, "policy.json")
        with open(self.policy_path, "w", encoding="utf-8") as fh:
            json.dump(make_policy(["key-a", "key-b"]), fh)

    def run_cli(self, *argv):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), \
                contextlib.redirect_stderr(stderr):
            try:
                rc = cli_main(list(argv))
            except SystemExit as exc:  # 策略不合法等以 SystemExit(4) 退出
                rc = exc.code
        return rc, stdout.getvalue(), stderr.getvalue()

    def base_args(self):
        return ["--catalog", self.catalog_db, "--prov", self.prov_db]

    def test_import_then_verify_then_queries(self):
        rc, out, _ = self.run_cli(
            *self.base_args(), "import",
            "--bind", f"{self.envelope_path}={self.image_amd64}")
        self.assertEqual(rc, 0, out)
        results = json.loads(out)["results"]
        self.assertEqual(results[0]["status"], "imported")

        rc, out, _ = self.run_cli(
            *self.base_args(), "verify", "--policy", self.policy_path)
        self.assertEqual(rc, 0, out)
        payload = json.loads(out)
        self.assertEqual(payload["evaluated"], 1)
        self.assertEqual(payload["evaluations"][0]["verdict"], "trusted")

        rc, out, _ = self.run_cli(
            *self.base_args(), "image", "--policy", self.policy_path,
            "--digest", self.image_amd64)
        self.assertEqual(rc, 0, out)
        report = json.loads(out)
        self.assertEqual(report["evidence"][0]["evaluation"]["verdict"],
                         "trusted")

        rc, out, _ = self.run_cli(
            *self.base_args(), "material", "--policy", self.policy_path,
            "--uri", "https://mirror.test/data.tar.gz",
            "--sha256", "11" * 32)
        self.assertEqual(rc, 0, out)
        matches = json.loads(out)["matches"]
        self.assertEqual([m["image_digest"] for m in matches],
                         [self.image_amd64])

        # 评价历史落库
        rc, out, _ = self.run_cli(*self.base_args(), "evaluations")
        self.assertEqual(rc, 0)
        self.assertTrue(json.loads(out)["evaluations"])

    def test_import_failure_exit_code_2(self):
        bad_path = os.path.join(self.tmpdir, "bad.json")
        with open(bad_path, "wb") as fh:
            fh.write(b'{"payloadType": "text/plain"}')
        rc, out, _ = self.run_cli(
            *self.base_args(), "import",
            "--bind", f"{bad_path}={self.image_amd64}")
        self.assertEqual(rc, 2)
        results = json.loads(out)["results"]
        self.assertEqual(results[0]["status"], "failed")
        self.assertTrue(results[0]["diagnostics"])

        rc, out, _ = self.run_cli(*self.base_args(), "failures")
        self.assertEqual(rc, 0)
        self.assertEqual(len(json.loads(out)["failures"]), 1)

    def test_unknown_image_query_exit_code_3(self):
        rc, _, err = self.run_cli(
            *self.base_args(), "image", "--policy", self.policy_path,
            "--digest", "sha256:" + "00" * 32)
        self.assertEqual(rc, 3)
        self.assertIn("error", json.loads(err))

    def test_invalid_policy_exit_code_4(self):
        bad_policy = os.path.join(self.tmpdir, "bad-policy.json")
        with open(bad_policy, "w", encoding="utf-8") as fh:
            json.dump(make_policy(["key-a", "ghost"]), fh)
        rc, _, err = self.run_cli(
            *self.base_args(), "verify", "--policy", bad_policy)
        self.assertEqual(rc, 4)
        self.assertIn("unknown_key", err)

    def test_material_query_validates_sha256(self):
        rc, _, err = self.run_cli(
            *self.base_args(), "material", "--policy", self.policy_path,
            "--uri", "https://mirror.test/data.tar.gz", "--sha256", "xyz")
        self.assertEqual(rc, 3)
        self.assertIn("64", err)


if __name__ == "__main__":
    unittest.main()
