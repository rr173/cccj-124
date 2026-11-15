"""端到端落库与查询：原子事务、行 ID 稳定、血缘追溯、CSV 导出与失败语义。"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


import json
import os
import unittest

from oci_catalog.relational.api import open_result_store, run_plan
from oci_catalog.relational.relational_cli import main as cli_main
from oci_catalog.relational.store import (
    NodeNotFoundError,
    OutputConflictError,
    RelationalStore,
    RunNotFoundError,
)
from relational_fixtures import RelationalFixture


class TestSuccessfulRun(RelationalFixture):

    def test_full_demo_run_persists(self):
        outcome = run_plan(self.demo_plan(), self.results_db,
                           self.views_db, self.catalog_db)
        self.assertTrue(outcome.ok, outcome.to_dict())
        self.assertEqual(outcome.handle.rejection_count, 3)
        store = open_result_store(self.results_db)
        try:
            rid = outcome.handle.run_id
            nodes = store.list_nodes(rid)
            self.assertEqual([n["node_name"] for n in nodes],
                             ["customers_src", "fees_src", "orders_src",
                              "orders_picked", "active_orders",
                              "orders_with_customer", "detail",
                              "region_summary"])
        finally:
            store.close()

    def test_row_ids_stable_and_fetchable_in_new_store(self):
        outcome = run_plan(self.demo_plan(), self.results_db,
                           self.views_db, self.catalog_db)
        rid = outcome.handle.run_id
        store1 = open_result_store(self.results_db)
        first = store1.fetch_rows(rid, "region_summary")
        row_ids = [r["row_id"] for r in first["rows"]]
        store1.close()
        # 重新打开（模拟新进程），row_id 与值保持一致
        store2 = open_result_store(self.results_db)
        try:
            second = store2.fetch_rows(rid, "region_summary")
            self.assertEqual([r["row_id"] for r in second["rows"]], row_ids)
            # decimal 列读侧还原为精确 Decimal
            from decimal import Decimal
            self.assertEqual(
                [r["values"]["fee_total"] for r in second["rows"]],
                [Decimal("10.00"), Decimal("12.80"), Decimal("5.00")])
        finally:
            store2.close()

    def test_trace_returns_sorted_dedup_sources_with_contribution(self):
        outcome = run_plan(self.demo_plan(), self.results_db,
                           self.views_db, self.catalog_db)
        rid = outcome.handle.run_id
        store = open_result_store(self.results_db)
        try:
            summary = store.fetch_rows(rid, "region_summary")
            north = next(r for r in summary["rows"]
                         if r["values"]["region"] == "north")
            trace = store.trace_row(rid, "region_summary",
                                    north["row_id"])
            sources = trace["sources"]
            # 稳定排序
            coords = [(s["table_name"], s["file_path"], s["record_seq"])
                      for s in sources]
            self.assertEqual(coords, sorted(coords))
            # O1 订单在 north 组贡献 2 次（F1/F2 两条收费）
            order_o1 = next(s for s in sources
                            if s["table_name"] == "orders"
                            and s["raw_values"]["order_id"] == "O1")
            self.assertEqual(order_o1["contribution"], 2)
            # 客户 C1 同样贡献 2 次
            cust_c1 = next(s for s in sources
                           if s["table_name"] == "customers")
            self.assertEqual(cust_c1["contribution"], 2)
            # 原始字段值可回看（含引号换行字段）
            self.assertIn("\n", order_o1["raw_values"]["note"])
        finally:
            store.close()

    def test_left_join_unmatched_row_trace_has_no_right_source(self):
        outcome = run_plan(self.demo_plan(), self.results_db,
                           self.views_db, self.catalog_db)
        rid = outcome.handle.run_id
        store = open_result_store(self.results_db)
        try:
            owc = store.fetch_rows(rid, "orders_with_customer")
            # O3 的 cust_id 为 null -> 左连接未匹配，右侧补 null
            o3 = next(r for r in owc["rows"]
                      if r["values"]["order_id"] == "O3")
            trace = store.trace_row(rid, "orders_with_customer",
                                    o3["row_id"])
            self.assertEqual({s["table_name"] for s in trace["sources"]},
                             {"orders"})
        finally:
            store.close()

    def test_rejections_record_location_and_raw(self):
        run_plan(self.demo_plan(), self.results_db,
                 self.views_db, self.catalog_db)
        store = open_result_store(self.results_db)
        try:
            rid = store.latest_success_run()
            rejections = store.list_rejections(rid)
            self.assertEqual(len(rejections), 3)
            by_table = {}
            for rej in rejections:
                by_table.setdefault(rej["table_name"], []).append(rej)
            # 坏金额 F5：物理行 6，记录序号 5
            fee_rej = by_table["fees"][0]
            self.assertEqual(fee_rej["reason_code"], "not_convertible")
            self.assertEqual(fee_rej["record_seq"], 5)
            self.assertEqual(fee_rej["physical_start_line"], 6)
            self.assertIn("BAD", fee_rej["raw_text"])
            # 非对象 JSON 行
            cust_rej = by_table["customers"][0]
            self.assertEqual(cust_rej["reason_code"], "json_not_object")
        finally:
            store.close()

    def test_export_utf8_csv_keeps_decimal_literal(self):
        outcome = run_plan(self.demo_plan(), self.results_db,
                           self.views_db, self.catalog_db)
        rid = outcome.handle.run_id
        store = open_result_store(self.results_db)
        try:
            csv_text = store.export_node_csv(rid, "region_summary")
            self.assertIn("12.80", csv_text)
            self.assertIn("fee_count,fee_total,region", csv_text)
            # UTF-8 可编码
            csv_text.encode("utf-8")
        finally:
            store.close()


class TestReadIsolation(RelationalFixture):

    def test_input_dbs_opened_readonly_and_untouched(self):
        before_views = os.path.getmtime(self.views_db)
        run_plan(self.demo_plan(), self.results_db,
                 self.views_db, self.catalog_db)
        # 结果库不含任何 fileview/catalog 表
        store = open_result_store(self.results_db)
        try:
            tables = {r[0] for r in store.conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'")}
            self.assertIn("result_rows", tables)
            self.assertNotIn("entries", tables)
            self.assertNotIn("tag_events", tables)
        finally:
            store.close()
        self.assertEqual(os.path.getmtime(self.views_db), before_views)

    def test_output_conflict_with_input_db_rejected_before_write(self):
        with self.assertRaises(OutputConflictError):
            RelationalStore(self.views_db,
                            input_db_paths=[self.views_db,
                                            self.catalog_db])


class TestFailureAtomicity(RelationalFixture):

    def test_invalid_plan_leaves_no_success_run(self):
        plan = self.demo_plan()
        plan["nodes"][0]["input"] = "ghost"
        outcome = run_plan(plan, self.results_db,
                           self.views_db, self.catalog_db)
        self.assertFalse(outcome.ok)
        self.assertEqual(outcome.error_code, "plan_invalid")
        store = open_result_store(self.results_db)
        try:
            with self.assertRaises(RunNotFoundError):
                store.latest_success_run()
            failures = store.list_failures()
            self.assertEqual(failures[0]["error_code"], "plan_invalid")
        finally:
            store.close()

    def test_missing_file_fails_whole_run_no_partial_nodes(self):
        plan = self.demo_plan()
        plan["inputs"][0]["files"][0]["path"] = "/data/does/not/exist.csv"
        outcome = run_plan(plan, self.results_db,
                           self.views_db, self.catalog_db)
        self.assertFalse(outcome.ok)
        self.assertEqual(outcome.error_code, "source_read_failed")
        store = open_result_store(self.results_db)
        try:
            with self.assertRaises(RunNotFoundError):
                store.latest_success_run()
            # 失败 run 没有任何结果节点
            self.assertEqual(
                store.conn.execute(
                    "SELECT COUNT(*) AS c FROM result_nodes").fetchone()["c"],
                0)
        finally:
            store.close()

    def test_corrupt_csv_fails_whole_run(self):
        # 直接构造一个视图含损坏 CSV（重复表头）
        self._add_bad_csv_view()
        plan = {
            "inputs": [{"name": "bad", "format": "csv",
                        "files": [{"image": self._bad_digest,
                                   "path": "/bad.csv"}],
                        "contract": {"fields": [
                            {"name": "id", "type": "string",
                             "nullable": False}]}}],
            "nodes": [{"name": "src", "kind": "source",
                       "input": "bad"}],
        }
        outcome = run_plan(plan, self.results_db,
                           self.views_db, self.catalog_db)
        self.assertFalse(outcome.ok)
        self.assertEqual(outcome.error_code, "source_read_failed")

    def _add_bad_csv_view(self):
        import io
        import tarfile
        from oci_catalog.digest import sha256_digest
        from oci_catalog.models import Descriptor, ManifestInfo, ManifestKind
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tf:
            data = b"id,id\nx,y\n"
            info = tarfile.TarInfo("bad.csv")
            info.size = len(data)
            info.mtime = 0
            tf.addfile(info, io.BytesIO(data))
        archive = buf.getvalue()
        layer_digest = sha256_digest(archive)
        layer_path = os.path.join(self.tmpdir, "bad.tar")
        with open(layer_path, "wb") as fh:
            fh.write(archive)
        image_digest = "sha256:" + ("bd" * 32)
        self.catalog.upsert_manifest(ManifestInfo(
            digest=image_digest,
            media_type="application/vnd.oci.image.manifest.v1+json",
            kind=ManifestKind.IMAGE,
            layers=(Descriptor(
                digest=layer_digest,
                media_type="application/vnd.oci.image.layer.v1.tar",
                size=len(archive)),)))
        self.catalog.conn.commit()
        result = self.views.build_view(
            image_digest, {layer_digest: layer_path})
        assert result.ok
        self._bad_digest = image_digest


class TestCliEntry(RelationalFixture):

    def test_cli_run_and_query(self):
        plan_path = os.path.join(self.tmpdir, "plan.json")
        with open(plan_path, "w", encoding="utf-8") as fh:
            json.dump(self.demo_plan(), fh)
        rc = cli_main(["run", "--plan", plan_path,
                       "--output", self.results_db,
                       "--views", self.views_db,
                       "--catalog", self.catalog_db])
        self.assertEqual(rc, 0)
        store = open_result_store(self.results_db)
        try:
            rid = store.latest_success_run()
        finally:
            store.close()
        # 查询命令的 --output 放在子命令之前
        rc = cli_main(["--output", self.results_db, "nodes",
                       "--run", str(rid)])
        self.assertEqual(rc, 0)
        # 不存在的节点退出码 3
        rc = cli_main(["--output", self.results_db, "rows",
                       "--run", str(rid), "--node", "nope"])
        self.assertEqual(rc, 3)

    def test_cli_invalid_plan_exit_code_2(self):
        plan = self.demo_plan()
        plan["nodes"] = []
        plan_path = os.path.join(self.tmpdir, "bad.json")
        with open(plan_path, "w", encoding="utf-8") as fh:
            json.dump(plan, fh)
        rc = cli_main(["run", "--plan", plan_path,
                       "--output", self.results_db,
                       "--views", self.views_db,
                       "--catalog", self.catalog_db])
        self.assertEqual(rc, 2)

    def test_cli_trace_and_export_in_subprocess(self):
        # 先落库
        outcome = run_plan(self.demo_plan(), self.results_db,
                           self.views_db, self.catalog_db)
        rid = outcome.handle.run_id
        store = open_result_store(self.results_db)
        try:
            summary = store.fetch_rows(rid, "region_summary")
            north_row = next(r for r in summary["rows"]
                             if r["values"]["region"] == "north")
            row_id = north_row["row_id"]
        finally:
            store.close()
        # 在独立子进程（-I）中用命令行追溯与导出，模拟新进程交付
        import subprocess
        import sys
        repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        env = dict(os.environ)
        trace = subprocess.run(
            [sys.executable, "-I", "-c",
             "import sys; sys.path.insert(0, %r); "
             "from oci_catalog.relational.relational_cli import main; "
             "raise SystemExit(main())" % repo_root,
             "--output", self.results_db, "trace", "--run", str(rid),
             "--node", "region_summary", "--row-id", str(row_id)],
            capture_output=True, text=True, env=env)
        self.assertEqual(trace.returncode, 0, trace.stderr)
        payload = json.loads(trace.stdout)
        contrib = {(s["table_name"], s["record_seq"]): s["contribution"]
                   for s in payload["sources"]}
        self.assertEqual(contrib[("orders", 1)], 2)
        # 导出 CSV 到文件
        export = subprocess.run(
            [sys.executable, "-I", "-c",
             "import sys; sys.path.insert(0, %r); "
             "from oci_catalog.relational.relational_cli import main; "
             "raise SystemExit(main())" % repo_root,
             "--output", self.results_db, "export", "--run", str(rid),
             "--node", "region_summary"],
            capture_output=True, text=True, env=env)
        self.assertEqual(export.returncode, 0, export.stderr)
        self.assertIn("12.80", export.stdout)
        self.assertIn("fee_count,fee_total,region", export.stdout)


if __name__ == "__main__":
    unittest.main()
