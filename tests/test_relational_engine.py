"""执行引擎：选列/过滤/连接/分组的确定性语义与血缘多重集。"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


import unittest
from decimal import Decimal

from oci_catalog.relational.contract import TableContract
from oci_catalog.relational.engine import Engine, Row, SourceKey
from oci_catalog.relational.plan import parse_plan
from oci_catalog.relational.sources import (
    ParsedRecord,
    ParsedTable,
    SourceLocation,
)

IMG = "sha256:" + "cd" * 32


def loc(seq, start=None, table="t"):
    return SourceLocation(IMG, f"/{table}.csv", seq,
                          start or seq + 1, start or seq + 1)


def make_table(name, rows, contract_fields):
    contract = TableContract.from_dict({"fields": contract_fields})
    records = [ParsedRecord(values=dict(r), location=loc(i + 1, table=name),
                            raw_values=dict(r), raw_text="")
               for i, r in enumerate(rows)]
    return ParsedTable(table_name=name, records=records)


def key(table, seq):
    return SourceKey(table, IMG, f"/{table}.csv", seq)


class TestJoinSemantics(unittest.TestCase):

    def _plan(self, join_type):
        return parse_plan({
            "inputs": [
                {"name": "left_t", "format": "csv",
                 "files": [{"image": IMG, "path": "/left_t.csv"}],
                 "contract": {"fields": [
                     {"name": "k", "type": "string", "nullable": True},
                     {"name": "lv", "type": "integer",
                      "nullable": False}]}},
                {"name": "right_t", "format": "csv",
                 "files": [{"image": IMG, "path": "/right_t.csv"}],
                 "contract": {"fields": [
                     {"name": "k", "type": "string", "nullable": True},
                     {"name": "rv", "type": "decimal",
                      "nullable": False}]}},
            ],
            "nodes": [
                {"name": "ls", "kind": "source", "input": "left_t"},
                {"name": "rs", "kind": "source", "input": "right_t"},
                {"name": "j", "kind": "join", "left": "ls",
                 "right": "rs", "join_type": join_type,
                 "left_key": "k", "right_key": "k",
                 "left_suffix": "_l", "right_suffix": "_r"},
            ],
        })

    def _tables(self, left_rows, right_rows):
        return {
            "left_t": make_table("left_t", left_rows, [
                {"name": "k", "type": "string", "nullable": True},
                {"name": "lv", "type": "integer", "nullable": False}]),
            "right_t": make_table("right_t", right_rows, [
                {"name": "k", "type": "string", "nullable": True},
                {"name": "rv", "type": "decimal", "nullable": False}]),
        }

    def test_null_keys_never_match_even_both_null(self):
        # 左两行：A 与 null；右两行：A 与 null
        left = [{"k": "A", "lv": 1}, {"k": None, "lv": 2}]
        right = [{"k": "A", "rv": Decimal("9.0")},
                 {"k": None, "rv": Decimal("8.0")}]
        plan = self._plan("inner")
        result = Engine(plan, self._tables(left, right)).run()
        rows = result.node_results["j"].rows
        # 只有 A=A 一对；null=null 不匹配
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].values["k_l"], "A")
        self.assertEqual(rows[0].values["rv"], Decimal("9.0"))

    def test_duplicate_keys_keep_all_combinations(self):
        left = [{"k": "A", "lv": 1}]
        right = [{"k": "A", "rv": Decimal("1.0")},
                 {"k": "A", "rv": Decimal("2.0")}]
        plan = self._plan("inner")
        rows = Engine(plan, self._tables(left, right)).run() \
            .node_results["j"].rows
        self.assertEqual([r.values["rv"] for r in rows],
                         [Decimal("1.0"), Decimal("2.0")])
        # 左源在两行里各贡献一次（多重集次数 1，但出现在两行）
        for row in rows:
            self.assertEqual(row.lineage[key("left_t", 1)], 1)

    def test_left_join_null_side_filled_no_fabricated_source(self):
        left = [{"k": "A", "lv": 1}, {"k": "B", "lv": 2}]
        right = [{"k": "A", "rv": Decimal("9.0")}]
        plan = self._plan("left")
        rows = Engine(plan, self._tables(left, right)).run() \
            .node_results["j"].rows
        self.assertEqual(len(rows), 2)
        unmatched = rows[1]
        self.assertEqual(unmatched.values["k_l"], "B")
        self.assertIsNone(unmatched.values["rv"])
        self.assertIsNone(unmatched.values["k_r"])
        # 空侧不虚构来源：血缘只有左侧记录
        self.assertEqual(set(unmatched.lineage), {key("left_t", 2)})

    def test_inner_join_drops_unmatched(self):
        left = [{"k": "A", "lv": 1}, {"k": "B", "lv": 2}]
        right = [{"k": "A", "rv": Decimal("9.0")}]
        plan = self._plan("inner")
        rows = Engine(plan, self._tables(left, right)).run() \
            .node_results["j"].rows
        self.assertEqual([r.values["k_l"] for r in rows], ["A"])

    def test_lineage_combinations_multiply(self):
        # 左 A 一行，右 A 两行；左源在每条结果贡献 1，右源各贡献 1
        left = [{"k": "A", "lv": 1}]
        right = [{"k": "A", "rv": Decimal("1.0")},
                 {"k": "A", "rv": Decimal("2.0")}]
        plan = self._plan("inner")
        rows = Engine(plan, self._tables(left, right)).run() \
            .node_results["j"].rows
        self.assertEqual(rows[0].lineage[key("right_t", 1)], 1)
        self.assertEqual(rows[1].lineage[key("right_t", 2)], 1)


class TestGroupAggregation(unittest.TestCase):

    def _run(self, rows):
        plan = parse_plan({
            "inputs": [{"name": "t", "format": "csv",
                        "files": [{"image": IMG, "path": "/t.csv"}],
                        "contract": {"fields": [
                            {"name": "g", "type": "string",
                             "nullable": True},
                            {"name": "amt", "type": "decimal",
                             "nullable": True},
                            {"name": "qty", "type": "integer",
                             "nullable": False}]}}],
            "nodes": [
                {"name": "src", "kind": "source", "input": "t"},
                {"name": "grp", "kind": "group", "input": "src",
                 "keys": ["g"], "count_alias": "cnt",
                 "sum_column": "amt", "sum_alias": "total"},
            ],
        })
        table = make_table("t", rows, [
            {"name": "g", "type": "string", "nullable": True},
            {"name": "amt", "type": "decimal", "nullable": True},
            {"name": "qty", "type": "integer", "nullable": False}])
        return Engine(plan, {"t": table}).run().node_results["grp"]

    def test_empty_input_produces_no_groups(self):
        result = self._run([])
        self.assertEqual(result.rows, [])

    def test_null_forms_its_own_group_sorted_first(self):
        rows = [
            {"g": "b", "amt": Decimal("1.00"), "qty": 1},
            {"g": None, "amt": Decimal("2.00"), "qty": 1},
            {"g": "a", "amt": Decimal("3.00"), "qty": 1},
            {"g": None, "amt": None, "qty": 1},
        ]
        result = self._run(rows)
        keys = [r.values["g"] for r in result.rows]
        self.assertEqual(keys, [None, "a", "b"])
        null_group = result.rows[0]
        self.assertEqual(null_group.values["cnt"], 2)
        # null 金额跳过求和
        self.assertEqual(null_group.values["total"], Decimal("2.00"))

    def test_decimal_sum_exact_and_count(self):
        rows = [
            {"g": "x", "amt": Decimal("0.10"), "qty": 1},
            {"g": "x", "amt": Decimal("0.20"), "qty": 1},
        ]
        result = self._run(rows)
        self.assertEqual(result.rows[0].values["total"],
                         Decimal("0.30"))
        self.assertEqual(result.rows[0].values["cnt"], 2)

    def test_integer_sum_returns_integer(self):
        plan = parse_plan({
            "inputs": [{"name": "t", "format": "csv",
                        "files": [{"image": IMG, "path": "/t.csv"}],
                        "contract": {"fields": [
                            {"name": "g", "type": "string",
                             "nullable": False},
                            {"name": "qty", "type": "integer",
                             "nullable": False}]}}],
            "nodes": [
                {"name": "src", "kind": "source", "input": "t"},
                {"name": "grp", "kind": "group", "input": "src",
                 "keys": ["g"], "count_alias": "cnt",
                 "sum_column": "qty", "sum_alias": "qsum"},
            ],
        })
        table = make_table("t", [
            {"g": "x", "qty": 2}, {"g": "x", "qty": 5}],
            [{"name": "g", "type": "string", "nullable": False},
             {"name": "qty", "type": "integer", "nullable": False}])
        result = Engine(plan, {"t": table}).run() \
            .node_results["grp"].rows[0]
        self.assertEqual(result.values["qsum"], 7)
        self.assertIsInstance(result.values["qsum"], int)

    def test_group_lineage_only_includes_member_sources(self):
        rows = [
            {"g": "a", "amt": Decimal("1.00"), "qty": 1},
            {"g": "b", "amt": Decimal("2.00"), "qty": 1},
            {"g": "a", "amt": Decimal("3.00"), "qty": 1},
        ]
        result = self._run(rows)
        a_group = next(r for r in result.rows if r.values["g"] == "a")
        self.assertEqual(set(a_group.lineage),
                         {key("t", 1), key("t", 3)})
        b_group = next(r for r in result.rows if r.values["g"] == "b")
        self.assertEqual(set(b_group.lineage), {key("t", 2)})


class TestSelectFilterPreserveLineage(unittest.TestCase):

    def test_select_and_filter_keep_lineage_identity(self):
        plan = parse_plan({
            "inputs": [{"name": "t", "format": "csv",
                        "files": [{"image": IMG, "path": "/t.csv"}],
                        "contract": {"fields": [
                            {"name": "id", "type": "string",
                             "nullable": False},
                            {"name": "status", "type": "string",
                             "nullable": False}]}}],
            "nodes": [
                {"name": "src", "kind": "source", "input": "t"},
                {"name": "pick", "kind": "select", "input": "src",
                 "columns": [{"source": "id", "alias": "ident"}]},
                {"name": "act", "kind": "filter", "input": "pick",
                 "expression": "ident = 'keep'"},
            ],
        })
        table = make_table("t", [
            {"id": "keep", "status": "active"},
            {"id": "drop", "status": "x"}],
            [{"name": "id", "type": "string", "nullable": False},
             {"name": "status", "type": "string", "nullable": False}])
        artifacts = Engine(plan, {"t": table}).run()
        rows = artifacts.node_results["act"].rows
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].lineage, {key("t", 1): 1})
        self.assertEqual(set(rows[0].values), {"ident"})


if __name__ == "__main__":
    unittest.main()
