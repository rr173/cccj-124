"""计划全量校验：重名、未知引用、循环依赖、类型与顺序无关拓扑。"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


import copy
import unittest

from oci_catalog.relational.plan import (
    JOIN_INNER,
    JOIN_LEFT,
    PlanError,
    parse_plan,
)


def base_plan():
    return {
        "inputs": [
            {"name": "t1", "format": "csv",
             "files": [{"image": "sha256:aaa", "path": "/a.csv"}],
             "contract": {"fields": [
                 {"name": "k", "type": "string", "nullable": False},
                 {"name": "n", "type": "integer", "nullable": False},
                 {"name": "d", "type": "decimal", "nullable": True}]}},
            {"name": "t2", "format": "jsonl",
             "files": [{"image": "sha256:bbb", "path": "/b.jsonl"}],
             "contract": {"fields": [
                 {"name": "k", "type": "string", "nullable": False},
                 {"name": "v", "type": "string", "nullable": True}]}},
        ],
        "nodes": [
            {"name": "s1", "kind": "source", "input": "t1"},
            {"name": "s2", "kind": "source", "input": "t2"},
            {"name": "joined", "kind": "join", "left": "s1",
             "right": "s2", "join_type": JOIN_INNER,
             "left_key": "k", "right_key": "k",
             "left_suffix": "_l", "right_suffix": "_r"},
            {"name": "picked", "kind": "select", "input": "joined",
             "columns": [{"source": "k_l"}, {"source": "n"},
                         {"source": "v"}]},
            {"name": "big", "kind": "filter", "input": "picked",
             "expression": "n >= 10"},
            {"name": "summary", "kind": "group", "input": "big",
             "keys": ["v"], "count_alias": "cnt",
             "sum_column": "n", "sum_alias": "total"},
        ],
    }


class TestValidPlan(unittest.TestCase):

    def test_parses_and_derives_schemas(self):
        plan = parse_plan(base_plan())
        self.assertEqual(
            plan.order,
            ("s1", "s2", "joined", "picked", "big", "summary"))
        joined = plan.nodes["joined"].output_schema
        self.assertEqual(joined["k_l"], "string")
        self.assertEqual(joined["k_r"], "string")
        self.assertEqual(joined["n"], "integer")
        self.assertEqual(joined["v"], "string")
        summary = plan.nodes["summary"].output_schema
        self.assertEqual(summary["cnt"], "integer")
        self.assertEqual(summary["total"], "integer")

    def test_order_independent_of_declaration(self):
        plan_a = parse_plan(base_plan())
        shuffled = base_plan()
        shuffled["nodes"] = list(reversed(shuffled["nodes"]))
        plan_b = parse_plan(shuffled)
        self.assertEqual(plan_a.order, plan_b.order)

    def test_left_join_accepts(self):
        p = base_plan()
        p["nodes"][2]["join_type"] = JOIN_LEFT
        plan = parse_plan(p)
        self.assertIn("joined", plan.nodes)


class TestDuplicateAndUnknown(unittest.TestCase):

    def test_duplicate_input_name(self):
        p = base_plan()
        p["inputs"][1]["name"] = "t1"
        with self.assertRaises(PlanError):
            parse_plan(p)

    def test_node_shadows_input_name(self):
        p = base_plan()
        p["nodes"][0]["name"] = "t1"
        with self.assertRaises(PlanError) as ctx:
            parse_plan(p)
        self.assertIn("t1", str(ctx.exception))

    def test_unknown_upstream_reference(self):
        p = base_plan()
        p["nodes"][0]["input"] = "ghost"
        with self.assertRaises(PlanError) as ctx:
            parse_plan(p)
        self.assertIn("s1", str(ctx.exception))
        self.assertIn("ghost", str(ctx.exception))

    def test_select_unknown_column(self):
        p = base_plan()
        p["nodes"][3]["columns"].append({"source": "ghost"})
        with self.assertRaises(PlanError) as ctx:
            parse_plan(p)
        self.assertIn("picked", str(ctx.exception))

    def test_filter_unknown_column(self):
        p = base_plan()
        p["nodes"][4]["expression"] = "ghost = 1"
        with self.assertRaises(PlanError):
            parse_plan(p)

    def test_join_unknown_key(self):
        p = base_plan()
        p["nodes"][2]["left_key"] = "nope"
        with self.assertRaises(PlanError) as ctx:
            parse_plan(p)
        self.assertIn("joined", str(ctx.exception))

    def test_group_unknown_sum_column(self):
        p = base_plan()
        p["nodes"][5]["sum_column"] = "nope"
        with self.assertRaises(PlanError):
            parse_plan(p)

    def test_group_sum_on_string_rejected(self):
        p = base_plan()
        p["nodes"][5]["sum_column"] = "v"
        with self.assertRaises(PlanError):
            parse_plan(p)


class TestCyclesAndJoinRules(unittest.TestCase):

    def test_cycle_detected_with_node_names(self):
        p = base_plan()
        # 造环：s1 -> summary（summary 已间接依赖 s1）
        p["nodes"][0]["input"] = "summary"
        p["nodes"][0]["dependencies"] = ("summary",)
        # 直接构造依赖环：把 s1 改成 group 不现实，改用两个节点互引
        p = base_plan()
        p["nodes"][0] = {"name": "s1", "kind": "filter", "input": "big",
                         "expression": "n >= 1"}
        with self.assertRaises(PlanError) as ctx:
            parse_plan(p)
        message = str(ctx.exception)
        self.assertIn("循环", message)
        self.assertIn("s1", message)

    def test_self_dependency_rejected(self):
        p = base_plan()
        p["nodes"][0]["input"] = "s1"
        with self.assertRaises(PlanError):
            parse_plan(p)

    def test_join_key_type_mismatch_rejected(self):
        p = base_plan()
        p["inputs"][1]["contract"]["fields"][0] = {
            "name": "k", "type": "integer", "nullable": False}
        with self.assertRaises(PlanError):
            parse_plan(p)

    def test_join_suffix_must_differ_and_be_nonempty(self):
        p = base_plan()
        p["nodes"][2]["right_suffix"] = "_l"
        with self.assertRaises(PlanError):
            parse_plan(p)
        p = base_plan()
        p["nodes"][2]["left_suffix"] = ""
        with self.assertRaises(PlanError):
            parse_plan(p)

    def test_relative_file_path_rejected(self):
        p = base_plan()
        p["inputs"][0]["files"][0]["path"] = "relative/a.csv"
        with self.assertRaises(PlanError):
            parse_plan(p)

    def test_duplicate_file_within_input_rejected(self):
        p = base_plan()
        p["inputs"][0]["files"].append(
            {"image": "sha256:aaa", "path": "/a.csv"})
        with self.assertRaises(PlanError):
            parse_plan(p)


class TestSelectAliasRules(unittest.TestCase):

    def test_duplicate_alias_rejected(self):
        p = base_plan()
        p["nodes"][3]["columns"] = [
            {"source": "n", "alias": "x"},
            {"source": "v", "alias": "x"}]
        with self.assertRaises(PlanError):
            parse_plan(p)

    def test_group_alias_collision_rejected(self):
        p = base_plan()
        p["nodes"][5]["count_alias"] = "v"
        with self.assertRaises(PlanError):
            parse_plan(p)


if __name__ == "__main__":
    unittest.main()
