"""受限过滤表达语言：词法/语法、类型校验、三值逻辑与无 eval 保证。"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


import unittest
from decimal import Decimal

from oci_catalog.relational.expression import (
    ExpressionError,
    compile_filter,
    evaluate,
    parse_expression,
)

SCHEMA = {
    "status": "string",
    "region": "string",
    "qty": "integer",
    "amount": "decimal",
}


class TestParsing(unittest.TestCase):

    def test_basic_comparisons_and_constants(self):
        ast = compile_filter("status = 'active'", SCHEMA)
        self.assertIs(evaluate(ast, {"status": "active"}), True)
        self.assertIs(evaluate(ast, {"status": "cancelled"}), False)

    def test_quoted_identifier_with_special_chars(self):
        schema = {'order-id': "string"}
        ast = compile_filter('"order-id" = \'O1\'', schema)
        self.assertIs(evaluate(ast, {"order-id": "O1"}), True)

    def test_integer_and_decimal_constants(self):
        self.assertIs(evaluate(
            compile_filter("qty >= 3", SCHEMA), {"qty": 3}), True)
        self.assertIs(evaluate(
            compile_filter("amount < 1.50", SCHEMA),
            {"amount": Decimal("1.00")}), True)

    def test_parentheses_and_not_precedence(self):
        ast = compile_filter(
            "status = 'active' AND NOT (qty >= 3 OR amount = 1.00)",
            SCHEMA)
        # qty=1, amount=2 -> 内层 FALSE -> NOT TRUE -> 整体 TRUE
        self.assertIs(evaluate(
            ast, {"status": "active", "qty": 1,
                  "amount": Decimal("2.00")}), True)
        # qty=3 -> 内层 TRUE -> NOT FALSE
        self.assertIs(evaluate(
            ast, {"status": "active", "qty": 3,
                  "amount": Decimal("2.00")}), False)

    def test_escaped_quotes_in_string(self):
        ast = compile_filter("status = 'it''s ok'", SCHEMA)
        self.assertIs(evaluate(ast, {"status": "it's ok"}), True)

    def test_syntax_errors_are_plan_level(self):
        for bad in ("status =", "= 'x'", "status == 'x'",
                    "qty >", "(status = 'a'", "status # 1",
                    "unknown_fn(1)", "", "   "):
            with self.assertRaises(ExpressionError):
                compile_filter(bad, SCHEMA)

    def test_unknown_column_rejected_at_compile(self):
        with self.assertRaises(ExpressionError):
            compile_filter("ghost = 'x'", SCHEMA)

    def test_cross_type_comparison_rejected(self):
        with self.assertRaises(ExpressionError):
            compile_filter("qty = '3'", SCHEMA)
        with self.assertRaises(ExpressionError):
            compile_filter("amount = 3", SCHEMA)

    def test_float_and_scientific_constants_rejected(self):
        # 1e3 会被词法当成整数 1 后遇到非法字符 e
        with self.assertRaises(ExpressionError):
            compile_filter("amount = 1e3", SCHEMA)


class TestThreeValuedLogic(unittest.TestCase):

    def test_null_comparison_is_unknown_and_filtered(self):
        ast = compile_filter("region = 'north'", SCHEMA)
        self.assertIsNone(evaluate(ast, {"region": None}))
        self.assertIs(evaluate(ast, {"region": "north"}), True)

    def test_null_keyword_constant(self):
        ast = compile_filter("region != NULL", SCHEMA)
        self.assertIsNone(evaluate(ast, {"region": None}))
        self.assertIsNone(evaluate(ast, {"region": "x"}))

    def test_and_or_not_truth_tables(self):
        t, f, u = True, False, None
        ast_and = compile_filter(
            "qty >= 1 AND amount >= 1.00", SCHEMA)
        ast_or = compile_filter(
            "qty >= 9 OR amount >= 1.00", SCHEMA)
        ast_not = compile_filter("NOT (qty >= 9)", SCHEMA)
        # AND: TRUE AND UNKNOWN -> UNKNOWN
        self.assertIsNone(evaluate(
            ast_and, {"qty": 5, "amount": None}))
        # AND: FALSE AND UNKNOWN -> FALSE
        self.assertIs(evaluate(
            ast_and, {"qty": 0, "amount": None}), False)
        # OR: FALSE OR UNKNOWN -> UNKNOWN
        self.assertIsNone(evaluate(
            ast_or, {"qty": 0, "amount": None}))
        # OR: TRUE OR UNKNOWN -> TRUE
        self.assertIs(evaluate(
            ast_or, {"qty": 0, "amount": Decimal("2.00")}), True)
        # NOT UNKNOWN -> UNKNOWN
        self.assertIsNone(evaluate(ast_not, {"qty": None}))
        self.assertIs(evaluate(ast_not, {"qty": 1}), True)

    def test_string_ordering_comparison(self):
        ast = compile_filter("status < 'b'", SCHEMA)
        self.assertIs(evaluate(ast, {"status": "active"}), True)
        self.assertIs(evaluate(ast, {"status": "z"}), False)

    def test_no_eval_surface(self):
        # 任何 Python 表达式形态都无法通过词法
        for attack in ("__import__('os')", "1 + 1",
                       "().__class__", "qty.__class__",
                       "lambda: 1", "x if True else y"):
            with self.assertRaises(ExpressionError):
                try:
                    parse_expression(attack)
                except ExpressionError:
                    raise
                # 即便词法通过，引用未知列也必须在编译期失败
                compile_filter(attack, SCHEMA)


if __name__ == "__main__":
    unittest.main()
