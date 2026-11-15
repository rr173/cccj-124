"""字段契约：严格类型转换、定点十进制、空值策略与记录级拒绝。"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


import unittest
from decimal import Decimal

from oci_catalog.relational.contract import (
    REASON_EMPTY_NOT_ALLOWED,
    REASON_EXTRA_FIELD,
    REASON_MISSING_FIELD,
    REASON_NOT_CONVERTIBLE,
    REASON_NULL_NOT_ALLOWED,
    TableContract,
    coerce_record,
    decimal_sum,
    parse_decimal,
    parse_integer,
)
from oci_catalog.relational.contract import (
    ContractSpecError,
    RejectedRecord,
)


def contract(fields, **policies):
    return TableContract.from_dict({"fields": fields, **policies})


def presence_for(raw, contract_obj):
    presence = {}
    for spec in contract_obj.fields:
        if spec.name not in raw:
            presence[spec.name] = "missing"
        elif raw[spec.name] is None:
            presence[spec.name] = "explicit_null"
        elif raw[spec.name] == "":
            presence[spec.name] = "empty_string"
        else:
            presence[spec.name] = "present"
    return presence


class TestStrictTypes(unittest.TestCase):

    def test_integer_accepts_only_integer_literals(self):
        self.assertEqual(parse_integer("12", "q"), 12)
        self.assertEqual(parse_integer("-3", "q"), -3)
        self.assertEqual(parse_integer(7, "q"), 7)
        for bad in ("1.0", " 1", "1 ", "1e3", "0x1", "1."):
            with self.assertRaises(RejectedRecord) as ctx:
                parse_integer(bad, "q")
            self.assertEqual(ctx.exception.reason_code,
                             REASON_NOT_CONVERTIBLE)
        with self.assertRaises(RejectedRecord):
            parse_integer(True, "q")

    def test_decimal_is_fixed_point_and_exact(self):
        self.assertEqual(parse_decimal("0.10", "a") +
                         parse_decimal("0.20", "a"), Decimal("0.30"))
        self.assertEqual(parse_decimal("10", "a"), Decimal("10"))
        # 保留尾随零（定点语义）
        self.assertEqual(str(parse_decimal("10.00", "a")), "10.00")
        for bad in ("1e3", "NaN", "Infinity", "-Infinity", ".5", "1.",
                    " 0.1", "0.1 "):
            with self.assertRaises(RejectedRecord):
                parse_decimal(bad, "a")
        # JSON 浮点与布尔绝不静默接受
        with self.assertRaises(RejectedRecord):
            parse_decimal(0.1, "a")
        with self.assertRaises(RejectedRecord):
            parse_decimal(True, "a")

    def test_decimal_sum_skips_null_and_stays_exact(self):
        total = decimal_sum([Decimal("0.10"), None, Decimal("0.20")])
        self.assertEqual(total, Decimal("0.30"))
        self.assertEqual(decimal_sum([]), Decimal("0"))
        # 不同标度相加不丢精度
        self.assertEqual(
            decimal_sum([Decimal("1.00"), Decimal("2.000")]),
            Decimal("3.000"))


class TestNullPolicies(unittest.TestCase):

    def setUp(self):
        self.c = contract([
            {"name": "id", "type": "string", "nullable": False},
            {"name": "nick", "type": "string", "nullable": True},
        ], missing="reject", empty_string="reject",
            extra_fields="reject")

    def _coerce(self, raw):
        return coerce_record(self.c, raw, presence_for(raw, self.c))

    def test_missing_reject(self):
        # 缺少不可空字段 id
        with self.assertRaises(RejectedRecord) as ctx:
            self._coerce({"nick": "y"})
        self.assertEqual(ctx.exception.reason_code, REASON_MISSING_FIELD)

    def test_explicit_null_respects_nullable(self):
        self.assertEqual(
            self._coerce({"id": "x", "nick": None}),
            {"id": "x", "nick": None})
        with self.assertRaises(RejectedRecord) as ctx:
            self._coerce({"id": None, "nick": "y"})
        self.assertEqual(ctx.exception.reason_code,
                         REASON_NULL_NOT_ALLOWED)

    def test_empty_string_reject(self):
        with self.assertRaises(RejectedRecord) as ctx:
            self._coerce({"id": "x", "nick": ""})
        self.assertEqual(ctx.exception.reason_code,
                         REASON_EMPTY_NOT_ALLOWED)

    def test_empty_string_to_null_for_nullable(self):
        c = contract([
            {"name": "id", "type": "string", "nullable": False},
            {"name": "nick", "type": "string", "nullable": True},
        ], empty_string="null")
        out = coerce_record(c, {"id": "x", "nick": ""},
                            presence_for({"id": "x", "nick": ""}, c))
        self.assertEqual(out, {"id": "x", "nick": None})

    def test_empty_string_keep_only_for_strings(self):
        c = contract([
            {"name": "id", "type": "string", "nullable": False},
        ], empty_string="keep")
        out = coerce_record(c, {"id": ""}, presence_for({"id": ""}, c))
        self.assertEqual(out, {"id": ""})
        with self.assertRaises(ContractSpecError):
            contract([{"name": "n", "type": "integer",
                       "nullable": False}], empty_string="keep")

    def test_extra_field_reject_or_ignore(self):
        with self.assertRaises(RejectedRecord) as ctx:
            self._coerce({"id": "x", "nick": "y", "ghost": "g"})
        self.assertEqual(ctx.exception.reason_code, REASON_EXTRA_FIELD)
        c = contract([
            {"name": "id", "type": "string", "nullable": False},
        ], extra_fields="ignore")
        out = coerce_record(c, {"id": "x", "ghost": "g"},
                            presence_for({"id": "x"}, c))
        self.assertEqual(out, {"id": "x"})


class TestContractSpecValidation(unittest.TestCase):

    def test_duplicate_field_names_rejected(self):
        with self.assertRaises(ContractSpecError):
            contract([{"name": "a", "type": "string", "nullable": False},
                      {"name": "a", "type": "integer", "nullable": False}])

    def test_unknown_type_and_bad_policies_rejected(self):
        with self.assertRaises(ContractSpecError):
            contract([{"name": "a", "type": "float", "nullable": False}])
        with self.assertRaises(ContractSpecError):
            contract([{"name": "a", "type": "string", "nullable": False}],
                     missing="whatever")
        with self.assertRaises(ContractSpecError):
            contract([{"name": "a", "type": "string", "nullable": False}],
                     empty_string="whatever")

    def test_string_field_rejects_numeric_scalar(self):
        c = contract([{"name": "id", "type": "string",
                       "nullable": False}])
        with self.assertRaises(RejectedRecord) as ctx:
            coerce_record(c, {"id": 5}, presence_for({"id": 5}, c))
        self.assertEqual(ctx.exception.reason_code,
                         REASON_NOT_CONVERTIBLE)


if __name__ == "__main__":
    unittest.main()
