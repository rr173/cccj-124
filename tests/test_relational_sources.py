"""CSV / JSONL 解析：引号逗号换行、物理行号、记录序号与文件级致命错误。"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


import unittest

from oci_catalog.relational.contract import TableContract
from oci_catalog.relational.sources import (
    SourceReadError,
    parse_csv_table,
    parse_jsonl_table,
)

IMG = "sha256:" + "ab" * 32
PATH = "/data/t.csv"


def csv_contract(extra="reject", nullable=None):
    fields = [
        {"name": "id", "type": "string", "nullable": False},
        {"name": "note", "type": "string", "nullable": True},
        {"name": "qty", "type": "integer", "nullable": False},
    ]
    return TableContract.from_dict({
        "fields": fields, "missing": "reject",
        "empty_string": "null", "extra_fields": extra})


class TestCsvParsing(unittest.TestCase):

    def test_quoted_comma_and_embedded_newline(self):
        data = (
            'id,note,qty\n'
            '1,"hello, world",3\n'
            '2,"line one\nline two",4\n'
            '3,plain,5\n'
        ).encode("utf-8")
        table = parse_csv_table(
            "t", csv_contract(), [(IMG, PATH, data)])
        self.assertEqual(len(table.records), 3)
        # 第二条记录跨物理行 3-4，记录序号仍是 2
        rec2 = table.records[1]
        self.assertEqual(rec2.location.record_seq, 2)
        self.assertEqual(rec2.location.physical_start_line, 3)
        self.assertEqual(rec2.location.physical_end_line, 4)
        self.assertEqual(rec2.values["note"], "line one\nline two")
        # 第一条：引号内逗号不拆列
        self.assertEqual(table.records[0].values["note"], "hello, world")
        self.assertEqual(
            (table.records[0].location.physical_start_line,
             table.records[0].location.physical_end_line), (2, 2))

    def test_blank_physical_lines_skipped_not_numbered(self):
        data = (
            'id,note,qty\n'
            '1,a,3\n'
            '\n'
            '2,b,4\n'
        ).encode("utf-8")
        table = parse_csv_table(
            "t", csv_contract(), [(IMG, PATH, data)])
        self.assertEqual([r.location.record_seq for r in table.records],
                         [1, 2])
        # 第二条记录从第 4 物理行开始（空行占第 3 行）
        self.assertEqual(table.records[1].location.physical_start_line, 4)

    def test_multi_file_sequence_continuous(self):
        d1 = b"id,note,qty\n1,a,3\n"
        d2 = b"id,note,qty\n2,b,4\n"
        table = parse_csv_table(
            "t", csv_contract(),
            [(IMG, "/a.csv", d1), (IMG, "/b.csv", d2)])
        self.assertEqual([r.location.record_seq for r in table.records],
                         [1, 2])
        self.assertEqual([r.location.file_path for r in table.records],
                         ["/a.csv", "/b.csv"])

    def test_duplicate_header_is_fatal(self):
        data = b"id,id,qty\n1,a,3\n"
        with self.assertRaises(SourceReadError) as ctx:
            parse_csv_table("t", csv_contract(), [(IMG, PATH, data)])
        self.assertEqual(ctx.exception.code, "csv_structure_error")

    def test_missing_contract_column_is_fatal(self):
        data = b"id,qty\n1,3\n"
        with self.assertRaises(SourceReadError) as ctx:
            parse_csv_table("t", csv_contract(), [(IMG, PATH, data)])
        self.assertEqual(ctx.exception.code, "csv_structure_error")

    def test_ragged_row_is_fatal(self):
        data = b"id,note,qty\n1,a,3,extra\n"
        with self.assertRaises(SourceReadError):
            parse_csv_table("t", csv_contract(), [(IMG, PATH, data)])

    def test_bad_encoding_is_fatal(self):
        data = b"id,note,qty\n1,\xff\xfe,3\n"
        with self.assertRaises(SourceReadError) as ctx:
            parse_csv_table("t", csv_contract(), [(IMG, PATH, data)])
        self.assertEqual(ctx.exception.code, "encoding_error")

    def test_bad_integer_goes_to_rejections_not_fatal(self):
        data = b"id,note,qty\n1,a,3\n2,b,NOPE\n3,c,5\n"
        table = parse_csv_table(
            "t", csv_contract(), [(IMG, PATH, data)])
        self.assertEqual(len(table.records), 2)
        self.assertEqual(len(table.rejections), 1)
        rej = table.rejections[0]
        self.assertEqual(rej.reason_code, "not_convertible")
        self.assertEqual(rej.location.record_seq, 2)
        self.assertIn("qty", rej.reason_message)
        # 合格记录继续，序号不重置
        self.assertEqual(table.records[1].values["id"], "3")

    def test_extra_header_column_rejected_or_ignored(self):
        data = b"id,note,qty,ghost\n1,a,3,g\n2,b,4,h\n"
        # reject 策略：额外字段是**记录级**拒绝（不是文件级致命错误），
        # 其它合格记录继续
        table = parse_csv_table("t", csv_contract("reject"),
                                [(IMG, PATH, data)])
        self.assertEqual(len(table.records), 0)
        self.assertEqual(len(table.rejections), 2)
        self.assertEqual(table.rejections[0].reason_code, "extra_field")
        # ignore 策略下额外列不进结果，记录合格
        table = parse_csv_table("t", csv_contract("ignore"),
                                [(IMG, PATH, data)])
        self.assertEqual(len(table.records), 2)
        self.assertNotIn("ghost", table.records[0].values)


class TestJsonlParsing(unittest.TestCase):

    def contract(self):
        return TableContract.from_dict({
            "fields": [
                {"name": "id", "type": "string", "nullable": False},
                {"name": "region", "type": "string", "nullable": True},
                {"name": "n", "type": "integer", "nullable": False}],
            "missing": "reject", "empty_string": "null",
            "extra_fields": "reject"})

    def test_non_object_and_invalid_lines_are_record_rejections(self):
        data = (
            '{"id": "a", "region": "north", "n": 1}\n'
            '["array", "not", "object"]\n'
            '{not json}\n'
            '\n'
            '{"id": "b", "region": null, "n": 2}\n'
        ).encode("utf-8")
        table = parse_jsonl_table(
            "t", self.contract(), [(IMG, "/t.jsonl", data)])
        self.assertEqual(len(table.records), 2)
        codes = [r.reason_code for r in table.rejections]
        self.assertEqual(codes, ["json_not_object", "json_invalid_line"])
        # 空物理行不占序号；但非空的拒绝行占序号：
        # 行1合格(seq1) 行2拒绝(seq2) 行3拒绝(seq3) 行4空 行5合格(seq4)
        self.assertEqual(table.records[1].location.record_seq, 4)
        self.assertEqual(table.records[1].location.physical_start_line, 5)
        self.assertIsNone(table.records[1].values["region"])

    def test_explicit_null_vs_missing_key(self):
        data = (
            '{"id": "a", "region": null, "n": 1}\n'
            '{"id": "b", "n": 2}\n'
        ).encode("utf-8")
        table = parse_jsonl_table(
            "t", self.contract(), [(IMG, "/t.jsonl", data)])
        # 第二行缺 region，missing=reject -> 拒绝
        self.assertEqual(len(table.records), 1)
        self.assertEqual(table.rejections[0].reason_code,
                         "missing_field")

    def test_json_float_into_decimal_rejected(self):
        c = TableContract.from_dict({
            "fields": [{"name": "d", "type": "decimal",
                        "nullable": False}],
            "missing": "reject", "empty_string": "null"})
        data = b'{"d": 0.1}\n{"d": "0.1"}\n'
        table = parse_jsonl_table("t", c, [(IMG, "/t.jsonl", data)])
        self.assertEqual(len(table.records), 1)
        self.assertEqual(table.rejections[0].reason_code,
                         "not_convertible")


if __name__ == "__main__":
    unittest.main()
