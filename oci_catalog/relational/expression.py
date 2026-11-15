"""过滤条件的受限数据表达语言（手写词法/语法分析，绝不使用 eval）。

语言只够表达“字段引用 与 常量 的比较 + 布尔组合”，没有算术、没有函数、
没有属性访问、没有可执行代码路径；列名、字段引用与常量都能在计划校验
阶段逐一核对。

文法（关键字大小写不敏感）::

    expr      := or_expr
    or_expr   := and_expr ( OR and_expr )*
    and_expr  := not_expr ( AND not_expr )*
    not_expr  := NOT not_expr | comparison
    comparison := operand ( = | != | < | <= | > | >= ) operand
    operand   := 字段引用 | 常量
    字段引用   := 裸标识符 [A-Za-z_][A-Za-z0-9_]*
                | 双引号标识符 "..."（"" 转义，可含点/空格/连字符）
    常量       := NULL
                | 单引号字符串 '...'（'' 转义）
                | 整数常量 [+-]?\d+
                | 定点十进制常量 [+-]?\d+\.\d+ （必须含小数点）

三值逻辑（与 SQL 一致）：任一侧为 NULL 的比较结果是 UNKNOWN；
AND/OR/NOT 带 UNKNOWN 真值表；表达式最终不为 TRUE 的行都被过滤掉。

类型检查在计划校验期完成：字符串只能与字符串比，整数只能与整数比，
decimal 只能与 decimal 比（NULL 常量可与任意类型比，运行时恒 UNKNOWN）。
跨类型比较、未知列引用、裸浮点/科学计数法常量都是计划级错误。
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from typing import Any, Optional

from .contract import TYPE_DECIMAL, TYPE_INTEGER, TYPE_STRING

# 三值
TRUE = True
FALSE = False
UNKNOWN = None

_OPERATORS = ("!=", "<=", ">=", "=", "<", ">")
_KEYWORDS = {"AND", "OR", "NOT", "NULL"}


class ExpressionError(ValueError):
    """表达式词法/语法/类型不合法（计划级错误）。"""


# ---------------------------------------------------------------------------
# 词法
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Token:
    kind: str          # ident | quoted_ident | string | number | op | keyword
    value: Any
    position: int


def _tokenize(text: str) -> list[Token]:
    tokens: list[Token] = []
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if ch.isspace():
            i += 1
            continue
        start = i
        if ch == '"':
            i, value = _read_quoted(text, i, '"')
            tokens.append(Token("quoted_ident", value, start))
            continue
        if ch == "'":
            i, value = _read_quoted(text, i, "'")
            tokens.append(Token("string", value, start))
            continue
        if ch.isdigit() or (ch in "+-" and i + 1 < n
                            and (text[i + 1].isdigit() or text[i + 1] == ".")):
            j = i + 1
            seen_dot = False
            while j < n and (text[j].isdigit() or text[j] == "."):
                if text[j] == ".":
                    if seen_dot:
                        raise ExpressionError(
                            f"位置 {j} 数字常量含多个小数点: {text!r}")
                    seen_dot = True
                j += 1
            literal = text[i:j]
            if seen_dot:
                tokens.append(Token("number", ("decimal", literal), start))
            else:
                tokens.append(Token("number", ("integer", literal), start))
            i = j
            continue
        if ch.isalpha() or ch == "_":
            j = i + 1
            while j < n and (text[j].isalnum() or text[j] == "_"):
                j += 1
            word = text[i:j]
            upper = word.upper()
            if upper in _KEYWORDS:
                tokens.append(Token("keyword", upper, start))
            else:
                tokens.append(Token("ident", word, start))
            i = j
            continue
        for op in _OPERATORS:
            if text.startswith(op, i):
                tokens.append(Token("op", op, start))
                i += len(op)
                break
        else:
            if ch in "()":
                tokens.append(Token("punct", ch, start))
                i += 1
                continue
            raise ExpressionError(f"位置 {i} 出现无法识别的字符 {ch!r}: "
                                  f"{text!r}")
    return tokens


def _read_quoted(text: str, i: int, quote: str) -> tuple[int, str]:
    """读取 quote 包围的字面量，处理双写转义（'' / ""）。"""
    parts: list[str] = []
    j = i + 1
    n = len(text)
    while j < n:
        if text[j] == quote:
            if j + 1 < n and text[j + 1] == quote:
                parts.append(quote)
                j += 2
                continue
            return j + 1, "".join(parts)
        parts.append(text[j])
        j += 1
    raise ExpressionError(f"位置 {i} 的 {quote} 引号未闭合: {text!r}")


# ---------------------------------------------------------------------------
# AST
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class FieldRef:
    name: str


@dataclass(frozen=True)
class Const:
    value: Any
    data_type: str          # string | integer | decimal | null


@dataclass(frozen=True)
class Comparison:
    op: str
    left: Any
    right: Any
    operand_type: str       # 校验后确定的运算类型（null 比较时为 ""）


@dataclass(frozen=True)
class And:
    operands: tuple


@dataclass(frozen=True)
class Or:
    operands: tuple


@dataclass(frozen=True)
class Not:
    operand: Any


# ---------------------------------------------------------------------------
# 语法分析（递归下降）
# ---------------------------------------------------------------------------
class _Parser:
    def __init__(self, text: str):
        self.text = text
        self.tokens = _tokenize(text)
        self.pos = 0

    def peek(self) -> Optional[Token]:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def take(self) -> Token:
        token = self.peek()
        if token is None:
            raise ExpressionError(f"表达式意外结束: {self.text!r}")
        self.pos += 1
        return token

    def expect_keyword(self, word: str) -> None:
        token = self.peek()
        if token is None or token.kind != "keyword" or token.value != word:
            raise ExpressionError(
                f"位置 {token.position if token else len(self.text)} "
                f"期望关键字 {word}")
        self.pos += 1

    def parse(self) -> Any:
        if not self.tokens:
            raise ExpressionError("过滤表达式为空")
        ast = self.parse_or()
        if self.peek() is not None:
            token = self.peek()
            raise ExpressionError(
                f"位置 {token.position} 之后存在无法解析的片段: {self.text!r}")
        return ast

    def parse_or(self) -> Any:
        operands = [self.parse_and()]
        while self._is_keyword("OR"):
            self.pos += 1
            operands.append(self.parse_and())
        return operands[0] if len(operands) == 1 else Or(tuple(operands))

    def parse_and(self) -> Any:
        operands = [self.parse_not()]
        while self._is_keyword("AND"):
            self.pos += 1
            operands.append(self.parse_not())
        return operands[0] if len(operands) == 1 else And(tuple(operands))

    def parse_not(self) -> Any:
        if self._is_keyword("NOT"):
            self.pos += 1
            return Not(self.parse_not())
        if self._is_punct("("):
            self.pos += 1
            inner = self.parse_or()
            token = self.peek()
            if not self._is_punct(")"):
                raise ExpressionError(
                    f"位置 {token.position if token else len(self.text)} "
                    f"括号未闭合，期望 ')'")
            self.pos += 1
            return inner
        return self.parse_comparison()

    def _is_punct(self, punct: str) -> bool:
        token = self.peek()
        return token is not None and token.kind == "punct" \
            and token.value == punct

    def parse_comparison(self) -> Any:
        left = self.parse_operand()
        token = self.peek()
        if token is None or token.kind != "op":
            raise ExpressionError(
                f"位置 {token.position if token else len(self.text)} "
                f"比较表达式缺少运算符（=, !=, <, <=, >, >=）")
        self.pos += 1
        right = self.parse_operand()
        return Comparison(token.value, left, right, operand_type="")

    def parse_operand(self) -> Any:
        token = self.take()
        if token.kind == "ident" or token.kind == "quoted_ident":
            return FieldRef(token.value)
        if token.kind == "keyword" and token.value == "NULL":
            return Const(None, "null")
        if token.kind == "string":
            return Const(token.value, TYPE_STRING)
        if token.kind == "number":
            kind, literal = token.value
            if kind == "integer":
                return Const(int(literal), TYPE_INTEGER)
            return Const(Decimal(literal), TYPE_DECIMAL)
        raise ExpressionError(
            f"位置 {token.position} 期望字段引用或常量，实际 {token.kind}")

    def _is_keyword(self, word: str) -> bool:
        token = self.peek()
        return token is not None and token.kind == "keyword" \
            and token.value == word


def parse_expression(text: str) -> Any:
    """词法 + 语法分析，返回未做类型绑定的 AST。"""
    if not isinstance(text, str) or not text.strip():
        raise ExpressionError("过滤表达式必须是非空字符串")
    return _Parser(text).parse()


# ---------------------------------------------------------------------------
# 计划期校验：列引用与类型
# ---------------------------------------------------------------------------
def _operand_type(operand: Any, schema: dict[str, str]) -> str:
    if isinstance(operand, FieldRef):
        if operand.name not in schema:
            raise ExpressionError(f"表达式引用了未知列 {operand.name!r}")
        return schema[operand.name]
    if isinstance(operand, Const):
        return operand.data_type
    raise ExpressionError(f"比较的操作数不是字段引用或常量: {operand!r}")


def validate_expression(ast: Any, schema: dict[str, str]) -> Any:
    """按节点输出 schema 校验 AST，返回绑定了运算类型的新 AST。"""
    if isinstance(ast, (And, Or)):
        return type(ast)(tuple(validate_expression(child, schema)
                               for child in ast.operands))
    if isinstance(ast, Not):
        return Not(validate_expression(ast.operand, schema))
    if isinstance(ast, Comparison):
        left_type = _operand_type(ast.left, schema)
        right_type = _operand_type(ast.right, schema)
        operand_type = _resolve_comparison_types(
            ast.op, left_type, right_type)
        return Comparison(ast.op, ast.left, ast.right, operand_type)
    raise ExpressionError(f"表达式顶层必须是比较或布尔组合: {ast!r}")


def _resolve_comparison_types(op: str, left_type: str,
                              right_type: str) -> str:
    if "null" in (left_type, right_type):
        # 与 NULL 的比较运行时恒 UNKNOWN，类型无需进一步约束
        return ""
    if left_type != right_type:
        raise ExpressionError(
            f"比较 {op!r} 两侧类型不兼容: {left_type} vs {right_type}")
    if left_type not in (TYPE_STRING, TYPE_INTEGER, TYPE_DECIMAL):
        raise ExpressionError(f"不支持比较的类型: {left_type}")
    if op in ("<", "<=", ">", ">=") and left_type == TYPE_STRING:
        # 字符串字典序比较是确定且常用的，允许
        pass
    return left_type


# ---------------------------------------------------------------------------
# 运行期求值（三值逻辑）
# ---------------------------------------------------------------------------
def evaluate(ast: Any, row: dict[str, Any]) -> Optional[bool]:
    """对一行求值，返回 TRUE/FALSE/UNKNOWN（None 即 UNKNOWN）。"""
    if isinstance(ast, And):
        result = TRUE
        for child in ast.operands:
            value = evaluate(child, row)
            if value is FALSE:
                return FALSE
            if value is UNKNOWN:
                result = UNKNOWN
        return result
    if isinstance(ast, Or):
        result = FALSE
        for child in ast.operands:
            value = evaluate(child, row)
            if value is TRUE:
                return TRUE
            if value is UNKNOWN:
                result = UNKNOWN
        return result
    if isinstance(ast, Not):
        value = evaluate(ast.operand, row)
        if value is UNKNOWN:
            return UNKNOWN
        return not value
    if isinstance(ast, Comparison):
        return _evaluate_comparison(ast, row)
    raise ExpressionError(f"非法 AST 节点: {ast!r}")


def _resolve_value(operand: Any, row: dict[str, Any]) -> Any:
    if isinstance(operand, FieldRef):
        return row.get(operand.name)
    return operand.value


def _evaluate_comparison(node: Comparison,
                         row: dict[str, Any]) -> Optional[bool]:
    left = _resolve_value(node.left, row)
    right = _resolve_value(node.right, row)
    if left is None or right is None:
        return UNKNOWN
    ops = {
        "=": lambda a, b: a == b,
        "!=": lambda a, b: a != b,
        "<": lambda a, b: a < b,
        "<=": lambda a, b: a <= b,
        ">": lambda a, b: a > b,
        ">=": lambda a, b: a >= b,
    }
    return ops[node.op](left, right)


def compile_filter(text: str, schema: dict[str, str]) -> Any:
    """一步完成解析 + 类型绑定，供计划校验调用。"""
    return validate_expression(parse_expression(text), schema)
