"""严格 JSON 读取：重复键定位、诊断对象（供信封/payload/策略三处共用）。

本项目的证明接入不接受“后值覆盖前值”的 JSON 解析：信封、payload 与信任
策略中的重复键都必须被定位并拒绝。标准库 ``json`` 的 ``object_pairs_hook``
不知道当前路径，因此这里先把对象保留为有序对（``Pairs``），再由
:func:`materialize` 在已知 JSONPath 的情况下转成 dict 并报告重复键。
"""

from __future__ import annotations

import json
from dataclasses import dataclass


@dataclass(frozen=True)
class Diagnostic:
    """带源位置（JSONPath）的诊断信息。"""

    code: str            # 机器可读错误码
    message: str         # 人可读描述
    location: str        # JSONPath（信封内 "$..."，payload 内 "payload:$..."）

    def to_dict(self) -> dict:
        return {"code": self.code, "message": self.message,
                "location": self.location}


class StrictJSONError(ValueError):
    """JSON 文本本身非法（非 UTF-8、语法错误等）。"""


class DuplicateKeyError(ValueError):
    """JSON 对象中出现重复键；携带完整 JSONPath 与被重复的键名。"""

    def __init__(self, path: str, key: str):
        self.path = path
        self.key = key
        super().__init__(f"重复 JSON 键 {key!r}（位置 {path}）")


class Pairs(list):
    """JSON 对象的中间形态：有序 (键, 值) 对列表，保留重复与顺序。"""

    __slots__ = ()


def loads_strict(raw: bytes) -> object:
    """把 UTF-8 JSON 字节解析为中间树（对象为 :class:`Pairs`）。

    只负责语法层：非法 UTF-8 与语法错误抛 :class:`StrictJSONError`；
    重复键在这一步**不**报错，由 :func:`materialize` 带路径报告。
    """
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise StrictJSONError(f"不是合法 UTF-8: {exc}") from exc
    try:
        return json.loads(text, object_pairs_hook=Pairs)
    except json.JSONDecodeError as exc:
        raise StrictJSONError(f"JSON 语法错误: {exc}") from exc


def materialize(node: object, path: str = "$") -> object:
    """把中间树转成普通 dict/list/标量；发现重复键抛 :class:`DuplicateKeyError`。

    转换是深度优先的，嵌套对象、数组内对象都会被检查；重复键报告其所在
    对象的完整 JSONPath。
    """
    if isinstance(node, Pairs):
        result: dict = {}
        for key, value in node:
            if key in result:
                raise DuplicateKeyError(path, key)
            result[key] = materialize(value, f"{path}.{key}")
        return result
    if isinstance(node, list):
        return [materialize(item, f"{path}[{index}]")
                for index, item in enumerate(node)]
    return node


def load_json(raw: bytes, path: str = "$") -> object:
    """严格读取一份 JSON 文档：语法检查 + 重复键定位，返回普通对象树。"""
    return materialize(loads_strict(raw), path)
