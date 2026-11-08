"""領域無關的 JSON Pointer 操作；目標必須存在且不允許根層替換。"""

import re


def tokens(pointer: str) -> tuple[str, ...]:
    """按 RFC 6901 token 比較父子關係，不用字串前綴猜測重疊。"""
    if not isinstance(pointer, str) or not pointer.startswith("/") or re.search(r"~(?![01])", pointer):
        raise ValueError("A non-root JSON Pointer is required")
    return tuple(part.replace("~1", "/").replace("~0", "~") for part in pointer[1:].split("/"))


def overlap(left: str, right: str) -> bool:
    """同一位置或互為父子的位置不能分別由模型與權威資料控制。"""
    a, b = tokens(left), tokens(right)
    return a[:len(b)] == b or b[:len(a)] == a


def key(node, token: str):
    """陣列索引只接受標準非負整數。"""
    if isinstance(node, dict):
        return token
    if isinstance(node, list) and re.fullmatch(r"0|[1-9][0-9]*", token):
        return int(token)
    raise ValueError("Pointer does not identify a JSON container")


def get(node, pointer: str):
    """讀取既有 JSON 值，不新增欄位或執行任何表達式。"""
    for token in tokens(pointer):
        node = node[key(node, token)]
    return node


def replace(node, pointer: str, value):
    """只替換已存在的目標；呼叫端必須先複製模板以免修改原 F 計畫。"""
    parts = tokens(pointer)
    for token in parts[:-1]:
        node = node[key(node, token)]
    target = key(node, parts[-1])
    node[target]
    node[target] = value
