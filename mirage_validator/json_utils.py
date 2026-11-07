"""JSON parsing and error paths, independent of schema validation engines."""


def pointer(parts):
    """將路徑片段轉為 RFC 6901 JSON Pointer；空字串代表根節點。"""
    return "".join("/" + str(p).replace("~", "~0").replace("/", "~1") for p in parts)


def reject_constant(value):
    """拒絕 JSON 規格不允許的 NaN、Infinity 等常數，拋出 ValueError。"""
    raise ValueError(f"Non-JSON constant: {value}")


def unique_object(pairs):
    """由鍵值配對建立物件，遇到重複 JSON 鍵時拋出 ValueError。"""
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate JSON key: {key}")
        result[key] = value
    return result
