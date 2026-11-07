"""JSON parsing and error paths, independent of schema validation engines."""


def pointer(parts):
    """RFC 6901 JSON Pointer; empty string denotes root."""
    return "".join("/" + str(p).replace("~", "~0").replace("/", "~1") for p in parts)


def reject_constant(value):
    raise ValueError(f"Non-JSON constant: {value}")


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate JSON key: {key}")
        result[key] = value
    return result
