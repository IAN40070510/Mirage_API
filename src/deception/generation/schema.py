"""從 D 的精確回應擷取生成 schema；只支援可明確解釋的子集，不改原契約。"""

import copy

from jsonschema import Draft202012Validator

from deception.profile_builder.builder import resolve_pointer

from .pointers import tokens

KEYWORDS = {"type", "properties", "required", "additionalProperties", "items", "enum", "const",
            "minLength", "maxLength", "pattern", "minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum",
            "minItems", "maxItems", "uniqueItems", "minProperties", "maxProperties", "description", "title",
            "format", "default", "examples"}


def _reference_node(spec, schema):
    """逐層檢查引用，不能在解引用時丟掉中間層不支援的結構限制。"""
    seen = set()
    while isinstance(schema, dict) and "$ref" in schema:
        if schema.keys() - {"$ref", "description", "title"}:
            raise ValueError("Generation does not support structural reference siblings")
        ref = schema["$ref"]
        if not isinstance(ref, str) or ref in seen or len(seen) >= 24:
            raise ValueError("Generation requires bounded internal references")
        seen.add(ref)
        schema = resolve_pointer(spec, ref)
    return schema


def _resolve(spec, schema, depth=0):
    """展開生成所需的局部內部引用；循環及不支援的複合 schema 明確拒絕。"""
    if depth > 24 or not isinstance(schema, dict):
        raise ValueError("Generation requires a bounded object schema")
    schema = copy.deepcopy(schema)
    if "$ref" in schema:
        return _resolve(spec, _reference_node(spec, schema), depth + 1)
    nullable = schema.pop("nullable", False)
    schema.pop("example", None)
    schema.pop("readOnly", None)
    schema.pop("writeOnly", None)
    for key in list(schema):
        if key.startswith("x-"):
            schema.pop(key)
    if schema.keys() - KEYWORDS:
        raise ValueError("Response uses an unsupported generation schema keyword")
    for key in ("exclusiveMinimum", "exclusiveMaximum"):
        if type(schema.get(key)) is bool:
            limit = "minimum" if key == "exclusiveMinimum" else "maximum"
            if schema.pop(key):
                schema[key] = schema.pop(limit)
    if "properties" in schema:
        schema["properties"] = {k: _resolve(spec, v, depth + 1) for k, v in schema["properties"].items()}
    if "items" in schema:
        schema["items"] = _resolve(spec, schema["items"], depth + 1)
    if isinstance(schema.get("additionalProperties"), dict):
        schema["additionalProperties"] = _resolve(spec, schema["additionalProperties"], depth + 1)
    if nullable:
        schema = {"anyOf": [schema, {"type": "null"}]}
    Draft202012Validator.check_schema(schema)
    return schema


def field_schema(profile, plan, pointer: str) -> dict:
    """沿明確 properties / items 取得欄位，原 H/I 契約仍保留完整原貌。"""
    if (profile.source.platform_id, profile.source.platform_version, profile.source.spec_sha256,
        profile.operation.method, profile.operation.path) != (
        plan.scope.platform_id, plan.scope.platform_version, plan.scope.spec_sha256, plan.method, plan.path):
        raise ValueError("Generation profile and plan identity disagree")
    responses = profile.operation.responses
    response = responses.get(str(plan.status_code), responses.get(f"{plan.status_code // 100}XX", responses.get("default")))
    if response is None:
        raise ValueError("Selected response is not defined")
    content = response.get("content", {})
    media = content.get(plan.media_type, content.get("application/*", content.get("*/*")))
    if not isinstance(media, dict) or "schema" not in media:
        raise ValueError("Selected media has no schema")
    schema = media["schema"]
    for token in tokens(pointer):
        if not isinstance(schema, dict):
            raise ValueError("Generation target has no explicit schema")
        if "$ref" in schema:
            schema = _reference_node(profile.specification, schema)
        if not isinstance(schema, dict):
            raise ValueError("Generation target has no explicit schema")
        if schema.get("type") == "array":
            if not token.isascii() or not token.isdigit() or str(int(token)) != token:
                raise ValueError("Generation array target must use a canonical index")
            schema = schema["items"]
        else:
            schema = schema["properties"][token]
    return _resolve(profile.specification, schema)
