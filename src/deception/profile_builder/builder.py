"""從本地固定規格建立 D Profile；不抓取來源、不推測缺少的契約。"""

import copy
import hashlib
import json
import os
import tempfile
from pathlib import Path
from urllib.parse import unquote

import yaml

from mirage_validator.gate import walk_refs
from mirage_validator.openapi_utils import create_openapi

from .models import OperationProfile, PlatformProfile, ProfileSource

METHODS = ("get", "post", "put", "patch", "delete", "head", "options", "trace")
VERSIONS = {"3.0.0", "3.0.1", "3.0.2", "3.0.3", "3.0.4", "3.1.0", "3.1.1"}


class ProfileError(ValueError):
    """來源、規格或已產生的 Profile 無法可靠使用。"""


class _UniqueLoader(yaml.SafeLoader):
    """讓重複 YAML key 成為錯誤，避免後值覆蓋契約。"""


def _unique_mapping(loader, node, deep=False):
    """建立安全 YAML mapping；非字串鍵或重複鍵直接拒絕，避免契約被後值覆寫。"""
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if not isinstance(key, str) or key in result:
            raise ProfileError("YAML keys must be unique strings")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


_UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _unique_mapping)


def read_yaml(data: bytes):
    """以安全 loader 讀取 JSON 相容 YAML，拒絕循環、NaN 等無法重現的值。"""
    try:
        value = yaml.load(data, Loader=_UniqueLoader)
        return json.loads(json.dumps(value, allow_nan=False))
    except (ValueError, TypeError, RecursionError, yaml.YAMLError) as exc:
        raise ProfileError(f"Invalid YAML/JSON input: {exc}") from exc


def local_path(root: Path, relative: str) -> Path:
    """限制規格與快照路徑在指定目錄內，包含解析 symlink 後的檢查。"""
    if Path(relative).is_absolute():
        raise ProfileError("File path must be relative to its directory")
    path = (root / relative).resolve()
    if not path.is_relative_to(root.resolve()):
        raise ProfileError("File must stay inside its directory")
    return path


def resolve_pointer(spec: dict, ref: str):
    """解析內部 JSON Pointer；只定位節點，不展開遞迴 schema。"""
    if not ref.startswith("#/"):
        raise ProfileError("Only bundled internal $ref is supported")
    value = spec
    try:
        for token in unquote(ref[2:]).split("/"):
            key = token.replace("~1", "/").replace("~0", "~")
            value = value[int(key)] if isinstance(value, list) else value[key]
        return value
    except (KeyError, IndexError, TypeError, ValueError) as exc:
        raise ProfileError(f"Unresolved reference: {ref}") from exc


def _check_refs(spec, node):
    """遞迴確認內部引用均可解析，並拒絕目前無法可靠處理的動態引用。"""
    if isinstance(node, dict):
        if "$dynamicRef" in node:
            raise ProfileError("$dynamicRef is not supported by this Profile builder")
        if "$ref" in node:
            resolve_pointer(spec, node["$ref"])
        for value in node.values():
            _check_refs(spec, value)
    elif isinstance(node, list):
        for value in node:
            _check_refs(spec, value)


def _object(spec: dict, node: dict) -> dict:
    """解析參數、回應等 Reference Object；schema 內部的引用維持原樣。"""
    node = copy.deepcopy(node)
    seen = set()
    while "$ref" in node:
        ref = node["$ref"]
        if ref in seen:
            raise ProfileError(f"Cyclic Reference Object: {ref}")
        seen.add(ref)
        siblings = {key: value for key, value in node.items() if key != "$ref"}
        if siblings.keys() - {"description", "summary"}:
            raise ProfileError("Structural siblings of Reference Objects are unsupported")
        target = copy.deepcopy(resolve_pointer(spec, ref))
        if not isinstance(target, dict):
            raise ProfileError(f"Reference Object must point to an object: {ref}")
        # 3.1 的 description/summary 可覆寫；3.0 Reference Object 的 sibling 會被忽略。
        if spec["openapi"].startswith("3.1."):
            target.update(siblings)
        node = target
    return node


def extract_profile(source: ProfileSource, data: bytes) -> PlatformProfile:
    """驗證同一份原始 bytes，再依排序規則擷取操作與已知缺口。"""
    if hashlib.sha256(data).hexdigest() != source.spec_sha256:
        raise ProfileError("Spec hash mismatch")
    spec = read_yaml(data)
    if not isinstance(spec, dict) or spec.get("openapi") not in VERSIONS:
        raise ProfileError("Only OpenAPI 3.0 / 3.1 is supported")
    walk_refs(spec)
    _check_refs(spec, spec)
    # 使用既有鎖版驗證器，避免另外維護一份 OpenAPI 規格驗證實作。
    create_openapi(spec)

    operations = []
    warnings = []
    if not source.approved:
        warnings.append("source_not_approved")
    if source.platform_version != spec["info"]["version"]:
        warnings.append("declared_version_differs_from_spec_info_version")
    for path, raw_item in sorted(spec.get("paths", {}).items()):
        if path.startswith("x-"):
            continue
        item = _object(spec, raw_item)
        item_pointer = "#/paths/" + path.replace("~", "~0").replace("/", "~1")
        referenced_item = raw_item
        while "$ref" in referenced_item:
            item_pointer = referenced_item["$ref"]
            referenced_item = resolve_pointer(spec, item_pointer)
        for method in METHODS:
            if method not in item:
                continue
            operation = item[method]
            operation_id = operation.get("operationId", f"{method.upper()} {path}")
            # operation 級同名參數覆寫 path 級參數；順序固定，不合併 schema。
            parameters = {}
            for raw in item.get("parameters", []) + operation.get("parameters", []):
                parameter = _object(spec, raw)
                parameters[(parameter["in"], parameter["name"])] = parameter
            responses = {}
            for status, raw in sorted(operation["responses"].items()):
                if status.startswith("x-"):
                    continue
                response = _object(spec, raw)
                if "headers" in response:
                    response["headers"] = {name: _object(spec, header)
                                           for name, header in response["headers"].items()}
                responses[status] = response
                if not response.get("content"):
                    warnings.append(f"{operation_id}/{status}:response_content_missing")
                for media_type, media in response.get("content", {}).items():
                    # 布林 schema（含 false）與空 schema 都是存在，不能用 truthiness 判斷。
                    if "schema" not in media:
                        warnings.append(f"{operation_id}/{status}/{media_type}:schema_missing")
            pointer = item_pointer + "/" + method
            operations.append(OperationProfile(
                operation_id=operation_id, method=method.upper(), path=path,
                schema_pointer=pointer, tags=operation.get("tags", []), summary=operation.get("summary"),
                parameters=list(parameters.values()),
                request_body=_object(spec, operation["requestBody"]) if "requestBody" in operation else None,
                security=operation.get("security", spec.get("security", [])), responses=responses,
            ))
    return PlatformProfile(
        source=source, openapi_version=spec["openapi"], spec_info_version=spec["info"]["version"],
        schema_file=f"schemas/{source.platform_id}/{source.spec_sha256}.yaml",
        operations=operations, warnings=warnings,
    )


def _atomic_write(path: Path, data: bytes):
    """先完成暫存檔再替換，避免讀者看到半份 Profile 或規格快照。"""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(data)
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def build_profile(source_path: Path, output_root: Path) -> PlatformProfile:
    """將 source.yaml 與規格編成 Profile；不同版本／雜湊禁止靜默覆寫。"""
    try:
        source = ProfileSource.model_validate(read_yaml(source_path.read_bytes()))
        data = local_path(source_path.parent, source.openapi_file).read_bytes()
        profile = extract_profile(source, data)
        output_path = local_path(output_root, f"profiles/{source.platform_id}.yaml")
        if output_path.exists():
            previous = PlatformProfile.model_validate(read_yaml(output_path.read_bytes()))
            if previous.source != source:
                raise ProfileError("Existing profile has a different source; use another output directory")
        # 先寫內容定址的快照，再發布 Profile；重建同一來源會產出完全相同 bytes。
        _atomic_write(local_path(output_root, profile.schema_file), data)
        _atomic_write(output_path, yaml.safe_dump(profile.model_dump(mode="json"),
                                                allow_unicode=True, sort_keys=False).encode("utf-8"))
        return profile
    except ProfileError:
        raise
    except Exception as exc:
        raise ProfileError(f"Cannot build profile: {exc}") from exc
