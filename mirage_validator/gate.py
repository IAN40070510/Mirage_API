"""Site-bound OpenAPI response gate. Never infers contracts from samples."""
import copy
import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Literal
from urllib.parse import parse_qs, urlsplit

import yaml
from openapi_core import Config, OpenAPI
from openapi_core.datatypes import RequestParameters
from openapi_core.validation.response.validators import V30ResponseValidator, V31ResponseValidator
from pydantic import Field
from werkzeug.datastructures import Headers

from .models import StrictModel, ValidationIssue
from .json_utils import pointer, reject_constant, unique_object


class StrictJSONBodyMixin:
    """Pinned openapi-core 0.19.5 hook: retain original JSON body types.

    Header deserialization/casting remains unchanged: HTTP headers are strings.
    Upgrade the pinned dependency only with the strict body regression tests.
    """

    def _get_content_schema_value_and_schema(self, raw, content, mimetype=None):
        mime_type, parameters, media_type = self._find_media_type(content, mimetype)
        value = self._deserialise_media_type(media_type, mime_type, parameters, raw)
        schema = media_type / "schema" if "schema" in media_type else None
        return value, schema


class StrictV30ResponseValidator(StrictJSONBodyMixin, V30ResponseValidator):
    pass


class StrictV31ResponseValidator(StrictJSONBodyMixin, V31ResponseValidator):
    pass


class Manifest(StrictModel):
    platform_id: str = Field(min_length=1)
    platform_version: str = Field(min_length=1)
    source_url: str = Field(pattern=r"^https://")
    source_revision: str = Field(min_length=1)
    spec_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    approved: bool = False
    openapi_file: str = "openapi.yaml"
    # Exact deployment bindings, including any API prefix; never guess a platform.
    base_urls: list[str] = Field(min_length=1)
    # Query combinations independently reviewed against this deployment.
    query_contexts: list[dict[str, list[str]]] = Field(default_factory=lambda: [{}])


class GateRequest(StrictModel):
    request_url: str = Field(min_length=1)
    request_method: str = Field(pattern=r"^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)$")
    status_code: int = Field(ge=100, le=599)
    headers: dict[str, str]
    body: str  # Final serialized UTF-8 body, not a Pydantic-coerced object.


class GateResult(StrictModel):
    valid: bool
    decision: Literal["pass", "reject", "unverifiable"]
    validation_basis: Literal["loaded_openapi_contract"] = "loaded_openapi_contract"
    platform_id: str | None = None
    platform_version: str | None = None
    operation_id: str | None = None
    spec_sha256: str | None = None
    errors: list[ValidationIssue]


def walk_refs(value):
    if isinstance(value, dict):
        for key, item in value.items():
            if key == "$ref" and (not isinstance(item, str) or not item.startswith("#/")):
                raise ValueError("Only bundled internal $ref is supported; bundle official specs first")
            walk_refs(item)
    elif isinstance(value, list):
        for item in value:
            walk_refs(item)


def deref(spec, node):
    seen = set()
    while isinstance(node, dict) and "$ref" in node:
        ref = node["$ref"]
        if ref in seen:
            raise ValueError("Cyclic reference at contract selection")
        seen.add(ref)
        node = spec
        for key in ref[2:].split("/"):
            node = node[key.replace("~1", "/").replace("~0", "~")]
    return node


@dataclass
class Bundle:
    manifest: Manifest
    spec: dict
    api: OpenAPI


@dataclass
class RequestAdapter:
    host_url: str
    path: str
    method: str
    parameters: RequestParameters
    body: bytes | None = None
    content_type: str = ""


@dataclass
class ResponseAdapter:
    status_code: int
    headers: Headers
    data: bytes
    content_type: str


class PlatformRegistry:
    def __init__(self, root: Path):
        self.bundles = []
        for path in sorted(root.glob("*/manifest.yaml")):
            manifest = Manifest.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")))
            spec_path = (path.parent / manifest.openapi_file).resolve()
            if not spec_path.is_relative_to(path.parent.resolve()):
                raise ValueError("Spec must stay inside platform directory")
            data = spec_path.read_bytes()
            if hashlib.sha256(data).hexdigest() != manifest.spec_sha256:
                raise ValueError(f"Spec hash mismatch: {path}")
            spec = yaml.safe_load(data)
            if spec.get("openapi") not in ("3.0.0", "3.0.1", "3.0.2", "3.0.3", "3.0.4", "3.1.0", "3.1.1"):
                raise ValueError("This engine supports OpenAPI 3.0 / 3.1 only")
            walk_refs(spec)
            # Server URLs are deployment bindings, not response schema changes.
            bound = copy.deepcopy(spec)
            bound["servers"] = [{"url": url.rstrip("/")} for url in manifest.base_urls]
            for item in bound.get("paths", {}).values():
                if "servers" in item or any(isinstance(v, dict) and "servers" in v for v in item.values()):
                    raise ValueError("Operation/path server overrides require an explicit adapter")
            for base in manifest.base_urls:
                parts = urlsplit(base)
                if parts.scheme not in ("http", "https") or not parts.hostname or parts.query or parts.fragment or parts.username:
                    raise ValueError("Invalid base URL binding")
            validator_cls = StrictV30ResponseValidator if spec["openapi"].startswith("3.0.") else StrictV31ResponseValidator
            config = Config(response_validator_cls=validator_cls)
            self.bundles.append(Bundle(manifest, bound, OpenAPI.from_dict(bound, config=config)))


class OfficialResponseGate:
    def __init__(self, registry: PlatformRegistry):
        self.registry = registry

    def validate(self, request: GateRequest) -> GateResult:
        errors = []
        identity = {}

        def result(decision, code=None, reason=None, location="contract", path=""):
            if code:
                errors.append(ValidationIssue(location=location, path=path, code=code, reason=reason))
            return GateResult(valid=decision == "pass", decision=decision, errors=errors, **identity)

        try:
            url = urlsplit(request.request_url)
        except ValueError:
            return result("unverifiable", "invalid_url", "URL 格式無法解析")
        if url.scheme not in ("http", "https") or not url.hostname or url.username or url.fragment:
            return result("unverifiable", "invalid_url", "需要不含帳密與 fragment 的完整 HTTP URL")
        matches = []
        for bundle in self.registry.bundles:
            for base in bundle.manifest.base_urls:
                parsed = urlsplit(base)
                prefix = parsed.path.rstrip("/")
                if (url.scheme, url.netloc.lower()) == (parsed.scheme, parsed.netloc.lower()) and (url.path == prefix or url.path.startswith(prefix + "/")):
                    matches.append((bundle, prefix))
        if len(matches) != 1:
            return result("unverifiable", "site_not_unique", "網站沒有契約綁定，或同時匹配多份契約")
        bundle, prefix = matches[0]
        manifest = bundle.manifest
        identity.update(platform_id=manifest.platform_id, platform_version=manifest.platform_version,
                        spec_sha256=manifest.spec_sha256)
        if not manifest.approved:
            return result("unverifiable", "contract_not_approved", "此規格尚未完成來源與適用範圍審查")
        query = parse_qs(url.query, keep_blank_values=True)
        if query not in manifest.query_contexts:
            return result("unverifiable", "unsupported_context", "此查詢參數組合未經契約審查")
        path = url.path[len(prefix):] or "/"
        routes = []
        for template, item in bundle.spec.get("paths", {}).items():
            pattern = re.sub(r"\\\{[^{}]+\\\}", "[^/]+", re.escape(template))
            if re.fullmatch(pattern, path):
                routes.append((template, deref(bundle.spec, item)))
        exact = [r for r in routes if r[0] == path]
        routes = exact or routes
        if len(routes) != 1 or request.request_method.lower() not in routes[0][1]:
            return result("unverifiable", "operation_not_unique", "找不到唯一的 HTTP 方法與端點契約")
        operation = routes[0][1][request.request_method.lower()]
        identity["operation_id"] = operation.get("operationId", f"{request.request_method} {routes[0][0]}")
        responses = operation["responses"]
        response_spec = responses.get(str(request.status_code), responses.get(f"{request.status_code // 100}XX", responses.get("default")))
        if response_spec is None:
            return result("reject", "unsupported_status", "狀態碼不在官方規格中", "status", "/status_code")
        response_spec = deref(bundle.spec, response_spec)
        headers = {}
        for name, value in request.headers.items():
            key = name.lower()
            if key in headers:
                return result("reject", "duplicate_header", "header 名稱忽略大小寫後重複", "headers", pointer([key]))
            headers[key] = value
        media_type = headers.get("content-type", "").split(";", 1)[0].strip().lower()
        content = response_spec.get("content", {})
        if not content:
            return result("unverifiable", "response_schema_missing", "此狀態碼沒有 body 契約，尚無法確認完整回應")
        media = content.get(media_type) or content.get(media_type.split("/")[0] + "/*") or content.get("*/*")
        if media is None:
            return result("reject", "content_type", "缺少或不符規格的 Content-Type", "headers", "/content-type")
        if not media.get("schema"):
            return result("unverifiable", "response_schema_missing", "此媒體類型未定義 schema")
        if media_type != "application/json" and not media_type.endswith("+json"):
            return result("unverifiable", "unsupported_media", "目前僅支援 JSON 回應")
        try:
            body = json.loads(request.body, parse_constant=reject_constant, object_pairs_hook=unique_object)
            json.dumps(body, allow_nan=False)
        except (ValueError, RecursionError) as exc:
            return result("reject", "invalid_json", str(exc), "body")
        for name, definition in response_spec.get("headers", {}).items():
            definition = deref(bundle.spec, definition)
            if definition.get("required") and name.lower() not in headers:
                errors.append(ValidationIssue(location="headers", path=pointer([name.lower()]), code="required", reason="缺少規格要求的 header"))
        adapter = RequestAdapter(f"{url.scheme}://{url.netloc}", url.path, request.request_method.lower(), RequestParameters(query=query))
        response = ResponseAdapter(request.status_code, Headers(request.headers), request.body.encode("utf-8"), media_type)
        try:
            for error in bundle.api.response_validator.iter_errors(adapter, response):
                cause = error
                leaves = []
                while cause is not None:
                    leaves.extend(getattr(cause, "schema_errors", []) or [])
                    cause = cause.__cause__
                if leaves:
                    for leaf in leaves:
                        errors.append(ValidationIssue(location="body", path=pointer(leaf.absolute_path), code=str(leaf.validator), reason=leaf.message, schema_path=pointer(leaf.absolute_schema_path)))
                else:
                    errors.append(ValidationIssue(location="headers" if "Header" in type(error).__name__ else "body", path="", code=type(error).__name__, reason=str(error)))
        except Exception:
            return result("unverifiable", "validator_error", "契約解析或驗證器執行失敗；禁止放行")
        return result("reject" if errors else "pass")
