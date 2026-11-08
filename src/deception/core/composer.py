"""H：明確模板與 E 映射 → 嚴格序列化 → D 契約 preflight → 候選回應。"""

import copy
import json
import re
from pathlib import Path
from urllib.parse import unquote

from openapi_core import Config
from werkzeug.datastructures import Headers

from deception.profile_builder import ProfileTool
from deception.synthetic.generator import checked_dataset
from deception.synthetic.models import SyntheticDataset
from mirage_validator.gate import StrictV30ResponseValidator, StrictV31ResponseValidator
from mirage_validator.openapi_utils import create_openapi

from .models import CandidateIdentity, CandidateResponse, CompositionPlan

HEADER_NAME = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$", re.ASCII)
JSON_MEDIA = re.compile(r"^application/(?:[a-z0-9!#$&^_.+-]+\+)?json$", re.ASCII)
SERVER_HEADERS = {"content-length", "transfer-encoding", "connection", "keep-alive", "upgrade",
                  "proxy-authenticate", "proxy-authorization", "trailer", "te", "content-encoding"}


class _TrueSchemaResponseValidator(StrictV31ResponseValidator):
    """0.19.5 的 literal true schema adapter：保留 JSON 解析與 header 檢查。"""

    def _get_content_and_schema(self, raw, content, mimetype=None):
        value, schema = super()._get_content_schema_value_and_schema(raw, content, mimetype)
        # 此上層擴充點只處理 response body；複合 header 使用未覆寫的下層方法。
        # 不可在下層一律丟棄 schema，否則會連 header.content 的限制一起跳過。
        if schema is not None and schema.contents() is True:
            return value, None
        if schema is not None:
            self._validate_schema(schema, value)
        return value, schema


class CompositionError(ValueError):
    """附機器可讀 code 的組合失敗，失敗時不產生候選、不重試或修正。"""

    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(f"{code}: {message}")


def _tokens(pointer: str) -> tuple[str, ...]:
    """只接受 RFC 6901 字串 Pointer，拒絕無效 escape 與 fragment 寫法。"""
    if pointer == "":
        return ()
    if not pointer.startswith("/") or re.search(r"~(?![01])", pointer):
        raise CompositionError("invalid_binding", "Bindings require a valid JSON Pointer")
    return tuple(token.replace("~1", "/").replace("~0", "~") for token in pointer[1:].split("/"))


def _key(node, token: str):
    if isinstance(node, list):
        if not re.fullmatch(r"0|[1-9][0-9]*", token):
            raise CompositionError("invalid_binding", "Array index must be a nonnegative canonical integer")
        return int(token)
    if isinstance(node, dict):
        return token
    raise CompositionError("invalid_binding", "Pointer does not refer to a JSON container")


def _get(node, tokens: tuple[str, ...]):
    for token in tokens:
        node = node[_key(node, token)]
    return node


def _apply_bindings(body, bindings, dataset: SyntheticDataset | None):
    """只對既有模板位置做顯式替換，不新增欄位、不展開程式或文字表達式。"""
    targets = []
    for binding in bindings:
        target = _tokens(binding.target_pointer)
        if any(target[:len(previous)] == previous or previous[:len(target)] == target for previous in targets):
            raise CompositionError("overlapping_binding", "Binding targets must not repeat or overlap")
        targets.append(target)
    if bindings and dataset is None:
        raise CompositionError("dataset_missing", "E data is required for bindings")
    source = {"products": [p.model_dump(mode="json") for p in dataset.products],
              "variants": [v.model_dump(mode="json") for v in dataset.variants]} if dataset is not None else {}
    result = copy.deepcopy(body)
    try:
        for binding, target in zip(bindings, targets):
            origin = _tokens(binding.source_pointer)
            if not origin or origin[0] not in ("products", "variants"):
                raise CompositionError("invalid_binding", "Only E products and variants may be mapped")
            value = copy.deepcopy(_get(source, origin))
            if not target:
                result = value
            else:
                parent = _get(result, target[:-1])
                key = _key(parent, target[-1])
                parent[key]  # 必須先存在；不能因 mapping 拼錯字而建立新欄位。
                parent[key] = value
        return result
    except (KeyError, IndexError, TypeError) as exc:
        raise CompositionError("invalid_binding", "Source or target pointer does not exist") from exc


def _headers(plan: CompositionPlan) -> tuple[tuple[str, str], ...]:
    """正規化單值 header，拒絕注入、重複名稱或與 body 不一致的傳輸設定。"""
    media_type = plan.media_type
    if not JSON_MEDIA.fullmatch(media_type):
        raise CompositionError("unsupported_media", "Only an explicit application/json or +json media type is supported")
    headers = {}
    original_names = {}
    for name, value in plan.headers.items():
        key = name.lower()
        if not HEADER_NAME.fullmatch(name) or any(ord(char) < 32 and char != "\t" or ord(char) == 127 for char in value):
            raise CompositionError("invalid_header", "Invalid header name or control character")
        if key in headers:
            raise CompositionError("duplicate_header", "Header names must be unique ignoring case")
        if key in SERVER_HEADERS:
            raise CompositionError("server_header", "Transfer framing and content encoding belong to the HTTP renderer")
        try:
            value.encode("latin-1")
        except UnicodeEncodeError as exc:
            raise CompositionError("invalid_header", "Header values must be representable as HTTP bytes") from exc
        headers[key] = value
        original_names[key] = name
    if "content-type" in headers:
        parts = [part.strip() for part in headers["content-type"].split(";")]
        if parts[0].lower() != media_type or len(parts) > 2:
            raise CompositionError("content_type_mismatch", "Content-Type does not match the selected JSON media type")
        if len(parts) == 2 and not re.fullmatch(r'charset\s*=\s*(?:"utf-8"|"utf8"|utf-8|utf8)', parts[1], re.IGNORECASE):
            raise CompositionError("unsupported_charset", "Only UTF-8 JSON is supported")
    else:
        headers["content-type"] = media_type
        original_names["content-type"] = "Content-Type"
    return tuple((original_names[key], value) for key, value in sorted(headers.items()))


def _preflight(context, status: int, media_type: str, headers, body: str):
    """檢查同一份序列化 triple；此處只檢查 D 契約，不核准網站或 query。"""
    responses = context.operation.responses
    response = responses.get(str(status), responses.get(f"{status // 100}XX", responses.get("default")))
    if response is None:
        raise CompositionError("unsupported_status", "Selected status is not defined by the operation")
    content = response.get("content", {})
    media = content.get(media_type, content.get(media_type.split("/")[0] + "/*", content.get("*/*")))
    if media is None or "schema" not in media:
        raise CompositionError("response_schema_missing", "Selected response media has no body schema")
    if media["schema"] is False:
        raise CompositionError("contract_mismatch", "The selected false schema forbids every body")
    supplied_headers = {name.lower(): value for name, value in headers}
    for name, definition in response.get("headers", {}).items():
        if definition.get("required") and name.lower() not in supplied_headers:
            raise CompositionError("required_header", f"Missing required response header: {name}")
    cls = StrictV30ResponseValidator if context.specification["openapi"].startswith("3.0.") else StrictV31ResponseValidator
    if media["schema"] is True:
        # 只補上鎖版驗證器對 literal true 的相容處理，不改寫 D 的原始規格。
        cls = _TrueSchemaResponseValidator
    api = create_openapi(context.specification, config=Config(response_validator_cls=cls))
    operation = api.spec
    # D 的 pointer 已定位到確切 operation，避免為了 preflight 虛構網站或挑到另一條路由。
    for token in unquote(context.operation.schema_pointer[2:]).split("/"):
        operation = operation / token.replace("~1", "/").replace("~0", "~")
    # 鎖版 0.19.5 的 extension point；升級時須跑 H/I 的型別與完全相同 triple 回歸測試。
    errors = list(api.response_validator._iter_errors(
        status, body.encode("utf-8"), Headers(headers), media_type, operation))
    if errors:
        raise CompositionError("contract_mismatch", "; ".join(str(error) for error in errors))


class ResponseComposer:
    """H 工具：每次從 D 重讀已校驗的 Profile，不跨版本或契約自動回退。"""

    def __init__(self, profile_root: Path):
        self.profile_root = profile_root

    def compose(self, plan: CompositionPlan, *, dataset: SyntheticDataset | None = None,
                allow_unreviewed: bool = False) -> CandidateResponse:
        """將明確的 body／映射組合成候選；未審來源只能顯式離線預覽。"""
        try:
            plan = CompositionPlan.model_validate(plan.model_dump(mode="json"))
            scope = plan.scope
            context = ProfileTool(self.profile_root).get_operation(
                platform_id=scope.platform_id, platform_version=scope.platform_version,
                spec_sha256=scope.spec_sha256, method=plan.method, path=plan.path,
                allow_unreviewed=allow_unreviewed)
            if plan.method == "HEAD" or plan.status_code in (204, 205, 304):
                raise CompositionError("unsupported_bodyless_response", "This composer only supports responses with a JSON body")
            if dataset is not None:
                dataset = checked_dataset(dataset, dataset.config)
                if dataset.config.scope != scope:
                    raise CompositionError("scope_mismatch", "E data does not match the composition scope")
            headers = _headers(plan)
            value = _apply_bindings(plan.body, plan.bindings, dataset)
            # 固定序列化，保留原始 JSON 型別，不依驗證結果 cast／補值／刪除欄位。
            body = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
            _preflight(context, plan.status_code, plan.media_type, headers, body)
            identity = CandidateIdentity(**scope.model_dump(), operation_id=context.operation.operation_id,
                                         method=plan.method, path=plan.path, source_approved=context.source.approved)
            return CandidateResponse(identity, plan.status_code, headers, body)
        except CompositionError:
            raise
        except Exception as exc:
            raise CompositionError("composition_failed", str(exc)) from exc
