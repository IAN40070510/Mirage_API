"""B 與 I 共用的契約選擇規則；不依順序或最長前綴猜測有歧義的來源。"""

import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import SplitResult, parse_qs, unquote, urlsplit


class SelectionError(ValueError):
    """可對外回報的匹配失敗；呼叫者維持未能確認的狀態。"""

    def __init__(self, code: str, reason: str):
        """保存穩定錯誤代碼與可回報原因，並以原因初始化 ValueError 訊息。"""
        self.code = code
        self.reason = reason
        super().__init__(reason)


def parse_request_url(value: str) -> SplitResult:
    """保留原始 path 編碼；先拒絕 URL parser 可能默默忽略的控制字元。"""
    try:
        if not isinstance(value, str) or not value or any(ord(char) <= 32 or ord(char) == 127 for char in value):
            raise ValueError("URL must not contain whitespace or controls")
        if "\\" in value or "#" in value or re.search(r"%(?![0-9a-fA-F]{2})", value):
            raise ValueError("Ambiguous URL encoding")
        url = urlsplit(value)
        if url.scheme not in ("http", "https") or not url.hostname or url.username is not None or url.password is not None:
            raise ValueError("Invalid origin or userinfo")
        url.port  # 即使不連線，也要觸發非法 port 的格式／範圍檢查。
        return url
    except ValueError as exc:
        raise SelectionError("invalid_url", "需要不含帳密、fragment 或歧義編碼的完整 HTTP URL") from exc


def parse_query(query: str) -> dict[str, list[str]]:
    """保留空值及重複值順序，UTF-8 錯誤不可被替代字元悄悄改寫。"""
    try:
        return parse_qs(query, keep_blank_values=True, errors="strict")
    except UnicodeError as exc:
        raise SelectionError("invalid_url", "query 必須使用有效 UTF-8 編碼") from exc


def base_identity(base: str) -> tuple[str, str, str]:
    """保持既有 I 的 origin／port 比對語意，只忽略 host 大小寫與前綴尾斜線。"""
    parsed = parse_request_url(base)
    if parsed.query:
        raise SelectionError("invalid_url", "部署 base URL 不可包含 query")
    return parsed.scheme, parsed.netloc.lower(), parsed.path.rstrip("/")


def match_base_url(url: SplitResult, base: str) -> str | None:
    """前綴須在 path segment 邊界吻合，/api 不可匹配 /apix。"""
    scheme, authority, prefix = base_identity(base)
    if (url.scheme, url.netloc.lower()) == (scheme, authority) and (
        url.path == prefix or url.path.startswith(prefix + "/")
    ):
        return prefix
    return None


@dataclass(frozen=True)
class SiteMatch:
    """唯一匹配的已載入契約與原始部署 base URL。"""

    bundle: Any
    base_url: str
    prefix: str


def select_site(bundles, url: SplitResult) -> SiteMatch:
    """重複 base、不同版本或重疊前綴一律回報歧義，不做自動優先排序。"""
    matches = []
    for bundle in bundles:
        for base in bundle.manifest.base_urls:
            prefix = match_base_url(url, base)
            if prefix is not None:
                matches.append(SiteMatch(bundle, base, prefix))
    if len(matches) != 1:
        raise SelectionError("site_not_unique", "網站沒有契約綁定，或同時匹配多份契約")
    return matches[0]


def deref(spec, node, *, path_item: bool = False):
    """解析內部 URI fragment 一次，再處理 JSON Pointer；無效引用不逃出 gate。"""
    seen = set()
    try:
        while isinstance(node, dict) and "$ref" in node:
            ref = node["$ref"]
            if not isinstance(ref, str) or not ref.startswith("#/") or ref in seen:
                raise ValueError("Invalid or cyclic reference at contract selection")
            if path_item and node.keys() - {"$ref", "summary", "description"}:
                # 與 D 的明確引用限制一致；不可把 servers 等結構 sibling 在解引用時丟掉。
                # 每一層引用都要檢查，避免透過中間 Path Item 隱藏部署覆寫。
                raise ValueError("Structural Path Item reference siblings require an explicit adapter")
            seen.add(ref)
            node = spec
            for token in unquote(ref[2:], errors="strict").split("/"):
                if re.search(r"~(?![01])", token):
                    raise ValueError("Invalid JSON Pointer escape")
                key = token.replace("~1", "/").replace("~0", "~")
                if isinstance(node, list):
                    if not re.fullmatch(r"0|[1-9][0-9]*", key):
                        raise ValueError("Invalid array index in reference")
                    node = node[int(key)]
                else:
                    node = node[key]
        return node
    except (LookupError, TypeError, ValueError) as exc:
        raise SelectionError("contract_reference_error", "契約內部引用無法解析、產生循環或包含不支援的結構覆寫") from exc


@dataclass(frozen=True)
class OperationMatch:
    """操作及原始編碼參數；不把已解碼 path 再拿來重新選路由。"""

    template: str
    operation: dict
    path_parameters: dict[str, str]


def select_operation(spec: dict, method: str, path: str) -> OperationMatch:
    """先挑唯一 path（靜態 exact 優先），再檢查 method，維持 B／I 同一規則。"""
    routes = []
    for template, item in spec.get("paths", {}).items():
        if template.startswith("x-"):
            continue
        names = []
        pieces = []
        minimal_pieces = []
        offset = 0
        for parameter in re.finditer(r"\{([^{}]+)\}", template):
            pieces.extend((re.escape(template[offset:parameter.start()]), "([^/]+)"))
            minimal_pieces.extend((re.escape(template[offset:parameter.start()]), "([^/]+?)"))
            names.append(parameter.group(1))
            offset = parameter.end()
        pieces.append(re.escape(template[offset:]))
        minimal_pieces.append(re.escape(template[offset:]))
        match = re.fullmatch("".join(pieces), path)
        if match:
            routes.append((template, deref(spec, item, path_item=True), names, match.groups(), "".join(minimal_pieces)))
    exact = [route for route in routes if route[0] == path]
    routes = exact or routes
    if len(routes) != 1 or method.lower() not in routes[0][1]:
        raise SelectionError("operation_not_unique", "找不到唯一的 HTTP 方法與端點契約")
    template, item, names, values, minimal_pattern = routes[0]
    # 先選 exact／唯一操作，再檢查其參數；未選到的動態模板不可擋住有效靜態路由。
    if len(names) != len(set(names)):
        raise SelectionError("operation_not_unique", "路徑參數名稱重複，無法唯一識別")
    if len(names) > 1:
        # pattern 只含 escaped literals 與 path-segment captures。最大／最小貪婪拆分
        # 若不同，就存在多種合法參數分割；不能任意把其中一組交給 C 或 E 查詢。
        minimal = re.fullmatch(minimal_pattern, path)
        if minimal is None or minimal.groups() != values:
            raise SelectionError("operation_not_unique", "路徑參數有多種合法拆分，無法唯一識別")
    return OperationMatch(template, item[method.lower()], dict(zip(names, values)))
