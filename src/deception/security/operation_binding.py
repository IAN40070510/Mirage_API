"""由可信 Ingress 的原始 HTTP 快照推導固定業務 Operation，拒絕路由歧義。"""

from dataclasses import dataclass
import hashlib
import re

from deception.api.fingerprint import fingerprint_request
from deception.api.ingress import NormalizedRequest


class OperationBindingError(ValueError):
    """表示請求路徑、方法或固定業務契約不能唯一對應可信 Operation。"""


@dataclass(frozen=True)
class VerifiedOperationBinding:
    """不可變的 HTTP Operation 來源，不能由 Runtime 指定 Handler 名稱。"""

    platform: str
    operation_id: str
    method: str
    path_template: str
    request_fingerprint: str
    request_body_sha256: str


def derive_verified_operation(request: NormalizedRequest) -> VerifiedOperationBinding:
    """使用固定 Synthetic API 規格及實際接收的原始 path 導出唯一 Operation。

    不接受百分比編碼路徑、非空 query、斜線或方法替代、重複／重疊路由。
    Medusa 映射須另外加入固定已審核的 native contract，未完成前 Fail-Closed。
    """
    if not isinstance(request, NormalizedRequest):
        raise OperationBindingError("verified_operation_requires_http_snapshot")
    if (not isinstance(request.path, str) or not isinstance(request.raw_path, bytes)
            or request.raw_path != request.path.encode("utf-8")
            or not isinstance(request.method, str)
            or not re.fullmatch(r"[A-Z]+", request.method)
            or request.query_string or request.query):
        raise OperationBindingError("verified_operation_ambiguous_route")

    from deception.domains.ecommerce.cart_http import cart_specification
    from deception.domains.ecommerce.inventory_http import inventory_specification

    matches = []
    for platform, specification in (
        ("synthetic-inventory", inventory_specification()),
        ("synthetic-carts", cart_specification()),
    ):
        for template, methods in specification["paths"].items():
            concrete = "/synthetic" + template
            expression = re.sub(r"\{[a-z_]+\}", r"[^/]+", concrete)
            if re.fullmatch(expression, request.path) and request.method.lower() in methods:
                matches.append((platform, methods[request.method.lower()]["operationId"], concrete))
    if len(matches) != 1:
        raise OperationBindingError("verified_operation_unknown_or_ambiguous")
    platform, operation_id, path_template = matches[0]
    return VerifiedOperationBinding(
        platform=platform, operation_id=operation_id, method=request.method,
        path_template=path_template,
        request_fingerprint=fingerprint_request(request),
        request_body_sha256=hashlib.sha256(request.body).hexdigest(),
    )
