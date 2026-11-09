"""僅識別的診斷入口；設定由明確覆寫或所選領域 manifest 提供，不執行內容生成。"""

import os
from pathlib import Path

from fastapi.responses import JSONResponse

from deception.discovery import PlatformIdentifier, RuntimeContext
from deception.domains.assets import resolve_identification_paths

from .app import create_app as create_ingress_app


def make_identification_handler(identifier: PlatformIdentifier, *, context: RuntimeContext | None = None):
    """把伺服器提供的 runtime context 綁到 A handler，不讀 HTTP 自稱的環境 header。"""
    async def identify(request):
        """將標準化請求交給 B，回傳識別失敗或尚未串接協調器的診斷回應。"""
        result = identifier.identify_request(request, context=context)
        if result.decision != "identified":
            return JSONResponse(status_code=409, content={"code": "identification_unverifiable",
                                "request_id": request.request_id,
                                "errors": [issue.model_dump() for issue in result.errors]})
        # 對外診斷只回傳身份，不回顯 path 參數、query、body 或 Authorization。
        identity = result.identity.model_dump(exclude={"path_parameters", "query", "base_url"})
        return JSONResponse(status_code=501, content={"code": "orchestrator_not_implemented",
                            "request_id": request.request_id, "identification": identity})
    return identify


def create_app():
    """給 uvicorn --factory 使用；設定錯誤會使啟動失敗，不選用猜測綁定。"""
    platforms, bindings = resolve_identification_paths(
        Path(os.environ["MIRAGE_PLATFORMS_DIR"]) if os.environ.get("MIRAGE_PLATFORMS_DIR") else None,
        Path(os.environ["MIRAGE_BINDINGS_FILE"]) if os.environ.get("MIRAGE_BINDINGS_FILE") else None)
    identifier = PlatformIdentifier.from_paths(platforms, bindings)
    values = [os.environ.get(name) for name in (
        "MIRAGE_ENVIRONMENT_ID", "MIRAGE_DEPLOYMENT_ID", "MIRAGE_SERVICE_ID")]
    if any(values) and not all(values):
        raise ValueError("All three runtime context IDs must be supplied together")
    context = RuntimeContext(environment_id=values[0], deployment_id=values[1], service_id=values[2]) if all(values) else None
    return create_ingress_app(make_identification_handler(identifier, context=context))
