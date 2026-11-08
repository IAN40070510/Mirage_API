"""既有鎖版 OpenAPI 驗證器的共同載入相容處理，原始來源保持不變。"""

import copy

from openapi_core import OpenAPI


def create_openapi(spec: dict, config=None) -> OpenAPI:
    """paths 的 x-* 是註記；0.19.5 依賴的檢查器卻可能把它當成 Path Item。"""
    effective = copy.deepcopy(spec)
    if isinstance(effective.get("paths"), dict):
        effective["paths"] = {key: value for key, value in effective["paths"].items() if not key.startswith("x-")}
    # 只排除路由表的擴充註記，保留所有真正 path、參數、response 與 schema 限制。
    # 若契約以 $ref 指向被排除的擴充內容，這個版本仍會拒絕載入，不猜測其語意。
    return OpenAPI.from_dict(effective, config=config)
