"""由領域供應器驗證後交給回應組合器的通用資料投影。"""

from pydantic import JsonValue

from .models import DatasetScope, SyntheticModel


class CompositionData(SyntheticModel):
    """綁定同一 scope 的 JSON payload；格式本身不是來源認證或業務資料驗證。"""

    scope: DatasetScope
    payload: dict[str, JsonValue]
