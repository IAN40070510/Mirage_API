"""原生合成購物車與訂單共用的 UTC 邏輯時間完整性檢查。"""

from collections.abc import Mapping
from datetime import datetime


def validate_native_times(context: Mapping) -> str:
    """檢查已保存的建立／更新／可選訂單時間並回傳最新更新時間。

    只接受伺服器使用的 UTC 毫秒表示及 created <= order <= updated 順序。
    缺失、格式或順序錯誤皆 ValueError；不修改輸入、不回填不明歷史，
    回傳值只供業務邏輯時間使用，不能替代授權或 Lease 時鐘。
    """
    if not isinstance(context, Mapping):
        raise ValueError("invalid native event time")
    names = ["created_at", "updated_at"]
    if "order_created_at" in context:
        names.append("order_created_at")
    for name in names:
        value = context.get(name)
        if not isinstance(value, str):
            raise ValueError("invalid native event time")
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if (parsed.tzinfo is None or parsed.utcoffset().total_seconds() != 0
                or parsed.isoformat(timespec="milliseconds").replace("+00:00", "Z") != value):
            raise ValueError("invalid native event time")
    # 固定 UTC 毫秒表示可直接按字典順序比較，不把不同時區混為同一格式。
    if (context["updated_at"] < context["created_at"] or ("order_created_at" in context
            and not context["created_at"] <= context["order_created_at"] <= context["updated_at"])):
        raise ValueError("invalid native event time order")
    return context["updated_at"]
