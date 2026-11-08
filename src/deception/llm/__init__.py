"""受限的本機 Pydantic AI 介面；local 與測試模型明確區分。"""

from .budget import BudgetExceeded, RunBudget
from .models import LLMConfig, RunLimits

__all__ = ["BudgetExceeded", "LLMConfig", "RunBudget", "RunLimits", "PydanticAIBackend"]


def __getattr__(name):
    """只有實際使用 backend 時載入 agent 依賴，便於其他工具各自使用。"""
    if name == "PydanticAIBackend":
        from .backend import PydanticAIBackend
        return PydanticAIBackend
    raise AttributeError(name)
