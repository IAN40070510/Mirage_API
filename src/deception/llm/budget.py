"""以單調時鐘維護全 run 預算，包含失敗的工具嘗試及模型實際回報用量。"""

import time

from .models import RunLimits


class BudgetExceeded(ValueError):
    """固定錯誤碼，避免模型或傳輸錯誤把敏感內容寫入診斷。"""

    def __init__(self, code: str):
        """保存超額或期限錯誤碼，讓上層回報預算失敗而不帶入模型內容。"""
        self.code = code
        super().__init__(code)


class RunBudget:
    """由 C 建立、傳給 planner 和 generator；provider 不得另外重置額度。"""

    def __init__(self, limits: RunLimits):
        """保存嚴格設定副本並從建立時開始計時。"""
        self.limits = RunLimits.model_validate(limits.model_dump())
        self.started = time.monotonic()
        self.requests = self.tool_calls = self.input_tokens = self.output_tokens = 0

    def remaining(self) -> float:
        """剩餘時間小於零即拒絕下一步，供 asyncio.timeout 共用。"""
        remaining = self.limits.timeout_seconds - (time.monotonic() - self.started)
        if remaining <= 0:
            raise BudgetExceeded("deadline_exceeded")
        return remaining

    def check(self) -> None:
        """每個主要階段前後確認仍在總期限內。"""
        self.remaining()

    def consume_request(self) -> None:
        """在發出模型請求前計數，失敗的請求也不能免費重試。"""
        self.check()
        if self.requests >= self.limits.max_model_requests:
            raise BudgetExceeded("model_request_limit")
        self.requests += 1

    def consume_tools(self, count: int = 1) -> None:
        """執行任何函式前計工具嘗試，包括未知名稱或無效參數。"""
        self.check()
        if type(count) is not int or count < 0:
            raise ValueError("Tool count must be a nonnegative integer")
        if self.tool_calls + count > self.limits.max_tool_calls:
            raise BudgetExceeded("tool_call_limit")
        self.tool_calls += count

    def consume_tokens(self, input_tokens: int, output_tokens: int) -> None:
        """累積回報 token；超額的回應不交給下一階段，也不產生候選。"""
        self.check()
        if any(type(value) is not int or value < 0 for value in (input_tokens, output_tokens)):
            raise ValueError("Token counts must be nonnegative integers")
        self.input_tokens += input_tokens
        self.output_tokens += output_tokens
        if self.input_tokens > self.limits.max_input_tokens:
            raise BudgetExceeded("input_token_limit")
        if self.output_tokens > self.limits.max_output_tokens:
            raise BudgetExceeded("output_token_limit")

    def audit(self) -> dict:
        """只輸出用量與時間，不保存模型推理文字或原始請求。"""
        return dict(model_requests=self.requests, tool_calls=self.tool_calls,
                    input_tokens=self.input_tokens, output_tokens=self.output_tokens,
                    elapsed_ms=round((time.monotonic() - self.started) * 1000))
