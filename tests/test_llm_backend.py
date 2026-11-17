"""本機模型身份與結構輸出回歸；使用 HTTP MockTransport，不啟動或下載真模型。"""

import asyncio
import json

import httpx2
import pytest
from pydantic import ConfigDict, Field, JsonValue, create_model
from pydantic_ai.messages import ModelResponse, TextPart, ToolCallPart
from pydantic_ai.models.function import FunctionModel

from deception.generation import GenerationIntent
from deception.llm import LLMConfig, PydanticAIBackend, RunBudget, RunLimits


@pytest.mark.parametrize("change", [{"temperature": 0.75}, {"max_output_tokens": 256}])
def test_model_identity_records_the_decoding_recipe(change):
    """權重相同但解碼設定改變時，追溯與生成快取必須使用不同模型執行身份。"""
    common = dict(model_name="local-audit:latest", model_digest="0" * 64, temperature=0.0, max_output_tokens=512)
    original = LLMConfig(**common).identity_fields()
    altered = LLMConfig(**dict(common, **change)).identity_fields()
    assert original != altered
    for key, value in change.items():
        assert altered[key] == value


@pytest.mark.parametrize("digest_changes", [None, "before_request", "after_request"])
def test_local_inference_verifies_pinned_digest_before_and_after_each_request(digest_changes):
    """模型 tag 在推論前或期間換權重都拒絕，不能把新模型內容誤記為舊 digest。"""
    config = LLMConfig(model_name="local-audit:latest", model_digest="0" * 64)
    calls = []
    state = {"inferred": False}

    async def transport(request):
        """只回本地 API 的固定測試回應；任何意外路徑都直接使測試失敗。"""
        path = request.url.path
        calls.append(path)
        if path == "/api/tags":
            changed = digest_changes == "before_request" or (
                digest_changes == "after_request" and state["inferred"])
            return httpx2.Response(200, json={"models": [{
                "name": config.model_name, "model": config.model_name,
                "digest": ("1" if changed else "0") * 64, "details": {},
            }]})
        if path == "/api/version":
            return httpx2.Response(200, json={"version": "synthetic-runtime-v1"})
        if path == "/v1/chat/completions":
            state["inferred"] = True
            return httpx2.Response(200, json={
                "id": "chatcmpl-synthetic", "object": "chat.completion", "created": 0,
                "model": config.model_name,
                "choices": [{"index": 0, "message": {"role": "assistant",
                             "content": json.dumps({"label-text": "A synthetic generated value"})},
                             "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 10, "completion_tokens": 6, "total_tokens": 16},
            })
        raise AssertionError(f"Unexpected local test request: {path}")

    async def execute():
        """以測試傳輸層執行一次本機生成，並在成功或失敗時關閉 backend。"""
        backend = PydanticAIBackend(config)
        original_transport = backend._http._transport
        # 相容 SDK 與 metadata 共用這個 client；換 transport 不會發出真正網路連線。
        backend._http._transport = httpx2.MockTransport(transport)
        await original_transport.aclose()
        output_type = create_model("SyntheticOutput", __config__=ConfigDict(extra="forbid", strict=True),
                                   field_0=(JsonValue, Field(..., alias="label-text")))
        try:
            return await backend.generate("Generate the declared synthetic field.", output_type, RunBudget(RunLimits()))
        finally:
            await backend.aclose()

    if digest_changes is None:
        result = asyncio.run(execute())
        assert result.model_dump(by_alias=True) == {"label-text": "A synthetic generated value"}
        assert calls.count("/api/tags") >= 2
        assert calls.count("/v1/chat/completions") == 1
    else:
        with pytest.raises(Exception):
            asyncio.run(execute())
        assert calls.count("/v1/chat/completions") == (0 if digest_changes == "before_request" else 1)
        if digest_changes == "after_request":
            assert calls.count("/api/tags") >= 2


def _structured_action_backend(responses):
    """以純 JSON 文字提供動作，不使用 native ToolCallPart 或真正 Ollama 服務。"""
    calls = []

    async def planner(messages, info):
        """每一步均經 NativeOutput 解碼，確認 completion-only 模型可以參與規劃。"""
        assert info.output_tools == []
        calls.append(messages)
        return ModelResponse(parts=[TextPart(json.dumps(responses[len(calls) - 1]))])

    async def unused_generator(messages, info):
        """規劃必須使用 planner 模型，不能意外切換到 G 的模型實例。"""
        raise AssertionError("Structured planning must not invoke the generator model")

    config = LLMConfig(execution_mode="test", model_name="completion-only-test", model_digest="0" * 64,
                       planner_mode="structured_actions")
    return PydanticAIBackend(config, planner_model=FunctionModel(planner),
                             generator_model=FunctionModel(unused_generator)), calls


def test_structured_actions_read_contract_once_then_return_a_typed_plan():
    """主機先讀契約並放進首輪觀察，只用一次推論完成計畫且保留工具計數。"""
    backend, calls = _structured_action_backend([
        {"action": "complete", "result": {"field_ids": ["description"], "instructions": ""}},
    ])
    executed = []
    budget = RunBudget(RunLimits())

    def read_contract():
        """Read the bound synthetic contract without altering its identity."""
        executed.append("read_contract")
        return {"description": {"type": "string"}}

    async def execute():
        """讓結構化動作模型讀取已綁定契約並回傳型別化計畫，最後釋放資源。"""
        try:
            return await backend.plan("Plan the permitted synthetic fields.", {"read_contract": read_contract},
                                      GenerationIntent, budget)
        finally:
            await backend.aclose()

    result = asyncio.run(execute())
    assert result == GenerationIntent(field_ids=["description"], instructions="")
    assert executed == ["read_contract"]
    assert len(calls) == budget.requests == 1
    assert budget.tool_calls == 1
    task = json.loads(calls[0][-1].parts[0].content)
    assert task["observations"] == [{"tool": "read_contract", "value": {"description": {"type": "string"}}}]
    assert "read_contract" not in task["available_tools"]


@pytest.mark.parametrize("failure", ["unknown_action", "tool_budget"])
def test_structured_actions_reject_unknown_or_over_budget_tools_before_execution(failure):
    """嚴格動作 schema 與工具預算均在主機執行前拒絕，不能藉純文字動作越權。"""
    action = "erase_files" if failure == "unknown_action" else "read_facts"
    backend, calls = _structured_action_backend([{"action": action, "result": None}])
    executed = []
    budget = RunBudget(RunLimits(max_tool_calls=0 if failure == "tool_budget" else 8))

    def read_facts():
        """Read the synthetic facts only when the host permits this action."""
        executed.append("read_facts")
        return {"type": "object"}

    async def execute():
        """送出越權或超額的規劃動作，確認失敗前不執行任何受控工具。"""
        try:
            return await backend.plan("Plan synthetic fields.", {"read_facts": read_facts},
                                      GenerationIntent, budget)
        finally:
            await backend.aclose()

    with pytest.raises(Exception):
        asyncio.run(execute())
    assert executed == []
    assert len(calls) == budget.requests == 1
    assert budget.tool_calls == 0


@pytest.mark.parametrize("failure", ["budget", "oversized", "exception", "timeout"])
def test_prefetched_contract_failure_stops_before_model_request(failure):
    """必需契約超額、逾期或讀取失敗時停止，不能發出缺少契約的模型請求。"""
    backend, calls = _structured_action_backend([])
    budget = RunBudget(RunLimits(max_tool_calls=0 if failure == "budget" else 8))
    executed = []

    async def read_contract():
        """模擬非同步契約讀取的大小、例外與逾期邊界，不存取外部服務。"""
        executed.append("read_contract")
        if failure == "exception":
            raise ValueError("Synthetic contract unavailable")
        if failure == "timeout":
            budget.started -= budget.limits.timeout_seconds + 1
        return "x" * 65536 if failure == "oversized" else {"type": "object"}

    async def execute():
        """在同一預算內預讀契約，失敗後仍關閉測試 backend。"""
        try:
            return await backend.plan("Plan synthetic fields.", {"read_contract": read_contract},
                                      GenerationIntent, budget)
        finally:
            await backend.aclose()

    with pytest.raises(Exception):
        asyncio.run(execute())
    assert calls == [] and budget.requests == 0
    assert executed == ([] if failure == "budget" else ["read_contract"])
    assert budget.tool_calls == (0 if failure == "budget" else 1)


def test_optional_async_read_uses_prefetched_contract_and_shared_budget():
    """契約預讀後仍可選擇非同步事實工具，觀察持續累積且工具只執行一次。"""
    backend, calls = _structured_action_backend([
        {"action": "read_facts", "result": None},
        {"action": "complete", "result": {"field_ids": ["description"], "instructions": ""}},
    ])
    budget = RunBudget(RunLimits(max_model_requests=2, max_tool_calls=2))
    executed = []

    def read_contract():
        """回傳本次固定欄位契約並記錄它先於事實工具執行。"""
        executed.append("read_contract")
        return {"description": {"type": "string"}}

    async def read_facts():
        """以非同步介面提供固定合成事實，不建立任何網路連線。"""
        executed.append("read_facts")
        return {"title": "Synthetic product"}

    async def execute():
        """執行兩輪結構規劃並確保成功後關閉測試 backend。"""
        try:
            return await backend.plan("Plan synthetic fields.",
                                      {"read_contract": read_contract, "read_facts": read_facts},
                                      GenerationIntent, budget)
        finally:
            await backend.aclose()

    assert asyncio.run(execute()) == GenerationIntent(field_ids=["description"], instructions="")
    assert executed == ["read_contract", "read_facts"]
    assert len(calls) == budget.requests == budget.tool_calls == 2
    task = json.loads(calls[-1][-1].parts[0].content)
    assert task["available_tools"] == {}
    assert task["observations"] == [
        {"tool": "read_contract", "value": {"description": {"type": "string"}}},
        {"tool": "read_facts", "value": {"title": "Synthetic product"}},
    ]


def test_prefetched_contract_cannot_be_read_again_by_model():
    """預讀後的契約不再是合法動作，模型要求重讀必須拒絕且不能重複執行。"""
    backend, calls = _structured_action_backend([{"action": "read_contract", "result": None}])
    budget = RunBudget(RunLimits())
    executed = []

    def read_contract():
        """回傳已綁定的契約並記錄主機讀取次數。"""
        executed.append("read_contract")
        return {"type": "object"}

    async def execute():
        """嘗試重讀已完成工具，確認動作解碼失敗後釋放資源。"""
        try:
            return await backend.plan("Plan synthetic fields.", {"read_contract": read_contract},
                                      GenerationIntent, budget)
        finally:
            await backend.aclose()

    with pytest.raises(Exception):
        asyncio.run(execute())
    assert executed == ["read_contract"]
    assert len(calls) == budget.requests == budget.tool_calls == 1


def test_backend_prompt_revision_changes_verified_model_identity(monkeypatch):
    """相同模型與政策換用共用提示時，模型身份改變以隔離先前內容快取。"""
    from deception.llm import backend as backend_module

    backend, calls = _structured_action_backend([])

    async def execute():
        """比較兩版提示的核對身份，不呼叫模型或讀取本機服務。"""
        try:
            original = await backend.check_ready(RunBudget(RunLimits()))
            monkeypatch.setattr(backend_module, "PROMPT_SHA256", "1" * 64)
            changed = await backend.check_ready(RunBudget(RunLimits()))
            return original, changed
        finally:
            await backend.aclose()

    original, changed = asyncio.run(execute())
    assert original != changed
    assert changed["prompt_sha256"] == "1" * 64
    assert calls == []


def test_planner_generation_and_repair_apply_independent_output_budgets():
    """三種任務實際送出不同輸出額度，修正不重置共同模型請求預算。"""
    received = []

    async def model(messages, info):
        """記錄框架收到的解碼設定，再回傳該任務要求的合法結構。"""
        received.append(info.model_settings)
        if info.output_tools:
            return ModelResponse(parts=[ToolCallPart(info.output_tools[0].name,
                                                     {"field_ids": ["description"], "instructions": ""})])
        return ModelResponse(parts=[TextPart('{"text":"A valid value"}')])

    config = LLMConfig(execution_mode="test", model_name="task-test", model_digest="0" * 64,
                       tasks={"planner": {"max_output_tokens": 111}, "generation": {"max_output_tokens": 222},
                              "repair": {"max_output_tokens": 333}})
    backend = PydanticAIBackend(config, planner_model=FunctionModel(model), generator_model=FunctionModel(model))
    output = create_model("TaskOutput", text=(str, ...))
    budget = RunBudget(RunLimits(max_model_requests=3))

    async def execute():
        """依次執行三種任務並在完成後關閉相同測試後端。"""
        try:
            await backend.plan("Plan allowed fields.", {}, GenerationIntent, budget)
            await backend.generate("Generate text.", output, budget)
            await backend.generate_repair("Repair text.", output, budget)
        finally:
            await backend.aclose()

    asyncio.run(execute())
    assert [settings["max_tokens"] for settings in received] == [111, 222, 333]
    assert budget.requests == 3
    assert {task: row["requests"] for task, row in budget.audit()["tasks"].items()} == {
        "planner": 1, "generation": 1, "repair": 1}
    assert all(row["token_usage_complete"] for row in budget.audit()["tasks"].values())


@pytest.mark.parametrize("profile", [
    {"model_name": "other"}, {"model_digest": "1" * 64},
    {"model_name": "remote-cloud", "model_digest": "1" * 64},
    {"model_name": "model with whitespace", "model_digest": "1" * 64},
])
def test_task_model_profiles_reject_incomplete_or_nonlocal_model_identity(profile):
    """任務覆寫不能繞過配對摘要、本機模型名稱與 cloud 拒絕規則。"""
    with pytest.raises(ValueError):
        LLMConfig(model_name="base", model_digest="0" * 64, tasks={"generation": profile})


def test_selected_task_models_all_require_their_own_pinned_metadata():
    """另一任務的模型存在但摘要不符時仍拒絕，不能只核對基準模型。"""
    config = LLMConfig(model_name="base", model_digest="0" * 64,
                       tasks={"repair": {"model_name": "stronger-local", "model_digest": "1" * 64}})
    assert config.for_task("repair").model_name == "stronger-local"
    identity = config.identity_fields()
    assert identity["tasks"]["repair"]["model_digest"] == "1" * 64
    with pytest.raises(ValueError, match="pinned"):
        PydanticAIBackend._verify_selected_model(config.for_task("repair"),
                                                [{"name": "stronger-local", "digest": "2" * 64}])


@pytest.mark.parametrize("input_tokens,output_tokens", [(None, None), (0, 0), (-1, 2)])
def test_task_usage_never_reports_missing_or_invalid_provider_usage_as_complete(input_tokens, output_tokens):
    """失敗、全零或無效 usage 必須標成未知部分，後續成功回報也不能掩蓋它。"""
    budget = RunBudget(RunLimits())
    budget.record_model_result("generation", elapsed_ms=5, input_tokens=input_tokens, output_tokens=output_tokens)
    budget.record_model_result("generation", elapsed_ms=7, input_tokens=10, output_tokens=2)
    row = budget.audit()["tasks"]["generation"]
    assert row == {"requests": 2, "elapsed_ms": 12, "input_tokens": 10, "output_tokens": 2,
                   "token_usage_complete": False}
