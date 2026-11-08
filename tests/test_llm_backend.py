"""本機模型身份與結構輸出回歸；使用 HTTP MockTransport，不啟動或下載真模型。"""

import asyncio
import json

import httpx2
import pytest
from pydantic import ConfigDict, Field, JsonValue, create_model
from pydantic_ai.messages import ModelResponse, TextPart
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
    """沒有原生工具呼叫的模型仍可先讀契約再完成，主機執行工具並累計共用預算。"""
    backend, calls = _structured_action_backend([
        {"action": "read_contract", "result": None},
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
    assert len(calls) == budget.requests == 2
    assert budget.tool_calls == 1


@pytest.mark.parametrize("failure", ["unknown_action", "tool_budget"])
def test_structured_actions_reject_unknown_or_over_budget_tools_before_execution(failure):
    """嚴格動作 schema 與工具預算均在主機執行前拒絕，不能藉純文字動作越權。"""
    action = "erase_files" if failure == "unknown_action" else "read_contract"
    backend, calls = _structured_action_backend([{"action": action, "result": None}])
    executed = []
    budget = RunBudget(RunLimits(max_tool_calls=0 if failure == "tool_budget" else 8))

    def read_contract():
        """Read the synthetic contract only when the host permits this action."""
        executed.append("read_contract")
        return {"type": "object"}

    async def execute():
        """送出越權或超額的規劃動作，確認失敗前不執行任何受控工具。"""
        try:
            return await backend.plan("Plan synthetic fields.", {"read_contract": read_contract},
                                      GenerationIntent, budget)
        finally:
            await backend.aclose()

    with pytest.raises(Exception):
        asyncio.run(execute())
    assert executed == []
    assert len(calls) == budget.requests == 1
    assert budget.tool_calls == 0
