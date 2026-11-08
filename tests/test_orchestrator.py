"""C 的強制流程驗證：可信請求、總預算及 F/G/H/I 交接不可由模型繞過。"""

import asyncio
import copy
import hashlib
import json
from dataclasses import replace
from datetime import timedelta
from types import SimpleNamespace

import pytest
from pydantic_ai.messages import ModelResponse, TextPart

from deception.generation import GenerationIntent
from deception.generation import ContentCache
from deception.llm import LLMConfig, RunBudget, RunLimits
from deception.synthetic import generate_dataset

from test_generation import function_backend, generation_stack, make_pipeline, run_pipeline
from test_scenarios import NOW, assessment_for, request_for


def test_missing_product_is_generated_with_404_contract(generation_stack):
    """F 判定不存在後，只允許生成錯誤說明，狀態與 not_found 事實維持一致。"""
    stack = generation_stack
    backend, calls = function_backend(field_id="message", value="The synthetic product could not be found.")
    pipeline, _, _ = make_pipeline(stack, backend=backend)
    request = request_for("prod-missing", request_id="cg-missing-request")
    result = run_pipeline(stack, pipeline, request=request)
    assert result.decision == "validated", result
    assert result.candidate.status_code == 404
    assert json.loads(result.candidate.body) == {
        "type": "not_found", "message": "The synthetic product could not be found."}
    assert result.gate_result.valid is True and calls["generator"]


@pytest.mark.parametrize("assessment_changes", [
    {"source_id": "untrusted"}, {"request_fingerprint": "0" * 64},
    {"request_id": "different-request"}, {"deployment_id": "different-deployment"},
])
def test_untrusted_or_unrelated_assessment_stops_before_any_model_call(generation_stack, assessment_changes):
    """C 必須先完成 B/D/F 信任檢查，模型不可自行決定跳過判定關聯。"""
    stack = generation_stack
    pipeline, _, calls = make_pipeline(stack)
    result = run_pipeline(stack, pipeline, assessment=assessment_for(stack["request"], **assessment_changes))
    assert result.decision == "unverifiable" and result.candidate is None, result
    assert calls == {"planner": [], "generator": []}


def test_benign_assessment_does_not_run_generation(generation_stack):
    """正常判定不觸發誘餌生成，也不把 not_applicable 當成自動轉送。"""
    stack = generation_stack
    pipeline, _, calls = make_pipeline(stack)
    result = run_pipeline(stack, pipeline, assessment=assessment_for(stack["request"], verdict="benign"))
    assert result.decision == "not_applicable" and result.candidate is None, result
    assert calls == {"planner": [], "generator": []}


def test_generation_config_must_match_the_prepared_run_scope(generation_stack):
    """C 不可為了讓資料可用而把另一個 run 的 E 產物重新標記。"""
    stack = generation_stack
    pipeline, _, calls = make_pipeline(stack)
    other = stack["config"].model_copy(update={"scope": stack["config"].scope.model_copy(update={"run_id": "other-run"})})
    result = run_pipeline(stack, pipeline, config=other)
    assert result.decision == "unverifiable" and result.candidate is None, result
    assert calls == {"planner": [], "generator": []}


def test_loaded_dataset_is_checked_against_the_requested_config(generation_stack):
    """相同 scope 下不同種子的合法 E 快照也不能取代呼叫端指定的設定。"""
    stack = generation_stack
    pipeline, _, calls = make_pipeline(stack)
    other_config = stack["config"].model_copy(update={"seed": stack["config"].seed + 1})
    other = generate_dataset(other_config)
    result = run_pipeline(stack, pipeline, dataset=other)
    assert result.decision == "unverifiable" and result.candidate is None, result
    assert calls == {"planner": [], "generator": []}


def test_planner_cannot_request_a_field_from_another_outcome(generation_stack):
    """found 情境不能採用 missing 的生成欄位，即使兩個欄位都存在於政策。"""
    backend, calls = function_backend(field_id="message", value="This belongs to a missing product.")
    pipeline, _, _ = make_pipeline(generation_stack, backend=backend)
    result = run_pipeline(generation_stack, pipeline)
    assert result.decision != "validated" and result.candidate is None, result
    assert calls["planner"] and calls["generator"] == []


def test_unknown_tool_call_is_not_executed(generation_stack):
    """模型要求任意網路／檔案工具時，受控工具表與零隱藏重試必須拒絕。"""
    backend, calls = function_backend(tool_name="read_arbitrary_file")
    pipeline, _, _ = make_pipeline(generation_stack, backend=backend)
    result = run_pipeline(generation_stack, pipeline)
    assert result.decision != "validated" and result.candidate is None, result
    assert calls["generator"] == []


def test_model_request_budget_is_shared_between_planner_and_generator(generation_stack):
    """規劃已耗用模型總預算時，不可讓 G 另開不計數的模型呼叫。"""
    stack = generation_stack
    policy_data = copy.deepcopy(stack["policy_data"])
    policy_data["limits"] = {"max_model_requests": 2}
    pipeline, _, calls = make_pipeline(stack, policy_data=policy_data)
    result = run_pipeline(stack, pipeline)
    assert result.decision != "validated" and result.candidate is None, result
    assert len(calls["planner"]) == 2 and calls["generator"] == []


def test_generator_exception_cannot_return_a_partially_composed_response(generation_stack):
    """模型服務錯誤只回失敗結果，不能把空描述模板當成已驗證回應輸出。"""
    async def failing_model(messages, info):
        """模擬模型服務拋錯，確認協調器不會把未生成的模板當成成功候選。"""
        raise RuntimeError("simulated model service failure")

    backend, _ = function_backend(generator_function=failing_model)
    pipeline, _, _ = make_pipeline(generation_stack, backend=backend)
    result = run_pipeline(generation_stack, pipeline)
    assert result.decision != "validated" and result.candidate is None, result


def test_total_deadline_cancels_generation(generation_stack):
    """單一生成呼叫慢於總期限時應取消，不等待模型自行結束。"""
    async def slow_model(messages, info):
        """延遲至共用期限之外，以驗證生成取消及失敗關閉。"""
        await asyncio.sleep(1.2)
        return ModelResponse(parts=[TextPart('{"description":"This response should arrive too late."}')])

    stack = generation_stack
    backend, _ = function_backend(generator_function=slow_model)
    policy_data = copy.deepcopy(stack["policy_data"])
    policy_data["limits"] = {"timeout_seconds": 1}
    pipeline, _, _ = make_pipeline(stack, backend=backend, policy_data=policy_data)
    result = run_pipeline(stack, pipeline)
    assert result.decision != "validated" and result.candidate is None, result


def test_authentication_headers_are_not_exposed_to_model_prompts_or_trace(generation_stack):
    """原請求的憑證僅用於指紋關聯，不加入模型上下文或診斷輸出。"""
    stack = generation_stack
    secret = "Bearer synthetic-test-credential-do-not-forward"
    request = replace(stack["request"], headers=stack["request"].headers + (("authorization", secret),))
    pipeline, _, calls = make_pipeline(stack)
    result = run_pipeline(stack, pipeline, request=request)
    assert result.decision == "validated", result
    assert secret not in repr(calls)
    assert secret not in json.dumps(result.trace, ensure_ascii=False)


def test_unknown_tool_attempt_is_charged_before_argument_validation():
    """未知工具即使沒有執行成功，仍消耗共用工具預算，不可免費重試。"""
    backend, calls = function_backend(tool_name="read_arbitrary_file")
    budget = RunBudget(RunLimits())
    executed = []

    def read_facts():
        """只允許本次已核對的唯讀事實，不接受模型指定檔案或 URL。"""
        executed.append(True)
        return {"product_id": "synthetic"}

    with pytest.raises(Exception):
        asyncio.run(backend.plan("Plan the allowed synthetic fields.", {"read_facts": read_facts},
                                 GenerationIntent, budget))
    assert budget.requests == 1 and budget.tool_calls == 1
    assert executed == [] and calls["generator"] == []


def test_zero_tool_budget_stops_before_executing_a_registered_function():
    """即使模型提出合法工具，工具總額為零時也不能先執行再報超限。"""
    backend, calls = function_backend()
    budget = RunBudget(RunLimits(max_tool_calls=0))
    executed = []

    def read_facts():
        """用明確副作用紀錄證明預算檢查早於工具執行。"""
        executed.append(True)
        return {"product_id": "synthetic"}

    with pytest.raises(Exception):
        asyncio.run(backend.plan("Plan the allowed synthetic fields.", {"read_facts": read_facts},
                                 GenerationIntent, budget))
    assert budget.requests == 1
    assert executed == [] and calls["generator"] == []


@pytest.mark.parametrize("url", [
    "https://127.0.0.1:11434/v1", "http://models.example/v1", "http://127.0.0.1:11434/v1?remote=1",
    "http://name:secret@127.0.0.1:11434/v1", "http://127.0.0.1:11434/other",
])
def test_model_endpoint_is_an_explicit_local_configuration(url):
    """本機模式不接受雲端、代理路徑或含帳密／query 的 endpoint。"""
    with pytest.raises(ValueError):
        LLMConfig(model_name="local-test", model_digest="0" * 64, base_url=url)


def test_assessment_expiring_during_cache_publication_cannot_return_validated(generation_stack, monkeypatch):
    """發布可能耗時；即使 H/I 先通過，回傳前已到期的判定也不能繼續當成有效授權。"""
    import deception.core.orchestrator as orchestrator_module

    clock = {"elapsed": 0.0}
    # 只控制 C 的 UTC 換算來源，asyncio 與 RunBudget 仍使用真正的單調時鐘。
    monkeypatch.setattr(orchestrator_module, "time", SimpleNamespace(monotonic=lambda: clock["elapsed"]))

    class SlowPublish(ContentCache):
        def __init__(self):
            """保存發布是否已經發生，避免測試只在前面的 F 檢查就提前失敗。"""
            super().__init__()
            self.called = False

        def publish(self, key, values):
            """模擬同步儲存耗時一秒，使有效期在發布期間越過截止點。"""
            self.called = True
            clock["elapsed"] += 1.0
            return super().publish(key, values)

    stack = generation_stack
    cache = SlowPublish()
    pipeline, _, calls = make_pipeline(stack, cache=cache)
    assessment = assessment_for(stack["request"], expires_at=NOW + timedelta(seconds=0.5))
    result = run_pipeline(stack, pipeline, assessment=assessment)
    assert cache.called is True, "The assessment must expire during publication, after the first H/I check"
    assert calls["generator"], "A real generation attempt must precede the publication boundary"
    assert result.decision == "unverifiable" and result.candidate is None, result
    assert result.errors
    cache.close()


def test_racing_cache_winner_is_the_content_recorded_in_the_final_trace(generation_stack):
    """競爭快取勝出值必須重新通過 H/I，追溯摘要與原請求 scope 也須對應最終候選。"""
    winner = {"description": "The winning synthetic description from a concurrent validated run."}

    class RacingCache(ContentCache):
        def publish(self, key, values):
            """模擬另一個同鍵 run 已先發布有效值，當前 run 必須使用該勝出內容。"""
            assert values != winner
            return super().publish(key, winner)

    stack = generation_stack
    cache = RacingCache()
    pipeline, _, calls = make_pipeline(stack, cache=cache)
    result = run_pipeline(stack, pipeline)
    assert result.decision == "validated", result
    assert result.gate_result.valid is True and result.gate_result.decision == "pass", result
    assert calls["generator"]
    assert json.loads(result.candidate.body)["product"]["description"] == winner["description"]
    encoded = json.dumps(winner, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    assert result.trace["generation"]["content_sha256"] == hashlib.sha256(encoded).hexdigest()
    assert result.trace["generation"]["cache_winner"] is True
    scope = stack["config"].scope.model_dump(mode="json")
    assert {name: getattr(result.candidate.identity, name) for name in scope} == scope
    assert result.trace["scenario"]["scope"] == scope
    cache.close()


def test_candidate_rejected_by_i_is_never_published_to_content_cache(generation_stack):
    """G/H 成功仍不足以發布；I 拒絕候選時不得讓失敗內容進入可重用快取。"""
    class RecordingCache(ContentCache):
        def __init__(self):
            """以明確紀錄證明快取發布沒有在 I 之前提前發生。"""
            super().__init__()
            self.published = []

        def publish(self, key, values):
            """若控制流程錯誤發布，保存實際嘗試以便回歸斷言。"""
            self.published.append((key, values))
            return super().publish(key, values)

    stack = generation_stack
    cache = RecordingCache()
    pipeline, _, calls = make_pipeline(stack, cache=cache)
    original_gate = pipeline.gate

    class RejectingGate:
        def validate(self, request):
            """先執行真正契約驗證，再模擬部署 gate 的拒絕判定。"""
            result = original_gate.validate(request)
            assert result.valid is True, result
            return result.model_copy(update={"valid": False, "decision": "reject"})

    pipeline.gate = RejectingGate()
    result = run_pipeline(stack, pipeline)
    assert result.decision == "reject" and result.candidate is None, result
    assert calls["generator"]
    assert cache.published == []
    cache.close()
