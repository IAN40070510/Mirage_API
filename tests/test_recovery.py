"""N 的有效性：有限修正、同契約備援、共用預算與資料／判定隔離。"""

import asyncio
import copy
import json
import time
from datetime import timedelta
from types import SimpleNamespace

import pytest
from pydantic import ValidationError
from pydantic_ai.messages import ModelResponse, TextPart

from deception.core.recovery import RecoveryPolicy, RecoveryTool
import deception.core.orchestrator as orchestration
from deception.generation import ContentCache
from deception.generation.models import digest
from mirage_validator.models import ValidationIssue

from test_generation import function_backend, generation_stack, make_pipeline, run_pipeline
from test_scenarios import NOW, assessment_for, request_for


class RecordingCache(ContentCache):
    """記錄真正的發布呼叫，驗證失敗與備援從未寫進模型內容快取。"""

    def __init__(self):
        """建立獨立記憶體快取與發布紀錄。"""
        super().__init__()
        self.published = []

    def publish(self, key, values):
        """保存發布參數後沿用原子快取行為，不替換被測邊界。"""
        self.published.append((key, copy.deepcopy(values)))
        return super().publish(key, values)


def enable_recovery(pipeline, *, outcome="found", values=None, changes=None, enabled=True):
    """依此 pipeline 的精確契約及 F/G 摘要建立一條管理者備援規則。"""
    rule = next(rule for rule in pipeline.generator.policy.rules if rule.outcome_id == outcome)
    fields = ("platform_id", "platform_version", "spec_sha256", "operation_id", "method", "path",
              "outcome_id", "status_code", "media_type")
    fallback = {field: getattr(rule, field) for field in fields}
    fallback.update(rule_id="fallback-" + outcome, generation_rule_id=rule.rule_id,
                    generation_policy_sha256=pipeline.generator.policy_sha256,
                    scenario_policy_sha256=pipeline.scenarios.policy_sha256,
                    values=values if values is not None else {rule.fields[0].field_id: "Reviewed synthetic fallback content."})
    fallback.update(changes or {})
    policy = RecoveryPolicy(domain="ecommerce", policy_id="reviewed-fallback", policy_version="1",
                            enabled=enabled, rules=[fallback])
    pipeline.recovery = RecoveryTool(policy)
    return policy


def test_invalid_generated_content_is_repaired_with_shared_budget(generation_stack):
    """第一次型別錯誤後只重新生成白名單值，成功修正保留相同 E 商品事實。"""
    count = 0

    async def invalid_then_valid(messages, info):
        """先輸出錯誤型別，再輸出合法描述，用真正 Agent 驗證 N 的第二次嘗試。"""
        nonlocal count
        count += 1
        return ModelResponse(parts=[TextPart(json.dumps({"description": 7 if count == 1 else "Repaired synthetic product description."}))])

    backend, calls = function_backend(generator_function=invalid_then_valid)
    pipeline, _, _ = make_pipeline(generation_stack, backend=backend)
    result = run_pipeline(generation_stack, pipeline)
    assert result.decision == "validated", result
    assert result.trace["repairs"] == 1 and count == 2
    assert result.trace["usage"]["model_requests"] == 4
    assert "allowed_content_rejected" in repr(calls["generator"][-1])
    assert json.loads(result.candidate.body)["product"]["id"] == generation_stack["dataset"].products[0].id


def test_exhausted_generation_uses_reviewed_fallback_without_cache_pollution(generation_stack):
    """生成耗盡才用同分支固定值，H/I 通過後仍不發布備援至模型快取。"""
    backend, calls = function_backend(value="bad")
    cache = RecordingCache()
    pipeline, _, _ = make_pipeline(generation_stack, backend=backend, cache=cache)
    enable_recovery(pipeline)
    original = generation_stack["dataset"].model_dump_json()
    result = run_pipeline(generation_stack, pipeline)
    assert result.decision == "validated", result
    assert result.trace["generation"]["source"] == "fallback"
    assert result.trace["generation"]["cache_hit"] is False
    assert result.trace["repairs"] == 1 and len(calls["generator"]) == 2
    assert result.gate_result.valid is True and cache.published == []
    assert json.loads(result.candidate.body)["product"]["description"] == "Reviewed synthetic fallback content."
    assert generation_stack["dataset"].model_dump_json() == original
    cache.close()


def test_missing_product_fallback_preserves_404_outcome(generation_stack):
    """不存在的商品只能使用 missing 的備援，不能改成 found 或 200。"""
    backend, _ = function_backend(field_id="message", value=1)
    pipeline, _, _ = make_pipeline(generation_stack, backend=backend)
    enable_recovery(pipeline, outcome="missing", values={"message": "Reviewed product not found message."})
    result = run_pipeline(generation_stack, pipeline, request=request_for("prod-missing"))
    assert result.decision == "validated" and result.candidate.status_code == 404, result
    assert json.loads(result.candidate.body) == {"type": "not_found", "message": "Reviewed product not found message."}


@pytest.mark.parametrize("values", [{"description": 1}, {"description": "short"}, {"id": "overwritten"},
                                   {"description": "Reviewed synthetic fallback content.", "title": "overwritten"}])
def test_fallback_must_satisfy_the_same_field_schema_and_whitelist(generation_stack, values):
    """備援也拒絕錯誤型別、過短或額外權威欄位，不因管理者提供就跳過 G/H/I。"""
    backend, _ = function_backend(value=False)
    pipeline, _, _ = make_pipeline(generation_stack, backend=backend)
    enable_recovery(pipeline, values=values)
    result = run_pipeline(generation_stack, pipeline)
    assert result.decision == "reject" and result.candidate is None, result
    assert result.errors[0].code == "fallback_rejected"


@pytest.mark.parametrize("changes", [
    {"spec_sha256": "f" * 64}, {"generation_policy_sha256": "f" * 64},
    {"scenario_policy_sha256": "f" * 64}, {"operation_id": "different"},
    {"status_code": 404}, {"outcome_id": "missing"}, {"generation_rule_id": "different"},
])
def test_other_contract_policy_or_branch_is_never_a_fallback(generation_stack, changes):
    """另一版本、政策、操作或結果的固定值不能借用到目前請求。"""
    backend, _ = function_backend(value=0)
    pipeline, _, _ = make_pipeline(generation_stack, backend=backend)
    enable_recovery(pipeline, changes=changes)
    result = run_pipeline(generation_stack, pipeline)
    assert result.decision == "reject" and result.candidate is None, result
    assert result.errors[0].code == "generation_rejected"


def test_disabled_recovery_does_not_return_a_template(generation_stack):
    """停用政策即使帶完整規則，生成失敗時也不得回傳模板。"""
    backend, _ = function_backend(value=0)
    pipeline, _, _ = make_pipeline(generation_stack, backend=backend)
    enable_recovery(pipeline, enabled=False)
    result = run_pipeline(generation_stack, pipeline)
    assert result.decision != "validated" and result.candidate is None


def test_unavailable_model_can_use_fallback_only_after_trust_checks(generation_stack):
    """本機模型不可用時只走確定性備援，仍須先完成 B/D/F/E 身份與資料核對。"""
    pipeline, _, calls = make_pipeline(generation_stack)
    enable_recovery(pipeline)

    async def unavailable(budget):
        """模擬模型服務離線，確定沒有規劃或生成可被誤報為真模型輸出。"""
        raise ConnectionError("private connection diagnostics must not leak")

    pipeline.generator.backend.check_ready = unavailable
    result = run_pipeline(generation_stack, pipeline)
    assert result.decision == "validated", result
    assert result.trace["model"]["provider"] == "not_used"
    assert result.trace["recovery"]["failure_stage"] == "planning_or_model_unavailable"
    assert calls == {"planner": [], "generator": []}
    assert "private connection" not in result.model_dump_json()
    unrelated = assessment_for(generation_stack["request"], request_fingerprint="0" * 64)
    rejected = run_pipeline(generation_stack, pipeline, assessment=unrelated)
    assert rejected.candidate is None and rejected.decision == "unverifiable"


@pytest.mark.parametrize("decision,location", [("unverifiable", "body"), ("reject", "headers"), ("reject", "contract")])
def test_unverifiable_identity_or_http_metadata_is_not_repaired_or_fallback(generation_stack, decision, location):
    """I 的身份不明或 HTTP metadata 錯誤不可用模型修正或備援掩蓋。"""
    pipeline, _, calls = make_pipeline(generation_stack)
    enable_recovery(pipeline)
    gate = pipeline.gate

    class RejectingGate:
        def validate(self, request):
            """保留真實契約身份，再注入非 body 可修正的部署拒絕。"""
            result = gate.validate(request)
            return result.model_copy(update={"valid": False, "decision": decision, "errors": [
                ValidationIssue(location=location, path="", code="deployment_rejected", reason="private diagnostic")]})

    pipeline.gate = RejectingGate()
    result = run_pipeline(generation_stack, pipeline)
    assert result.decision != "validated" and result.candidate is None
    assert len(calls["generator"]) == 1 and "recovery" not in result.trace


def test_body_rejection_is_repaired_and_gate_pass_is_rechecked(generation_stack):
    """I 明確拒絕 body 時可重新生成，但第二份候選仍須獨立經 I 通過。"""
    pipeline, _, calls = make_pipeline(generation_stack)
    gate = pipeline.gate
    seen = []

    class RejectFirstBody:
        def validate(self, request):
            """第一次附固定 body 錯誤，第二次採用真正 gate 的獨立結果。"""
            result = gate.validate(request)
            seen.append(request)
            if len(seen) == 1:
                return result.model_copy(update={"valid": False, "decision": "reject", "errors": [
                    ValidationIssue(location="body", path="/product/description", code="pattern", reason="secret reason")]})
            return result

    pipeline.gate = RejectFirstBody()
    result = run_pipeline(generation_stack, pipeline)
    assert result.decision == "validated" and result.trace["repairs"] == 1, result
    assert len(seen) == 2 and len(calls["generator"]) == 2
    assert "secret reason" not in repr(calls)


def test_gate_rejecting_fallback_returns_no_candidate(generation_stack):
    """模型與備援皆遭 I body 拒絕時，不能拿任何先前 pass 放行。"""
    pipeline, _, _ = make_pipeline(generation_stack)
    enable_recovery(pipeline)
    gate = pipeline.gate

    class RejectEveryBody:
        def validate(self, request):
            """每一份真實可解析候選都追加 body 拒絕，包含固定備援。"""
            result = gate.validate(request)
            return result.model_copy(update={"valid": False, "decision": "reject", "errors": [
                ValidationIssue(location="body", path="", code="pattern", reason="Rejected body")]})

    pipeline.gate = RejectEveryBody()
    result = run_pipeline(generation_stack, pipeline)
    assert result.decision == "reject" and result.candidate is None
    assert result.errors[0].code == "fallback_not_passed"


def test_exhausted_budget_never_activates_fallback(generation_stack):
    """進入 N 不得重設模型額度，預算耗盡也不能繞去備援。"""
    policy_data = copy.deepcopy(generation_stack["policy_data"])
    policy_data["limits"] = {"max_model_requests": 2}
    pipeline, _, calls = make_pipeline(generation_stack, policy_data=policy_data)
    enable_recovery(pipeline)
    result = run_pipeline(generation_stack, pipeline)
    assert result.decision == "unverifiable" and result.candidate is None
    assert result.errors[0].code == "model_request_limit"
    assert calls["generator"] == []


def test_expired_assessment_after_generation_cannot_use_fallback(generation_stack):
    """生成期間 F 判定失效時，模板再合法也不能輸出。"""
    backend, _ = function_backend(value=0)
    pipeline, _, _ = make_pipeline(generation_stack, backend=backend)
    enable_recovery(pipeline)
    resolve = pipeline.scenarios.resolve
    calls = 0

    def expire_after_initial_selection(prepared, data, *, now):
        """第一次選情境正常，其後以過期時間重查同一 seal。"""
        nonlocal calls
        calls += 1
        return resolve(prepared, data, now=now if calls == 1 else NOW + timedelta(days=1))

    pipeline.scenarios.resolve = expire_after_initial_selection
    result = run_pipeline(generation_stack, pipeline)
    assert result.decision == "unverifiable" and result.candidate is None
    assert result.errors[0].code == "context_changed"


def test_cancellation_propagates_instead_of_becoming_fallback(generation_stack):
    """呼叫端取消仍取消整個 run，不生成可用備援或固定失敗候選。"""
    pipeline, _, _ = make_pipeline(generation_stack)
    enable_recovery(pipeline)

    async def cancelled(budget):
        """在模型 readiness 邊界模擬呼叫端取消。"""
        raise asyncio.CancelledError()

    pipeline.generator.backend.check_ready = cancelled
    with pytest.raises(asyncio.CancelledError):
        run_pipeline(generation_stack, pipeline)


def test_data_changed_during_fallback_composition_is_not_released(generation_stack):
    """備援通過 H 也需重查 F 封存資料，組合期間變更 E 時不得放行。"""
    backend, _ = function_backend(value=0)
    pipeline, _, _ = make_pipeline(generation_stack, backend=backend)
    enable_recovery(pipeline)
    project = pipeline.data_provider.composition_data

    def project_then_mutate(data):
        """先建立通用資料投影，再模擬該 run 的原始資料遭其他工作變更。"""
        projected = project(data)
        data.products[0].title = "Changed after composition"
        return projected

    pipeline.data_provider.composition_data = project_then_mutate
    result = run_pipeline(generation_stack, pipeline)
    assert result.decision == "unverifiable" and result.candidate is None, result
    assert result.errors[0].code == "context_changed"


def test_no_repairs_configuration_uses_fallback_after_exactly_one_attempt(generation_stack):
    """max_repairs=0 時首次失敗立即選備援，不暗中重試模型或重新起算預算。"""
    policy_data = copy.deepcopy(generation_stack["policy_data"])
    policy_data["limits"] = {"max_repairs": 0}
    backend, calls = function_backend(value=0)
    pipeline, _, _ = make_pipeline(generation_stack, backend=backend, policy_data=policy_data)
    enable_recovery(pipeline)
    result = run_pipeline(generation_stack, pipeline)
    assert result.decision == "validated" and result.trace["repairs"] == 0, result
    assert len(calls["generator"]) == 1


def test_model_identity_failure_after_generation_does_not_activate_fallback(generation_stack):
    """已生成內容發布前的模型身份核對失敗須停止，不以固定備援掩蓋身份變動。"""
    pipeline, _, _ = make_pipeline(generation_stack)
    enable_recovery(pipeline)
    ready = pipeline.generator.backend.check_ready
    checks = 0

    async def changed_on_final_check(budget):
        """初次模型身份可用，生成後再核對時模擬固定摘要不符。"""
        nonlocal checks
        checks += 1
        if checks > 1:
            raise ValueError("The local model digest changed")
        return await ready(budget)

    pipeline.generator.backend.check_ready = changed_on_final_check
    result = run_pipeline(generation_stack, pipeline)
    assert result.decision == "unverifiable" and result.candidate is None, result
    assert "recovery" not in result.trace


def test_cache_publication_failure_does_not_activate_fallback(generation_stack):
    """快取儲存失敗屬一致性故障，不可被內容備援轉成成功。"""
    class UnavailableCache(ContentCache):
        def publish(self, key, values):
            """模擬實際發布階段的儲存故障。"""
            raise OSError("Private storage diagnostics")

    cache = UnavailableCache()
    pipeline, _, _ = make_pipeline(generation_stack, cache=cache)
    enable_recovery(pipeline)
    result = run_pipeline(generation_stack, pipeline)
    assert result.decision == "unverifiable" and result.candidate is None, result
    assert "recovery" not in result.trace
    assert "Private storage" not in result.model_dump_json()
    cache.close()


def test_release_deadline_stays_anchored_when_clock_reads_are_delayed(generation_stack, monkeypatch):
    """計算回送期限的時鐘讀取有排程延遲時，不得把剩餘秒數重新加到較晚時間。"""
    policy_data = copy.deepcopy(generation_stack["policy_data"])
    policy_data["limits"] = {"timeout_seconds": 10}
    pipeline, _, _ = make_pipeline(generation_stack, policy_data=policy_data)
    reads = 0
    real_clock = time.monotonic

    def delayed_clock():
        """只讓 C 的連續時鐘讀取逐步延後；共用預算仍使用真正的啟動時間。"""
        nonlocal reads
        value = real_clock() + reads * 0.5
        reads += 1
        return value

    monkeypatch.setattr(orchestration, "time", SimpleNamespace(monotonic=delayed_clock))
    before = real_clock()
    result = run_pipeline(generation_stack, pipeline)
    assert result.decision == "validated", result
    assert result.trace["release_deadline_monotonic"] <= before + 10.25


def test_recovery_policy_snapshot_and_duplicate_selectors(generation_stack):
    """工具封存政策副本且拒絕歧義；修改公開副本不會啟用另一組備援值。"""
    pipeline, _, _ = make_pipeline(generation_stack)
    original = enable_recovery(pipeline)
    expected = digest(original.model_dump(mode="json"))
    original.rules[0].values["description"] = "Changed original policy"
    snapshot = pipeline.recovery.policy
    snapshot.enabled = False
    assert pipeline.recovery.policy.enabled is True
    assert pipeline.recovery.policy_sha256 == expected
    duplicated = pipeline.recovery.policy.model_dump(mode="json")
    duplicated["rules"].append({**duplicated["rules"][0], "rule_id": "another-rule"})
    with pytest.raises(ValidationError):
        RecoveryPolicy.model_validate(duplicated)


def test_repair_bypasses_cached_values_rejected_by_current_gate(generation_stack):
    """已有快取被當次 gate 拒絕時，修正會真呼叫模型，而非重讀同一份舊值。"""
    pipeline, _, calls = make_pipeline(generation_stack)
    first = run_pipeline(generation_stack, pipeline)
    assert first.decision == "validated", first
    gate = pipeline.gate
    seen = 0

    class RejectFirstCachedBody:
        def validate(self, request):
            """僅第二個 run 首次候選遭拒，修正與競爭快取勝出值均重新檢查。"""
            nonlocal seen
            seen += 1
            result = gate.validate(request)
            if seen == 1:
                return result.model_copy(update={"valid": False, "decision": "reject", "errors": [
                    ValidationIssue(location="body", path="", code="pattern", reason="Reject cached content")]})
            return result

    pipeline.gate = RejectFirstCachedBody()
    second = run_pipeline(generation_stack, pipeline)
    assert second.decision == "validated" and second.trace["repairs"] == 1, second
    assert len(calls["generator"]) == 2
