"""可信世界內容的穩定性、首次配方追溯、模型前重用與重新驗證回歸。"""

import asyncio
import copy
import json
from dataclasses import replace

import pytest
from fastapi.testclient import TestClient
from pydantic_ai.messages import ModelResponse, TextPart

from deception.api.pipeline import create_app
from deception.generation import ContentCache, ContentLifecycle
from deception.world.models import WorldScope
from test_generation import _direct_generation_inputs, function_backend, generation_stack, make_pipeline, run_pipeline
from test_recovery import enable_recovery
from test_scenarios import NOW, assessment_for, request_for


def lifecycle_for(stack, **changes):
    """建立伺服器已核對世界的測試身份，不從 HTTP 欄位取 session 或版次。"""
    return ContentLifecycle(world_scope=WorldScope(
        environment_id=stack["runtime"].environment_id, deployment_id=stack["runtime"].deployment_id,
        session_id="session-1", world_generation_id="generation-1"),
        entity_version=changes.pop("entity_version", "entity-1"),
        content_epoch=changes.pop("content_epoch", "content-1"), **changes)


def run_bound(stack, pipeline, lifecycle, request=None):
    """執行帶可信內容生命週期的真正協調器，保留原情境、資料與 gate。"""
    request = stack["request"] if request is None else request
    return asyncio.run(pipeline.run(request, assessment_for(request), runtime=stack["runtime"],
                                   generation_config=stack["config"], dataset=stack["dataset"], now=NOW,
                                   content_lifecycle=lifecycle))


def test_published_world_content_survives_model_change_and_restart_without_inference(generation_stack, tmp_path):
    """同世界內容在重啟或換模型後仍不變，保留首次配方且零推論重新通過 gate。"""
    stack = generation_stack
    path = tmp_path / "content.sqlite3"
    cache = ContentCache(path)
    pipeline, _, _ = make_pipeline(stack, cache=cache)
    lifecycle = lifecycle_for(stack)
    first = run_bound(stack, pipeline, lifecycle)
    assert first.decision == "validated", first
    provenance = first.trace["generation"]["provenance"]
    cache.close()
    cache = ContentCache(path)
    backend, calls = function_backend(model_digest="1" * 64)

    async def unavailable(budget):
        """快取重用不需啟動模型；任何 readiness 呼叫都代表錯誤的依賴。"""
        raise AssertionError("A published world response must not require a model")

    backend.check_ready = unavailable
    second_pipeline, _, _ = make_pipeline(stack, backend=backend, cache=cache)
    second = run_bound(stack, second_pipeline, lifecycle, replace(stack["request"], request_id="repeat-world"))
    assert second.decision == "validated", second
    assert first.candidate.body == second.candidate.body
    assert second.trace["usage"]["model_requests"] == 0
    assert second.trace["model"] == {"provider": "not_used", "execution_mode": "cache"}
    assert second.trace["generation"]["provenance"] == provenance
    assert second.gate_result.valid is True and calls == {"planner": [], "generator": []}
    cache.close()


@pytest.mark.parametrize("change", ["entity_version", "content_epoch", "session", "generation"])
def test_world_content_versions_and_scope_never_cross_reuse(generation_stack, change):
    """實體內容版次、明確切換、不同 session 或世界世代不能借用已發布值。"""
    stack = generation_stack
    cache = ContentCache()
    pipeline, _, _ = make_pipeline(stack, cache=cache)
    lifecycle = lifecycle_for(stack)
    assert run_bound(stack, pipeline, lifecycle).decision == "validated"
    updated = lifecycle.model_dump(mode="json")
    if change in ("session", "generation"):
        updated["world_scope"]["session_id" if change == "session" else "world_generation_id"] += "-2"
    else:
        updated[change] += "-2"
    backend, calls = function_backend(value="A new description for the selected version.")
    pipeline, _, _ = make_pipeline(stack, backend=backend, cache=cache)
    result = run_bound(stack, pipeline, ContentLifecycle.model_validate(updated))
    assert result.decision == "validated" and calls["generator"], result
    assert result.trace["generation"]["cache_hit"] is False
    cache.close()


def test_unrelated_snapshot_change_preserves_content_but_changed_fact_does_not(generation_stack):
    """世界狀態摘要改變不覆寫已定義內容，真正可見的商品事實改變則重新產生。"""
    stack = generation_stack
    pipeline, generator, _ = make_pipeline(stack)
    lifecycle = lifecycle_for(stack)
    first = run_bound(stack, pipeline, lifecycle)
    assert first.decision == "validated", first
    plan, context, budget = _direct_generation_inputs(stack, generator, generator.backend)
    context.content_lifecycle = lifecycle
    context.state_sha256 = "e" * 64
    context.data_namespace = "f" * 64
    facts = pipeline.data_provider.facts(stack["dataset"], plan)
    cached = generator.cached(plan, context, stack["profile"], facts=facts, budget=budget)
    assert cached is not None
    assert cached.values["description"] == json.loads(first.candidate.body)["product"]["description"]
    facts["/product/title"] = "A different authoritative product title"
    assert generator.cached(plan, context, stack["profile"], facts=facts, budget=budget) is None
    generator.cache.close()


def test_published_content_keeps_first_recipe_until_explicit_content_epoch_cutover(generation_stack):
    """相同內容世代不因 prompt、policy 或模型配方更新而跳動，明確切換後才使用新文案。"""
    stack = generation_stack
    cache = ContentCache()
    first_pipeline, _, _ = make_pipeline(stack, cache=cache)
    lifecycle = lifecycle_for(stack)
    first = run_bound(stack, first_pipeline, lifecycle)
    changed_policy = copy.deepcopy(stack["policy_data"])
    changed_policy["prompt_version"] = "new-prompt"
    changed_policy["policy_version"] = "new-policy"
    changed_policy["rules"][0]["fields"][0]["instruction"] = "Use the newly approved wording."
    backend, calls = function_backend(value="A newly approved product description.", model_digest="2" * 64)
    pipeline, _, _ = make_pipeline(stack, backend=backend, cache=cache, policy_data=changed_policy)
    same_epoch = run_bound(stack, pipeline, lifecycle)
    assert first.decision == same_epoch.decision == "validated"
    assert first.candidate.body == same_epoch.candidate.body
    assert same_epoch.trace["generation"]["provenance"] == first.trace["generation"]["provenance"]
    assert calls == {"planner": [], "generator": []}
    cutover = run_bound(stack, pipeline, lifecycle_for(stack, content_epoch="content-2"))
    assert cutover.decision == "validated" and cutover.candidate.body != first.candidate.body
    assert calls["generator"]
    assert cutover.trace["generation"]["provenance"]["prompt_version"] == "new-prompt"
    cache.close()


def test_content_entry_publication_keeps_winning_values_and_recipe_together(tmp_path):
    """不同程序配方競爭同身份時，只保留先發布者的值與證據，重啟後仍一致。"""
    path = tmp_path / "competing.sqlite3"
    first = ContentCache(path)
    second = ContentCache(path)
    winner = first.publish_entry("same-world-entity", {"description": "First valid description."}, {"model": "first"})
    observed = second.publish_entry("same-world-entity", {"description": "Second valid description."}, {"model": "second"})
    assert winner == observed == {"values": {"description": "First valid description."}, "provenance": {"model": "first"}}
    first.close()
    second.close()
    reopened = ContentCache(path)
    assert reopened.get_entry("same-world-entity") == winner
    reopened.close()


def test_corrupted_published_entry_stops_before_models_or_fallback(generation_stack):
    """已發布值或配方摘要遭損毀時停止，不能在相同身份下重生內容掩蓋錯誤。"""
    stack = generation_stack
    pipeline, generator, calls = make_pipeline(stack)
    lifecycle = lifecycle_for(stack)
    assert run_bound(stack, pipeline, lifecycle).decision == "validated"
    with generator.cache._db:
        generator.cache._db.execute("UPDATE content_entries SET sha=?", ("0" * 64,))
    before = {name: len(rows) for name, rows in calls.items()}
    result = run_bound(stack, pipeline, lifecycle)
    assert result.decision == "unverifiable" and result.candidate is None
    assert result.errors[0].code == "cached_content_unverifiable"
    assert before == {name: len(rows) for name, rows in calls.items()}
    generator.cache.close()


def test_fact_dependencies_filter_both_planner_observations_and_generated_context(generation_stack):
    """未宣告的事實不進 planner 或 G；改動其他資料不改變模型可見的依賴集合。"""
    stack = generation_stack
    policy = copy.deepcopy(stack["policy_data"])
    policy["rules"][0]["fact_keys"] = ["/product/id", "/product/title"]
    pipeline, generator, calls = make_pipeline(stack, policy_data=policy)
    original = pipeline.data_provider.facts

    def expanded_facts(data, plan):
        """模擬領域供應器另有不屬描述依賴的資料，確認不會傳給模型。"""
        return {**original(data, plan), "unrelated": "private-unrelated-fact"}

    pipeline.data_provider.facts = expanded_facts
    result = run_bound(stack, pipeline, lifecycle_for(stack))
    assert result.decision == "validated", result
    assert "private-unrelated-fact" not in repr(calls)
    generator.cache.close()


def test_lifecycle_cache_cannot_bypass_current_gate_or_regenerate_rejected_content(generation_stack):
    """舊內容仍由本次 gate 判定；拒絕時不能用模型生成另一份相同身份的替代值。"""
    stack = generation_stack
    pipeline, generator, calls = make_pipeline(stack)
    lifecycle = lifecycle_for(stack)
    assert run_bound(stack, pipeline, lifecycle).decision == "validated"
    before = {name: len(items) for name, items in calls.items()}
    original = pipeline.gate

    class RejectBody:
        def validate(self, request):
            """保留真實契約身份並拒絕本次內容，用以驗證快取不是 gate pass。"""
            result = original.validate(request)
            return result.model_copy(update={"valid": False, "decision": "reject"})

    pipeline.gate = RejectBody()
    result = run_bound(stack, pipeline, lifecycle)
    assert result.decision != "validated" and result.candidate is None
    assert {name: len(items) for name, items in calls.items()} == before
    generator.cache.close()


def test_template_branch_uses_reviewed_request_bound_404_without_any_model(generation_stack):
    """固定錯誤分支不推論，仍綁定當次 ID、原 404 契約及同一 H/I 驗證。"""
    stack = generation_stack
    policy = copy.deepcopy(stack["policy_data"])
    policy["rules"][1]["generation_mode"] = "reviewed_template"
    pipeline, generator, calls = make_pipeline(stack, policy_data=policy)
    enable_recovery(pipeline, outcome="missing", values={"message": "Product {request_entity_id} was not found."})
    result = run_pipeline(stack, pipeline, request=request_for("missing-product"))
    assert result.decision == "validated" and result.candidate.status_code == 404, result
    assert json.loads(result.candidate.body)["message"] == "Product missing-product was not found."
    assert result.trace["generation"]["source"] == "template"
    assert result.trace["usage"]["model_requests"] == 0
    assert calls == {"planner": [], "generator": []}
    generator.cache.close()


def test_fixed_field_planning_uses_only_the_generation_request(generation_stack):
    """主機已固定的欄位不呼叫 planner，一次生成即完成且仍經同一契約 gate。"""
    stack = generation_stack
    policy = copy.deepcopy(stack["policy_data"])
    policy["rules"][0]["planning_mode"] = "fixed_fields"
    policy["limits"] = {"max_model_requests": 1, "max_repairs": 0}
    pipeline, generator, calls = make_pipeline(stack, policy_data=policy)
    result = run_pipeline(stack, pipeline)
    assert result.decision == "validated" and result.gate_result.valid is True, result
    assert calls["planner"] == [] and len(calls["generator"]) == 1
    assert result.trace["usage"]["model_requests"] == 1
    assert set(result.trace["usage"]["tasks"]) == {"generation"}
    generator.cache.close()


def test_template_without_explicit_approved_values_fails_closed(generation_stack):
    """選固定模板但沒有同分支核准值時拒絕，不能偷偷切換模型補足。"""
    stack = generation_stack
    policy = copy.deepcopy(stack["policy_data"])
    policy["rules"][0]["generation_mode"] = "reviewed_template"
    pipeline, generator, calls = make_pipeline(stack, policy_data=policy)
    result = run_pipeline(stack, pipeline)
    assert result.decision == "reject" and result.candidate is None
    assert calls == {"planner": [], "generator": []}
    generator.cache.close()


def test_lifecycle_wrong_deployment_stops_before_models(generation_stack):
    """外部提供的世界身份若屬另一部署就拒絕，不允許借用其他部署內容。"""
    stack = generation_stack
    pipeline, generator, calls = make_pipeline(stack)
    lifecycle = lifecycle_for(stack)
    lifecycle = lifecycle.model_copy(update={"world_scope": lifecycle.world_scope.model_copy(
        update={"deployment_id": "other-deployment"})})
    result = run_bound(stack, pipeline, lifecycle)
    assert result.decision == "unverifiable" and result.candidate is None
    assert calls == {"planner": [], "generator": []}
    generator.cache.close()


def test_run_seals_caller_lifecycle_before_shared_object_changes(generation_stack):
    """呼叫端在推論期間更新共用生命週期物件，不得改變已啟動 run 的內容身份。"""
    stack = generation_stack
    lifecycle = lifecycle_for(stack)
    observed = []

    async def change_shared_binding(messages, info):
        """模擬另一個請求更新組裝層共用模型，仍只回傳合法受限描述。"""
        lifecycle.content_epoch = "another-request-epoch"
        return ModelResponse(parts=[TextPart('{"description":"A valid product description."}')])

    backend, _ = function_backend(generator_function=change_shared_binding)
    pipeline, generator, _ = make_pipeline(stack, backend=backend)
    original = generator.generate

    async def observe_context(plan, context, profile, **kwargs):
        """記錄本次 run 自有上下文，以核對共享外部物件更新不會污染它。"""
        observed.append(context)
        return await original(plan, context, profile, **kwargs)

    generator.generate = observe_context
    result = run_bound(stack, pipeline, lifecycle)
    assert result.decision == "validated", result
    assert lifecycle.content_epoch == "another-request-epoch"
    assert observed[0].content_lifecycle.content_epoch == "content-1"
    assert result.trace["context_id"] == observed[0].context_id
    generator.cache.close()


def test_first_reviewed_fallback_is_stable_world_content_when_model_recovers(generation_stack):
    """同世界已採用的核准備援在模型恢復後仍保持，避免訪客觀察到描述突然改變。"""
    stack = generation_stack
    cache = ContentCache()
    backend, _ = function_backend(value=7)
    pipeline, _, _ = make_pipeline(stack, backend=backend, cache=cache)
    enable_recovery(pipeline, values={"description": "Reviewed product details are available."})
    lifecycle = lifecycle_for(stack)
    first = run_bound(stack, pipeline, lifecycle)
    assert first.decision == "validated" and first.trace["generation"]["source"] == "fallback", first
    backend, calls = function_backend(value="A new model description after recovery.")
    pipeline, _, _ = make_pipeline(stack, backend=backend, cache=cache)
    second = run_bound(stack, pipeline, lifecycle)
    assert second.decision == "validated" and first.candidate.body == second.candidate.body
    assert second.trace["generation"]["provenance"]["source"] == "fallback"
    assert calls == {"planner": [], "generator": []}
    assert cache._db.execute("SELECT count(*) FROM content").fetchone()[0] == 0
    cache.close()


def test_changing_model_to_template_does_not_override_same_world_content(generation_stack):
    """同內容世代改用固定模板不能覆寫已發布文案，明確 content_epoch 切換才套新模板。"""
    stack = generation_stack
    cache = ContentCache()
    pipeline, _, _ = make_pipeline(stack, cache=cache)
    lifecycle = lifecycle_for(stack)
    first = run_bound(stack, pipeline, lifecycle)
    policy = copy.deepcopy(stack["policy_data"])
    policy["rules"][0]["generation_mode"] = "reviewed_template"
    pipeline, _, calls = make_pipeline(stack, cache=cache, policy_data=policy)
    enable_recovery(pipeline, values={"description": "An approved replacement template."})
    same_epoch = run_bound(stack, pipeline, lifecycle)
    assert first.decision == same_epoch.decision == "validated"
    assert first.candidate.body == same_epoch.candidate.body
    cutover = run_bound(stack, pipeline, lifecycle_for(stack, content_epoch="template-v2"))
    assert cutover.decision == "validated", cutover
    assert cutover.candidate.body != first.candidate.body
    assert cutover.trace["generation"]["source"] == "template"
    assert calls == {"planner": [], "generator": []}
    cache.close()


def test_http_lifecycle_provider_is_server_bound_and_reuses_only_same_world(generation_stack):
    """HTTP 的訪客 world header 不取代伺服器 provider，重查同世界仍經最終回送驗證。"""
    stack = generation_stack
    pipeline, generator, calls = make_pipeline(stack)
    lifecycle = lifecycle_for(stack)
    observed = []

    def trusted_lifecycle(request, assessment):
        """測試模擬可信 Session/World 組裝層，固定回傳已驗證生命週期。"""
        observed.append(request.request_id)
        return lifecycle

    app = create_app(pipeline, runtime=stack["runtime"], generation_config=stack["config"],
                     dataset=stack["dataset"], assessment_provider=assessment_for, now=NOW,
                     content_lifecycle_provider=trusted_lifecycle)
    with TestClient(app, base_url="https://shop.test") as client:
        path = "/api/products/" + stack["dataset"].products[0].id
        first = client.get(path, headers={"X-Request-ID": "life-first"})
        second = client.get(path, headers={"X-Request-ID": "life-second", "X-World-Generation": "visitor-world"})
    assert first.status_code == second.status_code == 200
    assert first.content == second.content
    assert observed == ["life-first", "life-second"]
    assert len(calls["generator"]) == 1
    generator.cache.close()
