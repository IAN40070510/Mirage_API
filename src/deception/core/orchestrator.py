"""C/J：自家必經控制流程與受限 LLM 工具規劃；成功只回同一份通過 I 的內部候選。"""

import asyncio
import copy
import json
import time
from datetime import datetime, timedelta, timezone
from typing import Literal

from pydantic import Field, JsonValue

from deception.generation import GenerationContext, GenerationIntent
from deception.generation.models import digest
from deception.generation.pointers import get
from deception.generation.schema import field_schema
from deception.llm import BudgetExceeded, RunBudget
from deception.scenarios import fingerprint_request
from deception.scenarios.models import ScenarioIssue
from deception.synthetic import generate_dataset
from deception.synthetic.generator import checked_dataset
from deception.synthetic.models import SyntheticConfig, SyntheticModel
from mirage_validator.gate import GateResult

from .handoff import verify_candidate
from .models import CandidateResponse


class PipelineResult(SyntheticModel):
    """validated 是內部驗證結果，尚不是 M 對外輸出的 HTTP Response。"""

    decision: Literal["validated", "not_applicable", "unverifiable", "reject"]
    candidate: CandidateResponse | None = None
    gate_result: GateResult | None = None
    trace: dict[str, JsonValue] = Field(default_factory=dict)
    errors: list[ScenarioIssue] = Field(default_factory=list)


class SyntheticSnapshotProvider:
    """內建 E 電商快照供應器；其他領域可注入自己的 load/facts/composition_data 介面。"""

    def load(self, config, data, expected_scope):
        """核對管理者的完整設定與 scope，禁止把舊資料重新標記為新情境。"""
        config = SyntheticConfig.model_validate(config.model_dump(mode="json"))
        if config.scope != expected_scope:
            raise ValueError("Generation configuration does not match the prepared scenario scope")
        return generate_dataset(config) if data is None else checked_dataset(data, config)

    def facts(self, data, plan) -> dict:
        """只投影 H 已允許的權威欄位，整個原始請求與完整 E 資料不送模型。"""
        source = {"products": [p.model_dump(mode="json") for p in data.products],
                  "variants": [v.model_dump(mode="json") for v in data.variants]}
        return {binding.target_pointer: copy.deepcopy(get(source, binding.source_pointer)) for binding in plan.bindings}

    def composition_data(self, data):
        """H 目前支援 E 商品資料；新領域若不使用 E 映射可由自己的 provider 回 None。"""
        return data


class _Stop(ValueError):
    """控制流程只回固定診斷，避免 provider exception 回顯提示或本地檔名。"""

    def __init__(self, code, reason, decision="unverifiable"):
        """保存固定診斷與流程判定，供協調器將停止原因轉為不含原始資料的結果。"""
        self.code, self.reason, self.decision = code, reason, decision
        super().__init__(code)


class DeceptionOrchestrator:
    """強制身份、情境、資料、生成與 H/I 檢查；LLM 只可規劃已公開的零參數讀取工具。"""

    def __init__(self, *, identifier, profiles, scenarios, generator, composer, gate, data_provider=None):
        """依賴明確注入，不從訪客 header 自稱的 domain 或平台選工具。"""
        if scenarios.domain_id != generator.policy.domain:
            raise ValueError("Scenario and generation domains must match")
        self.identifier, self.profiles, self.scenarios = identifier, profiles, scenarios
        self.generator, self.composer, self.gate = generator, composer, gate
        self.data_provider = SyntheticSnapshotProvider() if data_provider is None else data_provider

    async def run(self, request, assessment, *, runtime, generation_config, dataset=None,
                  now=None, allow_unreviewed=False) -> PipelineResult:
        """執行一個獨立 run，共用預算、固定請求及快照，絕不重用其他請求的 gate pass。"""
        budget = RunBudget(self.generator.policy.limits)
        trace = {"request_id": request.request_id, "domain": self.scenarios.domain_id,
                 "request_fingerprint": fingerprint_request(request), "generation_policy_sha256": self.generator.policy_sha256}
        gate_result = None
        started = time.monotonic()
        clock = datetime.now(timezone.utc) if now is None else now

        def current_time():
            """注入時鐘仍會加上實際經過時間，長生成不能重用已過期的 F 判定。"""
            return clock + timedelta(seconds=time.monotonic() - started)

        try:
            if not self.generator.policy.enabled:
                return PipelineResult(decision="not_applicable", trace=trace)
            async with asyncio.timeout(budget.remaining()):
                identified = self.identifier.identify_request(request, context=runtime)
                if identified.decision != "identified" or identified.identity is None:
                    raise _Stop("identification_unverifiable", "B 無法確認唯一請求身份")
                identity = identified.identity
                profile = self.profiles.get_operation(**identity.profile_arguments(), allow_unreviewed=allow_unreviewed)
                preparation = self.scenarios.prepare(request, identified, profile, assessment,
                                                     run_id=generation_config.scope.run_id, now=current_time(),
                                                     allow_unreviewed=allow_unreviewed)
                if preparation.decision != "prepared" or preparation.prepared is None:
                    return PipelineResult(decision=preparation.decision, errors=preparation.errors,
                                          trace={**trace, "usage": budget.audit()})
                prepared = preparation.prepared
                data = self.data_provider.load(generation_config, dataset, prepared.scope)
                decision = self.scenarios.resolve(prepared, data, now=current_time())
                if decision.decision != "selected" or decision.composition_plan is None:
                    raise _Stop("scenario_unverifiable", "F 無法依核對後的資料選擇結果")
                budget.check()
                # check_ready 明確區分實際本機模型與 FunctionModel，並核對模型 digest。
                model_identity = await self.generator.backend.check_ready(budget)
                context = GenerationContext(
                    domain=prepared.domain, request_id=request.request_id,
                    request_fingerprint=fingerprint_request(request), environment_id=identity.environment_id,
                    deployment_id=identity.deployment_id, service_id=identity.service_id, scope=prepared.scope,
                    operation_id=identity.operation_id, outcome_id=decision.outcome_id,
                    scenario_decision_id=decision.trace["decision_id"], scenario_policy_sha256=self.scenarios.policy_sha256,
                    generation_policy_sha256=self.generator.policy_sha256, data_namespace=decision.trace["data_namespace"],
                    state_sha256=decision.trace["state_sha256"], domain_context=prepared.domain_context,
                    model_identity=model_identity)
                base_plan = decision.composition_plan
                rule = self.generator.select_rule(base_plan, context)
                schemas = {f.field_id: field_schema(profile, base_plan, f.target_pointer) for f in rule.fields}
                facts = self.data_provider.facts(data, base_plan)
                contract_view = {"operation_id": identity.operation_id, "method": base_plan.method,
                                 "path_template": base_plan.path, "status_code": base_plan.status_code,
                                 "media_type": base_plan.media_type, "fields": schemas}
                scenario_view = {"domain": context.domain, "scenario_id": context.scope.scenario_id,
                                 "outcome_id": context.outcome_id}

                def read_contract() -> str:
                    """Read the fixed operation and allowed field schemas for this request."""
                    return json.dumps(contract_view, ensure_ascii=False, sort_keys=True)

                def read_facts() -> str:
                    """Read authoritative synthetic facts. These values must not be changed."""
                    return json.dumps(facts, ensure_ascii=False, sort_keys=True)

                def read_scenario() -> str:
                    """Read the already selected domain and scenario outcome. They cannot be changed."""
                    return json.dumps(scenario_view, ensure_ascii=False, sort_keys=True)

                prompt = json.dumps(dict(task="Plan synthetic response content. Read relevant tools, then select every allowed field ID.",
                                         allowed_field_ids=[f.field_id for f in rule.fields],
                                         rule_instructions={f.field_id: f.instruction for f in rule.fields},
                                         domain=context.domain, outcome=context.outcome_id), ensure_ascii=False, sort_keys=True)
                intent = await self.generator.backend.plan(prompt, {"read_contract": read_contract, "read_facts": read_facts,
                                                                    "read_scenario": read_scenario}, GenerationIntent, budget)
                intent = GenerationIntent.model_validate(intent.model_dump())
                trace.update(context_id=context.context_id, scenario=decision.trace, model=model_identity)
                feedback = None
                for attempt in range(self.generator.policy.limits.max_repairs + 1):
                    budget.check()
                    try:
                        generated = await self.generator.generate(base_plan, context, profile, facts=facts,
                                                                  budget=budget, intent=intent, feedback=feedback)
                        candidate = self.composer.compose(generated.plan, dataset=self.data_provider.composition_data(data),
                                                          allow_unreviewed=allow_unreviewed)
                        gate_result = verify_candidate(candidate, self.gate, request.raw_url)
                        if gate_result.decision != "pass" or gate_result.valid is not True:
                            # 未審查／錯誤身份不透過模型修正；一般契約拒絕也不發布快取。
                            raise _Stop("gate_not_passed", "候選未通過 I，同一份回應不能對外使用",
                                        "reject" if gate_result.decision == "reject" else "unverifiable")
                        budget.check()
                        final_scenario = self.scenarios.resolve(prepared, data, now=current_time())
                        if (final_scenario.decision != "selected" or final_scenario.trace.get("decision_id") != decision.trace["decision_id"] or
                                fingerprint_request(request) != context.request_fingerprint):
                            raise _Stop("context_changed", "請求、判定期限或資料事實在生成期間改變")
                        # 只發布已通過 H/I 的內容。若另一個 run 先發布，取勝出值重新組合、驗證。
                        if await self.generator.backend.check_ready(budget) != model_identity:
                            raise _Stop("model_changed", "本機模型身份在生成期間改變")
                        winner = self.generator.cache.publish(generated.cache_key, generated.values)
                        actual_generation = {**generated.trace, "cache_winner": winner != generated.values}
                        if winner != generated.values:
                            winning_plan = self.generator.apply(base_plan, rule, schemas, winner)
                            candidate = self.composer.compose(winning_plan, dataset=self.data_provider.composition_data(data),
                                                              allow_unreviewed=allow_unreviewed)
                            gate_result = verify_candidate(candidate, self.gate, request.raw_url)
                            if gate_result.decision != "pass" or gate_result.valid is not True:
                                raise _Stop("cache_candidate_rejected", "競爭快取的候選無法重新驗證")
                            actual_generation.update(content_sha256=digest(winner), cache_hit=True)
                        # 發布可能等待 SQLite 鎖，競爭勝出值也可能再次組合；回傳前重查期限及事實。
                        final_scenario = self.scenarios.resolve(prepared, data, now=current_time())
                        if (final_scenario.decision != "selected" or
                                final_scenario.trace.get("decision_id") != decision.trace["decision_id"] or
                                fingerprint_request(request) != context.request_fingerprint):
                            raise _Stop("context_changed", "發布期間請求、判定期限或資料事實改變")
                        budget.check()
                        trace.update(generation=actual_generation, repairs=attempt, usage=budget.audit(),
                                     candidate_sha256=digest(candidate.to_dict()))
                        return PipelineResult(decision="validated", candidate=candidate, gate_result=gate_result, trace=trace)
                    except (_Stop, BudgetExceeded, asyncio.CancelledError):
                        raise
                    except Exception:
                        if attempt >= self.generator.policy.limits.max_repairs:
                            raise _Stop("generation_rejected", "生成內容或組合無法通過驗證", "reject")
                        feedback = "The previous allowed field values failed schema or contract validation. Regenerate only those fields."
                raise _Stop("generation_rejected", "未取得可驗證的生成內容", "reject")
        except _Stop as exc:
            return PipelineResult(decision=exc.decision, gate_result=gate_result, trace={**trace, "usage": budget.audit()},
                                  errors=[ScenarioIssue(code=exc.code, reason=exc.reason)])
        except (BudgetExceeded, TimeoutError) as exc:
            return PipelineResult(decision="unverifiable", trace={**trace, "usage": budget.audit()}, errors=[ScenarioIssue(
                code=exc.code if isinstance(exc, BudgetExceeded) else "deadline_exceeded", reason="C/G 已達共用執行預算，未產生可用候選")])
        except Exception:
            return PipelineResult(decision="unverifiable", trace={**trace, "usage": budget.audit()}, errors=[ScenarioIssue(
                code="pipeline_unverifiable", reason="無法可靠核對契約、資料或本機模型，未產生可用候選")])
