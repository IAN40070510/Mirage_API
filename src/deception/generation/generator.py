"""G：D schema＋政策白名單＋唯讀事實 → 本機模型片段；不生成或核准 HTTP metadata。"""

import copy
import json
from typing import Annotated

from jsonschema import Draft202012Validator, FormatChecker
from pydantic import ConfigDict, Field, JsonValue, WithJsonSchema, create_model

from deception.core.models import CompositionPlan

from .cache import ContentCache
from .models import GeneratedContent, GenerationPolicy, digest
from .pointers import get, overlap, replace
from .schema import field_schema


class ContentGenerator:
    """政策使用獨立快照；持久內容由 C 驗證成功後發布，不直接修改 E。"""

    def __init__(self, policy: GenerationPolicy, backend, *, cache: ContentCache | None = None):
        """依賴由呼叫端提供，支援真本機模型及明確標示的 FunctionModel 測試。"""
        checked = GenerationPolicy.model_validate(policy.model_dump(mode="json"))
        self._policy_json = checked.model_dump_json()
        self._policy_sha256 = digest(checked.model_dump(mode="json"))
        self.backend = backend
        self.cache = ContentCache() if cache is None else cache

    @property
    def policy_sha256(self) -> str:
        """唯讀的實際政策摘要，避免追溯及快取被公開屬性賦值污染。"""
        return self._policy_sha256

    @property
    def policy(self) -> GenerationPolicy:
        """每次回獨立副本，避免外部修改政策改變已建立的生成器。"""
        return GenerationPolicy.model_validate_json(self._policy_json)

    def select_rule(self, plan, context):
        """單次生成只用一條精確領域／契約／結果規則；歧義或停用均拒絕。"""
        policy = self.policy
        if not policy.enabled or policy.domain != context.domain or context.generation_policy_sha256 != self.policy_sha256:
            raise ValueError("Generation policy is disabled or does not match the context")
        matches = [r for r in policy.rules if
                   (r.platform_id, r.platform_version, r.spec_sha256, r.operation_id, r.method, r.path,
                    r.outcome_id, r.status_code, r.media_type) ==
                   (plan.scope.platform_id, plan.scope.platform_version, plan.scope.spec_sha256,
                    context.operation_id, plan.method, plan.path, context.outcome_id, plan.status_code, plan.media_type)]
        if len(matches) != 1 or plan.scope != context.scope:
            raise ValueError("Generation requires one exact rule and scope")
        rule = matches[0]
        for field in rule.fields:
            get(plan.body, field.target_pointer)
            if any(overlap(field.target_pointer, binding.target_pointer) for binding in plan.bindings):
                raise ValueError("Generated field overlaps an authoritative E binding")
        return rule

    def apply(self, plan, rule, schemas, values):
        """檢查完整 field ID 集合、原始 JSON 型別及 schema，再只替換白名單位置。"""
        if set(values) != {f.field_id for f in rule.fields}:
            raise ValueError("Generated fields must exactly match the allowed field IDs")
        result = CompositionPlan.model_validate(plan.model_dump(mode="json"))
        for field in rule.fields:
            Draft202012Validator(schemas[field.field_id], format_checker=FormatChecker()).validate(values[field.field_id])
            replace(result.body, field.target_pointer, copy.deepcopy(values[field.field_id]))
        return result

    async def generate(self, plan, context, profile, *, facts: dict, budget, intent, feedback=None) -> GeneratedContent:
        """產生或重用片段，回傳尚未發布的內容；相同鍵競爭由 C 發布後再驗勝出值。"""
        budget.check()
        rule = self.select_rule(plan, context)
        if len(intent.field_ids) != len(set(intent.field_ids)) or set(intent.field_ids) != {f.field_id for f in rule.fields}:
            raise ValueError("Planner requested fields outside the generation policy")
        schemas = {f.field_id: field_schema(profile, plan, f.target_pointer) for f in rule.fields}
        policy = self.policy
        references = {f.field_id: (get(context.domain_context, f.entity_pointer) if f.cache_scope == "entity"
                                  else context.request_fingerprint) for f in rule.fields}
        # 不包含 request_id 的 entity 鍵可跨請求重用；不同部署、資料、契約或模型仍隔離。
        key = digest(dict(domain=context.domain, environment=context.environment_id, deployment=context.deployment_id,
                          service=context.service_id, scope=context.scope.model_dump(mode="json"),
                          state=context.state_sha256, namespace=context.data_namespace, references=references,
                          rule=rule.model_dump(mode="json"), schemas=schemas, policy=self.policy_sha256,
                          scenario_policy=context.scenario_policy_sha256,
                          blueprint=plan.model_dump(mode="json"), facts=facts,
                          prompt_version=policy.prompt_version, model=context.model_identity))
        values = self.cache.get(key)
        cache_hit = values is not None
        if values is None:
            output_type = create_model("GeneratedFields", __config__=ConfigDict(extra="forbid", strict=True, allow_inf_nan=False),
                                       # 完整替換 decoder schema，避免 JsonValue 的 $ref 使部分解碼器忽略 sibling 限制。
                                       **{f"field_{i}": (Annotated[JsonValue, WithJsonSchema(schemas[f.field_id])],
                                                         Field(..., alias=f.field_id))
                                          for i, f in enumerate(rule.fields)})
            prompt = json.dumps(dict(task="Generate only the listed JSON fields for a synthetic API response.",
                                     domain=context.domain, outcome=context.outcome_id,
                                     fields=[dict(field_id=f.field_id, instruction=f.instruction,
                                                  schema=schemas[f.field_id]) for f in rule.fields],
                                     facts=facts, planner_guidance=intent.instructions,
                                     validation_feedback=feedback or "", prompt_version=policy.prompt_version),
                                ensure_ascii=False, sort_keys=True, allow_nan=False)
            if len(prompt.encode("utf-8")) > 65536:
                raise ValueError("Generation context exceeds the prompt size limit")
            output = await self.backend.generate(prompt, output_type, budget)
            values = output.model_dump(mode="json", by_alias=True)
        result = self.apply(plan, rule, schemas, values)
        budget.check()
        return GeneratedContent(plan=result, values=values, cache_key=key, cache_hit=cache_hit,
                                trace=dict(rule_id=rule.rule_id, cache_hit=cache_hit, content_sha256=digest(values),
                                           field_ids=[f.field_id for f in rule.fields], model=context.model_identity,
                                           context_id=context.context_id))
