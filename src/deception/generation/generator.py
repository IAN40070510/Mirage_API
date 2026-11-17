"""G：D schema＋政策白名單＋唯讀事實 → 本機模型片段；不生成或核准 HTTP metadata。"""

import copy
import json
import math
from typing import Annotated

from jsonschema import Draft202012Validator, FormatChecker
from pydantic import ConfigDict, Field, JsonValue, WithJsonSchema, create_model

from deception.core.models import CompositionPlan

from .cache import ContentCache
from .models import FieldViolation, GeneratedContent, GeneratedFieldValidationError, GenerationPolicy, digest
from .pointers import get, overlap, replace
from .schema import field_schema


def _schema_violation(field_id, error) -> FieldViolation:
    """只投影固定錯誤碼、有限數值或 JSON 型別，不帶入 schema 自由文字及失敗值。"""
    codes = {"type": "type", "minLength": "min_length", "maxLength": "max_length",
             "minimum": "minimum", "maximum": "maximum", "exclusiveMinimum": "exclusive_minimum",
             "exclusiveMaximum": "exclusive_maximum", "minItems": "min_items", "maxItems": "max_items",
             "minProperties": "min_properties", "maxProperties": "max_properties", "pattern": "pattern",
             "format": "format", "enum": "enum", "const": "const", "required": "required",
             "additionalProperties": "additional_properties", "uniqueItems": "unique_items"}
    code = codes.get(error.validator, "schema")
    data = {"field_id": field_id, "code": code}
    if code in {"min_length", "max_length", "minimum", "maximum", "exclusive_minimum", "exclusive_maximum",
                "min_items", "max_items", "min_properties", "max_properties"}:
        value = error.validator_value
        if type(value) is int or (type(value) is float and math.isfinite(value)):
            data["limit"] = value
    elif code == "type" and isinstance(error.validator_value, str) and error.validator_value in {
            "string", "number", "integer", "boolean", "object", "array", "null"}:
        data["expected_type"] = error.validator_value
    return FieldViolation.model_validate(data)


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
        """核對完整欄位與 schema；失敗拋受控摘要例外，全部通過才替換白名單位置。"""
        if set(values) != {f.field_id for f in rule.fields}:
            raise ValueError("Generated fields must exactly match the allowed field IDs")
        result = CompositionPlan.model_validate(plan.model_dump(mode="json"))
        violations = []
        for field in rule.fields:
            validator = Draft202012Validator(schemas[field.field_id], format_checker=FormatChecker())
            for error in validator.iter_errors(values[field.field_id]):
                violations.append(_schema_violation(field.field_id, error))
                if len(violations) >= 16:
                    break
            if len(violations) >= 16:
                break
        if violations:
            raise GeneratedFieldValidationError(violations)
        for field in rule.fields:
            replace(result.body, field.target_pointer, copy.deepcopy(values[field.field_id]))
        return result

    def cache_binding(self, plan, context, profile, facts):
        """建立精確契約、實體依賴與快取身份；世界模式只使用模型實際可見的事實投影。"""
        context = type(context).model_validate(context.model_dump(mode="json"))
        rule = self.select_rule(plan, context)
        schemas = {f.field_id: field_schema(profile, plan, f.target_pointer) for f in rule.fields}
        projected = copy.deepcopy(facts if rule.fact_keys is None else {key: facts[key] for key in rule.fact_keys})
        policy = self.policy
        references = {f.field_id: (get(context.domain_context, f.entity_pointer) if f.cache_scope == "entity"
                                  else context.request_fingerprint) for f in rule.fields}
        # 不包含 request_id 的 entity 鍵可跨請求重用；不同部署、資料、契約或模型仍隔離。
        binding = dict(domain=context.domain, environment=context.environment_id, deployment=context.deployment_id,
                          service=context.service_id, scope=context.scope.model_dump(mode="json"),
                          state=context.state_sha256, namespace=context.data_namespace, references=references,
                          rule=rule.model_dump(mode="json"), schemas=schemas, policy=self.policy_sha256,
                          scenario_policy=context.scenario_policy_sha256,
                          blueprint=plan.model_dump(mode="json"), facts=projected,
                          prompt_version=policy.prompt_version, model=context.model_identity)
        if context.content_lifecycle is not None:
            # 沿用部署、run、情境、契約與實體依賴隔離；全域快照與生成配方另作首次發布證據。
            stable_rule = rule.model_dump(mode="json", exclude={"fields", "generation_mode", "planning_mode"})
            stable_rule["protected_pointers"] = sorted(rule.protected_pointers)
            if rule.fact_keys is not None:
                stable_rule["fact_keys"] = sorted(rule.fact_keys)
            # 以固定 field_id 排序，設定中的欄位順序不會讓同一內容身份跳動。
            stable_fields = sorted((f.model_dump(mode="json", exclude={"instruction"}) for f in rule.fields),
                                   key=lambda field: field["field_id"])
            binding = dict(cache_version=2, domain=context.domain, environment=context.environment_id,
                           deployment=context.deployment_id, service=context.service_id,
                           scope=context.scope.model_dump(mode="json"),
                           lifecycle=context.content_lifecycle.model_dump(mode="json"), references=references,
                           rule=stable_rule, fields=stable_fields,
                           schemas=schemas, facts=projected, scenario_policy=context.scenario_policy_sha256)
        return rule, schemas, projected, digest(binding)

    def cached(self, plan, context, profile, *, facts, budget) -> GeneratedContent | None:
        """只對明確可信世界生命週期預讀已發布內容；命中仍驗欄位，呼叫端須重新 H/I。"""
        budget.check()
        if context.content_lifecycle is None:
            return None
        rule, schemas, _, key = self.cache_binding(plan, context, profile, facts)
        entry = self.cache.get_entry(key)
        if entry is None:
            return None
        result = self.apply(plan, rule, schemas, entry["values"])
        budget.check()
        return GeneratedContent(plan=result, values=entry["values"], cache_key=key, cache_hit=True,
                                trace=dict(rule_id=rule.rule_id, cache_hit=True, source="cache",
                                           content_sha256=digest(entry["values"]),
                                           field_ids=[f.field_id for f in rule.fields], context_id=context.context_id,
                                           content_lifecycle=True, provenance=entry["provenance"]))

    async def generate(self, plan, context, profile, *, facts: dict, budget, intent, feedback=None) -> GeneratedContent:
        """產生或重用片段，回傳尚未發布的內容；相同鍵競爭由 C 發布後再驗勝出值。"""
        budget.check()
        rule, schemas, facts, key = self.cache_binding(plan, context, profile, facts)
        if len(intent.field_ids) != len(set(intent.field_ids)) or set(intent.field_ids) != {f.field_id for f in rule.fields}:
            raise ValueError("Planner requested fields outside the generation policy")
        policy = self.policy
        lifecycle = context.content_lifecycle is not None
        # N 的修正必須重新生成，不能重複讀取剛被部署 gate 拒絕的舊內容。
        entry = self.cache.get_entry(key) if lifecycle and not feedback else None
        values = entry["values"] if entry is not None else None
        if not lifecycle and not feedback:
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
            generate = getattr(self.backend, "generate_repair", self.backend.generate) if feedback else self.backend.generate
            output = await generate(prompt, output_type, budget)
            values = output.model_dump(mode="json", by_alias=True)
        result = self.apply(plan, rule, schemas, values)
        budget.check()
        return GeneratedContent(plan=result, values=values, cache_key=key, cache_hit=cache_hit,
                                trace=dict(rule_id=rule.rule_id, cache_hit=cache_hit, content_sha256=digest(values),
                                           field_ids=[f.field_id for f in rule.fields], model=context.model_identity,
                                           context_id=context.context_id, content_lifecycle=lifecycle,
                                           provenance=entry["provenance"] if entry else dict(
                                               model=context.model_identity, policy_sha256=self.policy_sha256,
                                               prompt_version=policy.prompt_version,
                                               planner_guidance_sha256=digest(intent.instructions),
                                               state_sha256=context.state_sha256, data_namespace=context.data_namespace,
                                               blueprint_sha256=digest(plan.model_dump(mode="json")))))
