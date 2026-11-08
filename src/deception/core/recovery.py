"""N：在原契約與共用預算內修正生成欄位，或選取管理者明列的確定性備援值。"""

import copy
import json
from typing import Literal

from pydantic import Field, JsonValue, model_validator

from deception.generation.models import digest
from deception.synthetic.models import SLUG, SyntheticModel


class FallbackRule(SyntheticModel):
    """固定同一契約、情境結果及 F/G 政策的欄位值；不接受完整回應或任意 JSON Patch。"""

    rule_id: str = Field(pattern=SLUG)
    generation_rule_id: str = Field(pattern=SLUG)
    generation_policy_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    scenario_policy_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    platform_id: str = Field(pattern=SLUG)
    platform_version: str = Field(min_length=1, max_length=128)
    spec_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    operation_id: str = Field(min_length=1)
    method: str = Field(pattern=r"^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)$")
    path: str = Field(pattern=r"^/")
    outcome_id: str = Field(pattern=SLUG)
    status_code: int = Field(ge=200, le=599)
    media_type: Literal["application/json"] = "application/json"
    values: dict[str, JsonValue] = Field(min_length=1, max_length=16)


class RecoveryPolicy(SyntheticModel):
    """備援預設停用；修正次數仍由 G 的 RunLimits.max_repairs 管理，不另起預算。"""

    schema_version: Literal[1] = 1
    domain: str = Field(pattern=SLUG)
    policy_id: str = Field(pattern=SLUG)
    policy_version: str = Field(min_length=1, max_length=128)
    enabled: bool = False
    rules: list[FallbackRule] = Field(default_factory=list, max_length=256)

    @model_validator(mode="after")
    def check_unique(self):
        """拒絕重複規則 ID 或完全相同的選擇條件，避免備援有兩個不同答案。"""
        if len({rule.rule_id for rule in self.rules}) != len(self.rules):
            raise ValueError("Fallback rule IDs must be unique")
        selectors = [digest(rule.model_dump(mode="json", exclude={"rule_id", "values"})) for rule in self.rules]
        if len(set(selectors)) != len(selectors):
            raise ValueError("Fallback selectors must be unique")
        return self


class RecoveryTool:
    """封存 N 政策；選取結果仍須經 G.apply、H、I 及 C 的即時信任核對。"""

    def __init__(self, policy: RecoveryPolicy | None = None):
        """重驗並保存獨立政策快照；未提供政策時只保留原有有限修正，不啟用備援。"""
        checked = None if policy is None else RecoveryPolicy.model_validate(policy.model_dump(mode="json"))
        self._policy_json = None if checked is None else checked.model_dump_json()
        self._policy_sha256 = None if checked is None else digest(checked.model_dump(mode="json"))

    @property
    def policy(self) -> RecoveryPolicy | None:
        """回傳政策副本，呼叫端修改物件不會改動這個工具已封存的規則。"""
        return None if self._policy_json is None else RecoveryPolicy.model_validate_json(self._policy_json)

    @property
    def policy_sha256(self) -> str | None:
        """提供實際採用政策的摘要，沒有備援政策時回 None。"""
        return self._policy_sha256

    def select_fallback(self, plan, context, generation_rule_id: str) -> FallbackRule | None:
        """只選唯一精確匹配的同分支備援；停用或未配置時回 None，不回退其他規則。"""
        policy = self.policy
        if policy is None or not policy.enabled:
            return None
        if policy.domain != context.domain or plan.scope != context.scope:
            raise ValueError("Fallback domain and scope must match the current run")
        expected = (generation_rule_id, context.generation_policy_sha256, context.scenario_policy_sha256,
                    plan.scope.platform_id, plan.scope.platform_version, plan.scope.spec_sha256,
                    context.operation_id, plan.method, plan.path, context.outcome_id, plan.status_code, plan.media_type)
        matches = [rule for rule in policy.rules if
                   (rule.generation_rule_id, rule.generation_policy_sha256, rule.scenario_policy_sha256,
                    rule.platform_id, rule.platform_version, rule.spec_sha256, rule.operation_id,
                    rule.method, rule.path, rule.outcome_id, rule.status_code, rule.media_type) == expected]
        if len(matches) > 1:
            raise ValueError("Fallback selection is ambiguous")
        return None if not matches else matches[0].model_copy(deep=True)

    def apply_fallback(self, generator, plan, context, rule, schemas):
        """以 G 相同白名單及 schema 套用固定值；回傳計畫與備援追溯，不寫模型內容快取。"""
        fallback = self.select_fallback(plan, context, rule.rule_id)
        if fallback is None:
            return None
        values = copy.deepcopy(fallback.values)
        result = generator.apply(plan, rule, schemas, values)
        return result, {"source": "fallback", "fallback_rule_id": fallback.rule_id,
                        "policy_sha256": self.policy_sha256, "content_sha256": digest(values),
                        "field_ids": sorted(values), "cache_hit": False}

    @staticmethod
    def can_repair_gate(result) -> bool:
        """僅允許有明確 body 錯誤的 reject 進入欄位修正；身份、headers 或不明結果直接停止。"""
        return (result.decision == "reject" and result.valid is False and bool(result.errors)
                and all(issue.location == "body" for issue in result.errors))

    @staticmethod
    def repair_feedback(field_ids) -> str:
        """只回固定指示及管理者核准的欄位 ID，不把例外、原請求或 I 的原始 reason 回填模型。"""
        return json.dumps({"code": "allowed_content_rejected", "allowed_field_ids": sorted(field_ids),
                           "instruction": "Regenerate only these allowed fields to satisfy their supplied schemas. "
                                          "Keep authoritative facts, scenario and HTTP metadata unchanged."},
                          ensure_ascii=False, sort_keys=True)
