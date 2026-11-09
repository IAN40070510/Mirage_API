"""F：選擇領域 → 可信判定與政策 → 情境 family → 領域資料 → H 計畫。"""

from .engine import ScenarioEngine, fingerprint_request, load_policy
from .models import (AttackAssessment, DomainOutcome, DomainPolicy, PreparedScenario,
                     ResponseTemplateBase, ScenarioDecision, ScenarioPreparation, ScenarioRuleBase)
from .registry import DomainRegistry, ScenarioDomain, default_registry

__all__ = ["AttackAssessment", "DomainOutcome", "DomainPolicy", "DomainRegistry", "OutcomeDefinition",
           "PreparedScenario", "ResponseTemplate", "ResponseTemplateBase", "ScenarioDomain",
           "ScenarioDecision", "ScenarioEngine", "ScenarioPolicy", "ScenarioPreparation",
           "ScenarioRule", "ScenarioRuleBase", "TemplateBinding", "default_registry", "fingerprint_request", "load_policy"]


def __getattr__(name):
    """僅為舊電商政策名稱提供延遲相容轉出，共用引擎載入時不初始化商品模型。"""
    if name in {"OutcomeDefinition", "ResponseTemplate", "ScenarioPolicy", "ScenarioRule", "TemplateBinding"}:
        from deception.domains.ecommerce import scenarios

        return getattr(scenarios, name)
    raise AttributeError(name)
