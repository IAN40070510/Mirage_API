"""舊情境匯入路徑的相容入口；電商業務實作已移到專屬領域套件。"""

from deception.domains.ecommerce.scenarios import (
    EcommerceDomain, OutcomeDefinition, ResponseTemplate, ScenarioPolicy, ScenarioRule,
    TemplateBinding, pointer_tokens, template_value,
)

__all__ = ["EcommerceDomain", "OutcomeDefinition", "ResponseTemplate", "ScenarioPolicy", "ScenarioRule",
           "TemplateBinding", "pointer_tokens", "template_value"]
