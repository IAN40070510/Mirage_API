"""明確的領域註冊表；未知領域不會自動套用電商邏輯。"""

import re
from collections.abc import Iterable
from typing import Protocol

from pydantic import JsonValue

from deception.discovery.models import IdentifiedOperation
from deception.profile_builder.models import OperationContext
from deception.common.models import SLUG

from .models import DomainOutcome, DomainPolicy, PreparedScenario, ScenarioRuleBase


class ScenarioDomain(Protocol):
    """領域擴充介面：自行驗證政策、選擇依據與資料，核心維持共用信任檢查。"""

    domain_id: str
    policy_type: type[DomainPolicy]

    def prepare(self, rule: ScenarioRuleBase, identity: IdentifiedOperation,
                profile: OperationContext, operation: dict) -> dict[str, JsonValue]:
        """檢查領域契約並擷取可封存的選擇資料，不讀寫互動狀態。"""
        ...

    def resolve(self, policy: DomainPolicy, rule: ScenarioRuleBase,
                prepared: PreparedScenario, data: object) -> DomainOutcome:
        """驗證領域資料與 scope，回傳結果及交給 H 的明確計畫。"""
        ...


class DomainRegistry:
    """由伺服器程式註冊處理器；YAML 只可選 ID，不可指定 Python 匯入路徑。"""

    def __init__(self, handlers: Iterable[ScenarioDomain] = ()):
        """獨立保存註冊表，不依賴可變的全域 registry。"""
        self._handlers: dict[str, ScenarioDomain] = {}
        for handler in handlers:
            self.register(handler)

    def register(self, handler: ScenarioDomain) -> None:
        """拒絕不完整處理器及重複領域，避免靜默覆寫原有行為。"""
        domain = getattr(handler, "domain_id", None)
        model = getattr(handler, "policy_type", None)
        if (not isinstance(domain, str) or not re.fullmatch(SLUG, domain) or
                not isinstance(model, type) or not issubclass(model, DomainPolicy) or
                not callable(getattr(handler, "prepare", None)) or not callable(getattr(handler, "resolve", None))):
            raise ValueError("A domain requires an ID, a DomainPolicy subclass and prepare/resolve handlers")
        if domain in self._handlers:
            raise ValueError(f"Domain already registered: {domain}")
        self._handlers[domain] = handler

    def get(self, domain: str) -> ScenarioDomain:
        """只接受明確已註冊的 ID，不從 URL、header 或平台名稱猜測領域。"""
        if not isinstance(domain, str) or domain not in self._handlers:
            raise ValueError(f"Unknown scenario domain: {domain}")
        return self._handlers[domain]

    def domain_ids(self) -> tuple[str, ...]:
        """回傳穩定排序的已註冊 ID，供 CLI 或未來選擇介面使用。"""
        return tuple(sorted(self._handlers))


def default_registry() -> DomainRegistry:
    """目前內建電商；後續領域由應用程式明確註冊各自的處理器。"""
    from deception.domains.registry import default_implementations

    implementations = default_implementations()
    return DomainRegistry([implementations.get(domain).scenario_factory() for domain in implementations.domain_ids()])
