"""只接受伺服器明確註冊的領域實作，資產 YAML 不能要求任意 Python 匯入。"""

import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass


@dataclass(frozen=True)
class DomainImplementation:
    """綁定同一領域的情境、資料、展示與驗證入口，核心不解讀商品等業務欄位。"""

    domain_id: str
    scenario_factory: Callable
    data_provider_factory: Callable
    http_demo_factory: Callable
    generation_demo: Callable
    http_verifier: Callable
    scenario_demo: Callable | None = None


class DomainImplementations:
    """獨立的領域實作表；未知 ID 與重複註冊均拒絕，不回退其他領域。"""

    def __init__(self, implementations: Iterable[DomainImplementation] = ()):
        """複製明確提供的實作定義，不掃描外部套件或執行設定中的程式碼。"""
        self._items = {}
        for implementation in implementations:
            self.register(implementation)

    def register(self, implementation: DomainImplementation) -> None:
        """檢查領域 ID 與完整 callable 介面後加入註冊表，避免靜默替換實作。"""
        if (not isinstance(implementation, DomainImplementation) or
                not isinstance(implementation.domain_id, str) or
                not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,63}", implementation.domain_id) or
                any(not callable(getattr(implementation, name)) for name in
                    ("scenario_factory", "data_provider_factory", "http_demo_factory", "generation_demo", "http_verifier")) or
                (implementation.scenario_demo is not None and not callable(implementation.scenario_demo))):
            raise ValueError("A domain requires an explicit ID and all registered interfaces")
        if implementation.domain_id in self._items:
            raise ValueError("The domain is already registered")
        self._items[implementation.domain_id] = implementation

    def get(self, domain_id: str) -> DomainImplementation:
        """依明確 ID 取得已註冊實作；找不到時不猜測或使用預設電商。"""
        if not isinstance(domain_id, str) or domain_id not in self._items:
            raise ValueError("The selected domain implementation is not registered")
        return self._items[domain_id]

    def domain_ids(self) -> tuple[str, ...]:
        """回傳固定排序的領域清單，供設定選單與命令列使用。"""
        return tuple(sorted(self._items))


def default_implementations() -> DomainImplementations:
    """由應用程式明確載入內建領域插件；資產只選 ID，不能新增程式碼入口。"""
    from .ecommerce.plugin import implementation

    return DomainImplementations([implementation])


def get_data_provider(domain_id: str):
    """為已選領域建立資料供應器；新領域也可由協調器明確注入自己的 provider。"""
    return default_implementations().get(domain_id).data_provider_factory()
