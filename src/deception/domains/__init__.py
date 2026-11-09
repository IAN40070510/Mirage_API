"""領域擴充入口：共用流程透過明確註冊的實作選擇業務處理器。"""

from .registry import DomainImplementation, DomainImplementations, default_implementations, get_data_provider

__all__ = ["DomainImplementation", "DomainImplementations", "default_implementations", "get_data_provider"]
