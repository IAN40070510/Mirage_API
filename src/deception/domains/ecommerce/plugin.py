"""電商插件的延遲入口，避免載入共用核心時啟動展示或讀取電商資產。"""

from deception.domains.registry import DomainImplementation


def make_scenario_handler():
    """建立電商專用情境處理器，不改變共用情境引擎。"""
    from .scenarios import EcommerceDomain

    return EcommerceDomain()


def make_data_provider():
    """建立只管理虛構商品快照的資料供應器。"""
    from .provider import SyntheticSnapshotProvider

    return SyntheticSnapshotProvider()


def create_http_demo(**kwargs):
    """把明確管理者設定交給電商展示工廠，不從訪客請求選擇領域。"""
    from .http_demo import create_app

    return create_app(**kwargs)


async def run_generation_demo(*args, **kwargs):
    """執行電商專用真模型展示，共用入口只負責派送所選領域。"""
    from .generation_demo import run_demo

    return await run_demo(*args, **kwargs)


def verify_http_demo(*args, **kwargs):
    """執行電商專用 HTTP 案例，未要求其他領域使用商品查詢矩陣。"""
    from .verification import verify

    return verify(*args, **kwargs)


def run_scenario_demo(*args, **kwargs):
    """執行電商離線情境展示，讓共用命令列只派送明確註冊的領域入口。"""
    from .scenario_demo import run_demo

    return run_demo(*args, **kwargs)


implementation = DomainImplementation("ecommerce", make_scenario_handler, make_data_provider,
                                      create_http_demo, run_generation_demo, verify_http_demo,
                                      scenario_demo=run_scenario_demo)
