"""舊電商離線展示的延遲相容轉出；新程式應選領域後使用該領域入口。"""

__all__ = ["run_demo"]


def __getattr__(name):
    """只在既有呼叫端讀取展示函式時載入電商模組，不在共用入口定義商品行為。"""
    if name in {"run_demo", "_json_bytes", "_specification", "_policy", "_request"}:
        from deception.domains.ecommerce import scenario_demo

        return getattr(scenario_demo, name)
    raise AttributeError(name)
