"""舊電商生成展示的相容轉出；共用命令列透過領域註冊表選取展示。"""


def __getattr__(name):
    """保持既有工具的 helper 匯入可用，實作與商品規則只存在電商套件內。"""
    from deception.domains.ecommerce import generation_demo

    if name in {"_bytes", "_policies", "_specification", "_request", "run_demo"}:
        return getattr(generation_demo, name)
    raise AttributeError(name)
