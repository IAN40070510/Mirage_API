"""共用展示入口：依管理者選定的領域派送，不在核心定義商品或其他業務欄位。"""

from pathlib import Path
import os

from deception.domains.assets import load_application_selection
from deception.domains.registry import default_implementations


def create_app(config=None, *, output_root: Path | None = None, registry=None):
    """選擇領域並回傳其 FastAPI 展示 app。

    config 可明確提供領域設定；省略時讀管理者 app 設定與 manifest。
    registry 只接受受信任程式建立的實作表，output_root 覆寫展示產物位置。
    未知領域、缺少資產或領域設定錯誤會拋出例外，不回退其他領域；
    領域工廠可在輸出目錄建立合成契約、資料與快取，連線由 app 生命週期關閉。
    """
    implementations = default_implementations() if registry is None else registry
    assets = None
    if config is None:
        selection, assets = load_application_selection()
        domain = selection.domain
    else:
        domain = getattr(config, "domain", None)
    implementation = implementations.get(domain)
    if output_root is None:
        output_root = (Path(os.environ["MIRAGE_DEMO_OUTPUT"]) if os.environ.get("MIRAGE_DEMO_OUTPUT") else
                       Path(os.environ.get("MIRAGE_OUTPUT_ROOT", "generated")) / "domains" / domain)
    arguments = {"config": config, "output_root": output_root}
    if assets is not None:
        arguments.update(config_path=assets.resolve(assets.manifest.demo_config, file=True),
                         weakness_catalog=assets.resolve(assets.manifest.weakness_catalog, file=True))
    return implementation.http_demo_factory(**arguments)


def __getattr__(name):
    """舊電商展示模型名稱只作相容轉出；新程式應從明確的領域套件匯入。"""
    if name in {"DemoConfig", "TemplateOnlyBackend", "load_demo_config"}:
        from deception.domains.ecommerce import http_demo

        return getattr(http_demo, name)
    raise AttributeError(name)
