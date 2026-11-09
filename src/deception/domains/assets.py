"""以明確領域 ID 載入資產包；規格、政策及弱點資料均限制在選定包內。"""

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from pydantic import Field

from deception.common.models import SLUG, SyntheticModel
from deception.profile_builder.builder import local_path, read_yaml


class ApplicationConfig(SyntheticModel):
    """共用應用程式只選領域及資產根目錄，不包含商品或其他產業欄位。"""

    schema_version: Literal[1] = 1
    domain: str = Field(pattern=SLUG)
    domains_dir: str = "domains"


class DomainManifest(SyntheticModel):
    """一個領域包的相對資產位置，不包含可執行匯入路徑。"""

    schema_version: Literal[1] = 1
    domain_id: str = Field(pattern=SLUG)
    title: str = Field(min_length=1)
    demo_config: str = Field(min_length=1)
    source_dir: str = Field(min_length=1)
    platform_dir: str = Field(min_length=1)
    bindings_config: str = Field(min_length=1)
    policy_dir: str = Field(min_length=1)
    weakness_catalog: str = Field(min_length=1)


@dataclass(frozen=True)
class DomainAssets:
    """已定位的領域目錄與格式核對過的 manifest，資產讀取仍逐一檢查邊界。"""

    root: Path
    manifest: DomainManifest

    def resolve(self, relative: str, *, file: bool = False) -> Path:
        """拒絕絕對、逃逸或不存在的資產，包含 symlink 解析後越界的路徑。"""
        path = local_path(self.root, relative)
        if not (path.is_file() if file else path.is_dir()):
            raise ValueError("The selected domain asset does not exist")
        return path


def load_domain_assets(domain: str, root: Path = Path("domains")) -> DomainAssets:
    """讀取 root 下明確 domain 的 manifest，回傳可解析包內資產的 DomainAssets。

    領域 ID、檔案類型、缺檔與解析後越界都會拒絕；只讀本地資產，
    不修改來源、下載檔案、核准平台或載入 YAML 指定的程式碼。
    """
    if not isinstance(domain, str):
        raise ValueError("An explicit domain ID is required")
    selection = ApplicationConfig(domain=domain)
    directory = local_path(root, selection.domain)
    manifest = DomainManifest.model_validate(read_yaml(local_path(directory, "domain.yaml").read_bytes()))
    if manifest.domain_id != selection.domain:
        raise ValueError("The domain manifest does not match the selected ID")
    assets = DomainAssets(directory, manifest)
    for name in ("demo_config", "source_dir", "platform_dir", "bindings_config", "policy_dir", "weakness_catalog"):
        assets.resolve(getattr(manifest, name), file=name in ("demo_config", "bindings_config", "weakness_catalog"))
    return assets


def load_application_selection(path: Path | None = None) -> tuple[ApplicationConfig, DomainAssets]:
    """讀管理者設定及環境覆寫，回傳 ApplicationConfig 與核對後的領域資產。

    path 省略時使用 MIRAGE_APP_CONFIG 或 configs/app.yaml；無效設定、
    未找到領域包或資產不符會拋出例外。只讀檔案，不使用 HTTP header 選領域。
    """
    path = Path(os.environ.get("MIRAGE_APP_CONFIG", "configs/app.yaml")) if path is None else path
    value = read_yaml(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("Application configuration must be an object")
    overrides = {name: os.environ[key] for name, key in (("domain", "MIRAGE_DOMAIN"), ("domains_dir", "MIRAGE_DOMAINS_DIR"))
                 if os.environ.get(key)}
    config = ApplicationConfig.model_validate({**value, **overrides})
    return config, load_domain_assets(config.domain, Path(config.domains_dir))


def resolve_identification_paths(platforms_dir: Path | None = None,
                                 bindings_file: Path | None = None) -> tuple[Path, Path]:
    """優先使用管理者明確路徑；缺少的識別輸入只從所選領域 manifest 取得，不猜資料夾。"""
    if platforms_dir is not None and bindings_file is not None:
        return Path(platforms_dir), Path(bindings_file)
    _, assets = load_application_selection()
    platforms = Path(platforms_dir) if platforms_dir is not None else assets.resolve(assets.manifest.platform_dir)
    bindings = Path(bindings_file) if bindings_file is not None else assets.resolve(assets.manifest.bindings_config, file=True)
    return platforms, bindings
