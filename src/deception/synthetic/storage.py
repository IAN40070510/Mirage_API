"""將 E 產物保存為可重建 JSON，載入時核對外部指定的設定。"""

import json
from pathlib import Path

from deception.profile_builder.builder import _atomic_write, local_path, read_yaml
from mirage_validator.json_utils import reject_constant, unique_object

from .generator import SyntheticError, checked_dataset, encoded
from .models import SyntheticConfig, SyntheticDataset


def read_config(path: Path) -> SyntheticConfig:
    """讀取明確指定的規則 YAML，不載入舊版 state 草稿或外部資料。"""
    try:
        return SyntheticConfig.model_validate(read_yaml(path.read_bytes()))
    except Exception as exc:
        raise SyntheticError(f"Invalid synthetic configuration: {exc}") from exc


def load_dataset(path: Path, expected_config: SyntheticConfig) -> SyntheticDataset:
    """拒絕重複 JSON key、損壞資料與 scope 不符的產物，再執行完整重建驗證。"""
    try:
        value = json.loads(path.read_bytes(), object_pairs_hook=unique_object, parse_constant=reject_constant)
        dataset = SyntheticDataset.model_validate(value)
        return checked_dataset(dataset, expected_config)
    except SyntheticError:
        raise
    except Exception as exc:
        raise SyntheticError(f"Cannot load dataset: {exc}") from exc


def save_dataset(dataset: SyntheticDataset, output_root: Path) -> Path:
    """以完整設定的 hash 作檔名，原子保存；已存在的有效產物可重用。"""
    try:
        checked = checked_dataset(dataset, dataset.config)
        path = local_path(output_root, f"synthetic_data/{checked.config.scope.platform_id}/{checked.namespace}.json")
        if path.exists():
            load_dataset(path, checked.config)
        _atomic_write(path, encoded(checked.model_dump(mode="json")))
        return path
    except SyntheticError:
        raise
    except Exception as exc:
        raise SyntheticError(f"Cannot save dataset: {exc}") from exc
