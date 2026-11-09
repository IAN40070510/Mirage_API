"""電商資料供應器：完整驗證商品快照，再輸出通用事實及組合資料。"""

import copy
from pathlib import Path

from deception.common.data import CompositionData
from deception.generation.pointers import get

from .synthetic.generator import checked_dataset, generate_dataset
from .synthetic.models import SyntheticConfig
from .synthetic.storage import load_dataset, read_config


class EcommerceDataProvider:
    """將電商資料語意隔離在領域實作，協調器只調用共同的供應介面。"""

    def load(self, config, data, expected_scope):
        """核對管理者完整規則與情境 scope，禁止重新標記其他 run 的商品資料。"""
        config = SyntheticConfig.model_validate(config.model_dump(mode="json"))
        if config.scope != expected_scope:
            raise ValueError("Generation configuration does not match the prepared scenario scope")
        return generate_dataset(config) if data is None else checked_dataset(data, config)

    def facts(self, data, plan) -> dict:
        """只投影本次計畫明列的權威映射，不將完整資料集或原始請求送給模型。"""
        source = self.composition_data(data).payload
        return {binding.target_pointer: copy.deepcopy(get(source, binding.source_pointer)) for binding in plan.bindings}

    def composition_data(self, data) -> CompositionData:
        """由電商模型重建驗證後轉成 scope／payload，組合核心不再匯入商品型別。"""
        return data.to_composition_data()

    def from_files(self, config_path: Path, dataset_path: Path) -> CompositionData:
        """依明確設定重讀並核對電商資料檔，供共用組合 CLI 使用領域投影。"""
        config = read_config(config_path)
        return self.composition_data(load_dataset(dataset_path, config))


# 舊協調器曾公開此名稱；相同領域實作不複製或重新定義生成行為。
SyntheticSnapshotProvider = EcommerceDataProvider
