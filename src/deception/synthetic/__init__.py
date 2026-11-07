"""E：具種子、隔離身份、關聯驗證與可重建產物的合成資料工具。"""

from .generator import SyntheticError, generate_dataset, verify_dataset
from .models import DatasetScope, Price, Product, SyntheticConfig, SyntheticDataset, Variant, VerificationReport
from .storage import load_dataset, read_config, save_dataset
from .tool import SyntheticTool

__all__ = ["SyntheticError", "generate_dataset", "verify_dataset", "DatasetScope", "Price", "Product",
           "SyntheticConfig", "SyntheticDataset", "Variant", "VerificationReport", "load_dataset",
           "read_config", "save_dataset", "SyntheticTool"]
