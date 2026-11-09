"""電商領域的合成商品、變體、價格、庫存及唯讀查詢工具。"""

from .generator import SyntheticError, generate_dataset, verify_dataset
from .models import DatasetScope, Price, Product, SyntheticConfig, SyntheticDataset, Variant, VerificationReport
from .storage import load_dataset, read_config, save_dataset
from .tool import SyntheticTool

__all__ = ["SyntheticError", "generate_dataset", "verify_dataset", "DatasetScope", "Price", "Product",
           "SyntheticConfig", "SyntheticDataset", "Variant", "VerificationReport", "load_dataset",
           "read_config", "save_dataset", "SyntheticTool"]
