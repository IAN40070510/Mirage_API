"""跨領域共用的嚴格模型與資料交換介面。"""

from .models import DatasetScope, SLUG, SyntheticModel
from .data import CompositionData

__all__ = ["CompositionData", "DatasetScope", "SLUG", "SyntheticModel"]
