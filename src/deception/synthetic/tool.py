"""舊電商資料模組相容轉出；實作只保留在領域套件。"""

import sys
from deception.domains.ecommerce.synthetic import tool as _implementation

# 共用同一模組物件，保留既有函式、型別與測試替換語意。
sys.modules[__name__] = _implementation
