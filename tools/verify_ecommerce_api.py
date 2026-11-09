"""舊電商 HTTP 驗證命令的相容入口；專用案例實作位於電商領域套件。"""

import sys

from deception.domains.ecommerce import verification as implementation

if __name__ == "__main__":
    raise SystemExit(implementation.main())
else:
    # 保持既有呼叫端對同一模組 helper 的替換語意，不複製另一套驗證實作。
    sys.modules[__name__] = implementation
