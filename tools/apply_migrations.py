"""從受控環境變數取得 DSN，套用 Mirage 專用資料庫 migrations。"""

import os
from pathlib import Path

from deception.world.migrations import apply_migrations


def main() -> int:
    """執行版本化 schema 更新，僅印出已套用版本，不輸出憑證或連線字串。"""
    dsn = os.environ.get("MIRAGE_POSTGRES_DSN")
    if not dsn:
        raise ValueError("MIRAGE_POSTGRES_DSN must be set")
    applied = apply_migrations(dsn, Path(__file__).resolve().parents[1] / "migrations")
    print("Runtime migrations applied: " + (", ".join(applied) if applied else "already current"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
