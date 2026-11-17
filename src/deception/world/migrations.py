"""以資料庫交易鎖與 checksum 套用有序、可追溯的 Runtime schema migrations。"""

import hashlib
from pathlib import Path
import re

from .postgres_store import PostgresWorldStore


def apply_migrations(dsn: str, directory: Path) -> tuple[str, ...]:
    """依檔名套用 SQL 並記錄 checksum，拒絕改寫已登錄 migration。

    所有變更在同一交易內提交。並行啟動以 schema 專屬 advisory lock 序列化，
    不保存或輸出 DSN。呼叫端必須提供 Mirage 專用資料庫／schema。
    """
    root = directory.resolve()
    paths = sorted(directory.glob("*.sql"))
    if not paths:
        raise ValueError("no runtime migrations found")
    applied = []
    with PostgresWorldStore(dsn)._connection() as connection:
        schema, = connection.execute("SELECT current_schema()").fetchone()
        if not schema:
            raise ValueError("runtime migration schema is unavailable")
        connection.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s,0))", ("mirage:migrations:" + schema,))
        connection.execute("CREATE TABLE IF NOT EXISTS mirage_schema_migrations "
                           "(version TEXT PRIMARY KEY, sha256 CHAR(64) NOT NULL)")
        for path in paths:
            if not re.fullmatch(r"[0-9]{3}_[a-z0-9_]+\.sql", path.name) or path.is_symlink() or path.resolve().parent != root:
                raise ValueError("invalid runtime migration path")
            data = path.read_bytes()
            digest = hashlib.sha256(data).hexdigest()
            previous = connection.execute("SELECT sha256 FROM mirage_schema_migrations WHERE version=%s",
                                          (path.name,)).fetchone()
            if previous:
                if previous[0] != digest:
                    raise ValueError("runtime migration checksum changed: " + path.name)
                continue
            connection.execute(data.decode("utf-8"))
            connection.execute("INSERT INTO mirage_schema_migrations VALUES (%s,%s)", (path.name, digest))
            applied.append(path.name)
    return tuple(applied)
