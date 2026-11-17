"""已驗證衍生內容的快取；SQLite 唯一鍵提供跨程序 first-writer-wins 發布。"""

import copy
import json
import sqlite3
import threading
from pathlib import Path

from .models import digest


class ContentCache:
    """未提供路徑時使用記憶體；持久化只保存生成片段及摘要，不保存原始請求。"""

    def __init__(self, path: Path | None = None):
        """建立私有連線與唯一鍵；呼叫者明確決定快取檔案位置。"""
        self._lock = threading.RLock()
        if path is not None:
            path.parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(str(path) if path is not None else ":memory:", check_same_thread=False,
                                   timeout=5)
        self._db.execute("CREATE TABLE IF NOT EXISTS content (key TEXT PRIMARY KEY, payload TEXT NOT NULL, sha TEXT NOT NULL)")
        self._db.execute("CREATE TABLE IF NOT EXISTS content_entries (key TEXT PRIMARY KEY, payload TEXT NOT NULL, sha TEXT NOT NULL)")
        self._db.commit()

    def get(self, cache_key: str) -> dict | None:
        """核對本地內容摘要，異常快取不當成可用模型回應。"""
        with self._lock:
            row = self._db.execute("SELECT payload, sha FROM content WHERE key=?", (cache_key,)).fetchone()
        if row is None:
            return None
        value = json.loads(row[0])
        if not isinstance(value, dict) or digest(value) != row[1]:
            raise ValueError("Content cache integrity check failed")
        return value

    def publish(self, cache_key: str, values: dict) -> dict:
        """C 完成 H/I 後發布；競爭者一律取得勝出值，C 會再驗證相同候選。"""
        payload = json.dumps(values, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
        with self._lock, self._db:
            self._db.execute("INSERT OR IGNORE INTO content(key,payload,sha) VALUES(?,?,?)",
                             (cache_key, payload, digest(values)))
        return copy.deepcopy(self.get(cache_key))

    def get_entry(self, cache_key: str) -> dict | None:
        """讀取同世界內容及首次生成證據，核對整份封套摘要；損毀時明確拒絕。"""
        with self._lock:
            row = self._db.execute("SELECT payload,sha FROM content_entries WHERE key=?", (cache_key,)).fetchone()
        if row is None:
            return None
        entry = json.loads(row[0])
        if (not isinstance(entry, dict) or set(entry) != {"values", "provenance"}
                or not isinstance(entry["values"], dict) or not isinstance(entry["provenance"], dict)
                or digest(entry) != row[1]):
            raise ValueError("Content entry integrity check failed")
        return entry

    def publish_entry(self, cache_key: str, values: dict, provenance: dict) -> dict:
        """原子保存首次通過驗證的值與配方；競爭發布回傳同一勝出封套，絕不覆寫舊內容。"""
        entry = {"values": values, "provenance": provenance}
        payload = json.dumps(entry, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
        with self._lock, self._db:
            self._db.execute("INSERT OR IGNORE INTO content_entries(key,payload,sha) VALUES(?,?,?)",
                             (cache_key, payload, digest(entry)))
        return copy.deepcopy(self.get_entry(cache_key))

    def close(self):
        """釋放檔案連線，不刪除已驗證內容。"""
        with self._lock:
            self._db.close()
