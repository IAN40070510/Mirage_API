"""保存部署範圍內 issuer／kid 的永久撤銷，與入口 Replay 消費排序。"""

from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import json


class KeyRevocationError(ValueError):
    """表示金鑰撤銷參數、版本或交易模式不符合控制協定。"""


@dataclass(frozen=True)
class KeyRevocation:
    """保存指定 issuer／kid 在此部署的永久撤銷版本，不包含金鑰內容。"""

    issuer: str
    kid: str
    revision: int


class PostgresTrustedKeyRevocations:
    """共用永久墓碑；公鑰仍由固定部署設定提供，不從資料庫或 Token 新增信任。"""

    def __init__(self, dsn: str, *, environment_id: str, deployment_id: str):
        """固定管理域及 Mirage 專用資料庫，連線延後到操作時建立。"""
        if not isinstance(dsn, str) or not dsn.strip():
            raise KeyRevocationError("key_revocation_requires_dsn")
        self._validate_identity(environment_id, deployment_id)
        self._dsn, self._environment_id, self._deployment_id = dsn, environment_id, deployment_id

    @staticmethod
    def _validate_identity(first: str, second: str) -> None:
        """驗證兩個身份欄位皆為非空、最多 128 字元的字串，不接受任意物件或空白。"""
        if any(not isinstance(value, str) or not value.strip() or len(value) > 128 for value in (first, second)):
            raise KeyRevocationError("invalid_key_revocation_identity")

    def _connection(self):
        """建立不自動提交且有連線期限的控制連線，錯誤不降級至記憶體。"""
        import psycopg

        return psycopg.connect(self._dsn, connect_timeout=5)

    def _lock(self, cursor, issuer: str, kid: str, *, exclusive: bool = False) -> None:
        """以資料表及完整身份摘要鎖住控制域，只接受有效 Read Committed 交易。"""
        self._validate_identity(issuer, kid)
        if cursor.connection.autocommit:
            raise KeyRevocationError("key_control_requires_transaction")
        identity = json.dumps([self._environment_id, self._deployment_id, issuer, kid], ensure_ascii=True,
                              separators=(",", ":")).encode("ascii")
        digest = hashlib.sha256(identity).hexdigest()
        function = "pg_advisory_xact_lock" if exclusive else "pg_advisory_xact_lock_shared"
        cursor.execute("SET LOCAL statement_timeout='5s'")
        cursor.execute("SELECT current_setting('transaction_isolation'), " + function + "(hashtextextended("
            "'mirage-trusted-key:'||'trusted_key_revocations'::regclass::oid::text||':'||%s,0))", (digest,))
        isolation, _ = cursor.fetchone()
        if isolation != "read committed":
            raise KeyRevocationError("key_control_requires_read_committed")

    def _select(self, cursor, issuer: str, kid: str) -> KeyRevocation | None:
        """在已取得控制鎖後以新 statement 讀墓碑，避免等待前的舊快照漏看撤銷。"""
        cursor.execute("SELECT revision FROM trusted_key_revocations WHERE "
            "environment_id=%s AND deployment_id=%s AND issuer=%s AND kid=%s",
            (self._environment_id, self._deployment_id, issuer, kid))
        row = cursor.fetchone()
        return None if row is None else KeyRevocation(issuer, kid, row[0])

    @contextmanager
    def guard(self, issuer: str, kid: str):
        """持有共享撤銷鎖直到呼叫端完成 Replay 消費，讓已撤銷 key 不能取得新驗證。"""
        self._validate_identity(issuer, kid)
        with self._connection() as connection:
            with connection.cursor() as cursor:
                self._lock(cursor, issuer, kid)
                yield self._select(cursor, issuer, kid)

    def consume_guarded_replay(self, replay_store, *, issuer: str, kid: str,
                               audience: str, jti: str, expires_at: int, now: int):
        """以同一實體連線與交易持有 Key 鎖並消費 Replay；確認 COMMIT 後才回報結果。

        不接受分離的 Replay DSN 或其他儲存實作，以免呼叫端誤以為跨連線已
        原子提交。傳回 (revocation, replay_result)，遭撤銷時不寫入 Replay。
        """
        from deception.world.postgres_replay import PostgresReplayStore

        if not isinstance(replay_store, PostgresReplayStore) or replay_store._dsn != self._dsn:
            raise KeyRevocationError("ingress_requires_same_postgres_connection_domain")
        with self._connection() as connection:
            with connection.cursor() as cursor:
                self._lock(cursor, issuer, kid)
                revoked = self._select(cursor, issuer, kid)
                if revoked is not None:
                    return revoked, None
                result = replay_store._consume_on_cursor(cursor, issuer=issuer, audience=audience,
                                                          jti=jti, expires_at=expires_at, now=now)
                return None, result

    def revocation(self, issuer: str, kid: str) -> KeyRevocation | None:
        """以新交易查目前永久墓碑，未知提交結果只查回，不盲目重做撤銷。"""
        with self.guard(issuer, kid) as state:
            return state

    def revoke(self, issuer: str, kid: str, *, revision: int) -> KeyRevocation:
        """排他鎖內提交或提升永久墓碑；版本須遞增，不提供刪除或復活方法。"""
        self._validate_identity(issuer, kid)
        if type(revision) is not int or not 1 <= revision <= 9223372036854775807:
            raise KeyRevocationError("invalid_key_revocation_revision")
        with self._connection() as connection:
            with connection.cursor() as cursor:
                self._lock(cursor, issuer, kid, exclusive=True)
                previous = self._select(cursor, issuer, kid)
                if previous is not None and revision <= previous.revision:
                    raise KeyRevocationError("key_revocation_revision_not_monotonic")
                cursor.execute("INSERT INTO trusted_key_revocations "
                    "(environment_id,deployment_id,issuer,kid,revision) VALUES (%s,%s,%s,%s,%s) "
                    "ON CONFLICT (environment_id,deployment_id,issuer,kid) DO UPDATE SET revision=EXCLUDED.revision",
                    (self._environment_id, self._deployment_id, issuer, kid, revision))
        return KeyRevocation(issuer, kid, revision)
