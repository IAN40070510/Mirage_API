"""G5 隔離 Fence PostgreSQL 的受簽章 Checkpoint/Head；不得用作 BD-05 解禁。"""

from __future__ import annotations

from dataclasses import replace
import hmac

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
import psycopg

from .restore_anchor import (
    RestoreAnchorError, SignedAnchorCheckpoint, SignedAnchorHead, _MAX_CHECKPOINTS,
    _ZERO_DIGEST, _identifier,
)


class PostgresAnchorPublisher:
    """僅限獨立 Fence Publisher 登入，在同一交易提交簽署鏈節及單調 Head。"""

    def __init__(self, dsn: str, *, expected_login: str, trusted_namespace: str,
                 trusted_epoch: str, publisher_public_key: bytes) -> None:
        """從獨立部署設定固定登入、權威範圍與公鑰，不接受還原庫自選世代。"""
        if (not dsn or not _identifier(expected_login)
                or not _identifier(trusted_namespace) or not _identifier(trusted_epoch)
                or type(publisher_public_key) is not bytes or len(publisher_public_key) != 32):
            raise RestoreAnchorError("restore_anchor_publisher_config_invalid")
        self._dsn = dsn
        self._login = expected_login
        self._namespace = trusted_namespace
        self._epoch = trusted_epoch
        self._key = Ed25519PublicKey.from_public_bytes(publisher_public_key)

    def append(self, checkpoint: SignedAnchorCheckpoint) -> str:
        """原子發布下一節 COMMITTED 證據；ACK 不明時由上游另查，絕不盲重送。"""
        if not isinstance(checkpoint, SignedAnchorCheckpoint) or checkpoint.status != "COMMITTED":
            raise RestoreAnchorError("restore_anchor_not_committed")
        if (checkpoint.namespace != self._namespace or checkpoint.epoch != self._epoch):
            raise RestoreAnchorError("restore_anchor_publisher_scope_mismatch")
        try:
            self._key.verify(checkpoint.signature, checkpoint.payload())
        except (ValueError, InvalidSignature) as exc:
            raise RestoreAnchorError("restore_anchor_publisher_signature_invalid") from exc
        digest = checkpoint.chain_digest()
        try:
            with psycopg.connect(self._dsn, connect_timeout=5) as connection:
                with connection.cursor() as cursor:
                    cursor.execute("SET LOCAL lock_timeout='3s'")
                    cursor.execute("SELECT current_user")
                    if cursor.fetchone()[0] != self._login:
                        raise RestoreAnchorError("restore_anchor_publisher_login_mismatch")
                    # 第 1 節尚無可 FOR UPDATE 的 Head；固定 advisory xact lock
                    # 將同 Namespace/Epoch 的首次發布也序列化。
                    cursor.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
                                   (f"{len(checkpoint.namespace)}:{checkpoint.namespace}:{checkpoint.epoch}",))
                    cursor.execute(
                        """SELECT sequence, checkpoint_digest FROM mirage_restore_fence.heads
                           WHERE namespace=%s AND epoch=%s FOR UPDATE""",
                        (checkpoint.namespace, checkpoint.epoch),
                    )
                    head = cursor.fetchone()
                    if head is None:
                        expected_seq, prior, next_event = 1, _ZERO_DIGEST, 1
                    else:
                        expected_seq, prior = head[0] + 1, head[1]
                        cursor.execute(
                            """SELECT last_event FROM mirage_restore_fence.checkpoints
                               WHERE namespace=%s AND epoch=%s AND sequence=%s""",
                            (checkpoint.namespace, checkpoint.epoch, head[0]),
                        )
                        last = cursor.fetchone()
                        if last is None:
                            raise RestoreAnchorError("restore_anchor_head_without_checkpoint")
                        next_event = last[0] + 1
                    if (checkpoint.sequence != expected_seq or expected_seq > _MAX_CHECKPOINTS
                            or not hmac.compare_digest(checkpoint.previous_digest, prior)
                            or checkpoint.first_event != next_event):
                        raise RestoreAnchorError("restore_anchor_publish_sequence_or_coverage")
                    cursor.execute(
                        """INSERT INTO mirage_restore_fence.checkpoints
                           (namespace,epoch,sequence,previous_digest,world_digest,events_digest,
                            first_event,last_event,publication_id,status,signature,checkpoint_digest)
                           VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                        (checkpoint.namespace, checkpoint.epoch, checkpoint.sequence,
                         checkpoint.previous_digest, checkpoint.world_digest,
                         checkpoint.events_digest, checkpoint.first_event, checkpoint.last_event,
                         checkpoint.publication_id, checkpoint.status, checkpoint.signature, digest),
                    )
                    if head is None:
                        cursor.execute(
                            """INSERT INTO mirage_restore_fence.heads
                               (namespace,epoch,sequence,checkpoint_digest) VALUES (%s,%s,%s,%s)""",
                            (checkpoint.namespace, checkpoint.epoch, checkpoint.sequence, digest),
                        )
                    else:
                        cursor.execute(
                            """UPDATE mirage_restore_fence.heads
                               SET sequence=%s,checkpoint_digest=%s
                               WHERE namespace=%s AND epoch=%s""",
                            (checkpoint.sequence, digest, checkpoint.namespace, checkpoint.epoch),
                        )
            return digest
        except (psycopg.Error, OSError) as exc:
            raise RestoreAnchorError("restore_anchor_publish_unverifiable") from exc


class PostgresAnchorHeadReader:
    """獨立 Head Authority 以 Fence DB 最新 Head 回答挑戰並唯讀提供簽章鏈。"""

    def __init__(self, dsn: str, *, expected_login: str, trusted_namespace: str,
                 trusted_epoch: str, head_private_key: Ed25519PrivateKey) -> None:
        """由獨立設定釘住 Head 範圍和私鑰，禁止還原庫與 HTTP 指定舊世代。"""
        if (not dsn or not _identifier(expected_login)
                or not _identifier(trusted_namespace) or not _identifier(trusted_epoch)
                or not isinstance(head_private_key, Ed25519PrivateKey)):
            raise RestoreAnchorError("restore_anchor_head_config_invalid")
        self._dsn = dsn
        self._login = expected_login
        self._namespace = trusted_namespace
        self._epoch = trusted_epoch
        self._key = head_private_key

    def _query(self, statement: str, args: tuple) -> list[tuple]:
        """獨立唯讀交易核對實際登入；連線或 ACL 不明即拒絕。"""
        try:
            with psycopg.connect(self._dsn, connect_timeout=5, options="-c default_transaction_read_only=on") as conn:
                with conn.cursor() as cursor:
                    cursor.execute("SELECT current_user")
                    if cursor.fetchone()[0] != self._login:
                        raise RestoreAnchorError("restore_anchor_head_login_mismatch")
                    cursor.execute(statement, args)
                    return cursor.fetchall()
        except (psycopg.Error, OSError) as exc:
            raise RestoreAnchorError("restore_anchor_head_unverifiable") from exc

    def observe_head(self, namespace: str, epoch: str, challenge: bytes) -> SignedAnchorHead:
        """對真正獨立持久化最高 Head 簽署當次 nonce，而非信任 World DB 副本。"""
        if (not _identifier(namespace) or not _identifier(epoch)
                or type(challenge) is not bytes or len(challenge) != 32):
            raise RestoreAnchorError("restore_anchor_head_request_invalid")
        if namespace != self._namespace or epoch != self._epoch:
            raise RestoreAnchorError("restore_anchor_head_scope_mismatch")
        rows = self._query(
            """SELECT sequence, checkpoint_digest FROM mirage_restore_fence.heads
               WHERE namespace=%s AND epoch=%s""", (namespace, epoch),
        )
        if len(rows) != 1:
            raise RestoreAnchorError("restore_anchor_head_missing")
        result = SignedAnchorHead(namespace=namespace, epoch=epoch, sequence=rows[0][0],
                                  checkpoint_digest=rows[0][1], challenge=challenge,
                                  signature=bytes(64))
        return replace(result, signature=self._key.sign(result.payload()))

    def read_checkpoints(self, namespace: str, epoch: str, first: int,
                         last: int) -> list[SignedAnchorCheckpoint]:
        """由同一獨立 Fence DB 取得有界且按序的原始簽章節點。"""
        if (not _identifier(namespace) or not _identifier(epoch)
                or type(first) is not int or type(last) is not int
                or first < 1 or last < first or last > _MAX_CHECKPOINTS):
            raise RestoreAnchorError("restore_anchor_range_invalid")
        if namespace != self._namespace or epoch != self._epoch:
            raise RestoreAnchorError("restore_anchor_head_scope_mismatch")
        rows = self._query(
            """SELECT namespace,epoch,sequence,previous_digest,world_digest,events_digest,
                      first_event,last_event,publication_id,status,signature
               FROM mirage_restore_fence.checkpoints
               WHERE namespace=%s AND epoch=%s AND sequence BETWEEN %s AND %s
               ORDER BY sequence""", (namespace, epoch, first, last),
        )
        return [SignedAnchorCheckpoint(*row[:10], bytes(row[10])) for row in rows]
