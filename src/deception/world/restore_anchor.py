"""G5 獨立 Restore Anchor 的簽章鏈與還原落後判定；不提供解禁權限。"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import json
import re
import secrets
from typing import Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


_ZERO_DIGEST = "0" * 64
_CHECKPOINT_DOMAIN = b"mirage.restore-anchor.checkpoint.v1\0"
_HEAD_DOMAIN = b"mirage.restore-anchor.head.v1\0"
_MAX_CHECKPOINTS = 10_000


class RestoreAnchorError(ValueError):
    """獨立證據不可驗證時的固定拒絕；呼叫者必須維持 Quarantine。"""


def _digest(value: str) -> bool:
    """僅接受完整小寫 SHA-256，防止跨實作大小寫或編碼別名。"""
    return type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _identifier(value: str) -> bool:
    """限制權威與發布識別符的型別、長度及字元集。"""
    return (type(value) is str and 1 <= len(value) <= 128
            and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]*", value) is not None)


def _canonical(fields: dict[str, object], domain: bytes) -> bytes:
    """以域分離與固定 JSON 編碼產生不能被另一種簽章用途重用的訊息。"""
    return domain + json.dumps(fields, sort_keys=True, separators=(",", ":"),
                               ensure_ascii=True, allow_nan=False).encode("ascii")


@dataclass(frozen=True)
class SignedAnchorCheckpoint:
    """由專屬 Publisher 簽署且在 World DB 備份域外保存的不可變鏈節。"""

    namespace: str
    epoch: str
    sequence: int
    previous_digest: str
    world_digest: str
    events_digest: str
    first_event: int
    last_event: int
    publication_id: str
    status: str
    signature: bytes

    def payload(self) -> bytes:
        """固定簽章的所有涵蓋欄位，拒絕不正規或未定義的 checkpoint 狀態。"""
        if (not _identifier(self.namespace) or not _identifier(self.epoch)
                or not _identifier(self.publication_id)
                or type(self.sequence) is not int or self.sequence < 1
                or not all(_digest(item) for item in (
                    self.previous_digest, self.world_digest, self.events_digest))
                or type(self.first_event) is not int or type(self.last_event) is not int
                or self.first_event < 1 or self.last_event < self.first_event - 1
                or self.status not in {"PREPARED", "COMMITTED"}
                or type(self.signature) is not bytes or len(self.signature) != 64):
            raise RestoreAnchorError("restore_anchor_checkpoint_invalid")
        return _canonical({
            "epoch": self.epoch, "events_digest": self.events_digest,
            "first_event": self.first_event, "last_event": self.last_event,
            "namespace": self.namespace, "previous_digest": self.previous_digest,
            "publication_id": self.publication_id, "sequence": self.sequence,
            "status": self.status, "world_digest": self.world_digest,
        }, _CHECKPOINT_DOMAIN)

    def chain_digest(self) -> str:
        """將簽署內容連同簽章放入下一節的不可變雜湊鏈。"""
        return hashlib.sha256(self.payload() + self.signature).hexdigest()


@dataclass(frozen=True)
class SignedAnchorHead:
    """獨立最新 Head Authority 對本次隨機挑戰的即時簽章回應。"""

    namespace: str
    epoch: str
    sequence: int
    checkpoint_digest: str
    challenge: bytes
    signature: bytes

    def payload(self) -> bytes:
        """將當次 nonce、Head 與 Authority Domain 完整綁定。"""
        if (not _identifier(self.namespace) or not _identifier(self.epoch)
                or type(self.sequence) is not int or self.sequence < 1
                or not _digest(self.checkpoint_digest)
                or type(self.challenge) is not bytes or len(self.challenge) != 32
                or type(self.signature) is not bytes or len(self.signature) != 64):
            raise RestoreAnchorError("restore_anchor_head_invalid")
        return _canonical({
            "challenge": self.challenge.hex(), "checkpoint_digest": self.checkpoint_digest,
            "epoch": self.epoch, "namespace": self.namespace, "sequence": self.sequence,
        }, _HEAD_DOMAIN)


class IndependentAnchorReader(Protocol):
    """必須以獨立 Secret／連線讀域外最新權威，不能從還原的 World DB 提供。"""

    def observe_head(self, namespace: str, epoch: str, challenge: bytes) -> SignedAnchorHead:
        """向獨立權威要求對當次 nonce 簽章的最新且單調 Head。"""
        ...

    def read_checkpoints(self, namespace: str, epoch: str, first: int,
                         last: int) -> list[SignedAnchorCheckpoint]:
        """從域外不可變紀錄讀回含邊界的完整連續 checkpoint 範圍。"""
        ...


@dataclass(frozen=True)
class RestoreAnchorComparison:
    """可信鏈與還原快照的有限比對結果；絕不代表 BD-05 解禁判定。"""

    head_sequence: int
    head_digest: str
    restored_sequence: int
    state: str
    release_authorized: bool = False


def verify_restore_anchor(
    *, reader: IndependentAnchorReader, namespace: str, epoch: str,
    restored_sequence: int, restored_world_digest: str,
    publisher_public_key: bytes, head_public_key: bytes,
) -> RestoreAnchorComparison:
    """驗證獨立即時 Head／鏈／事件序號及還原狀態，不核准新發送。

    外部 Reader 必須由**未隨 World DB 還原**的域外權威提供最新 Head；
    權威只能以當次 nonce 簽署其真正持久化的最高序號。即使檢查通過，
    BD-05 還須驗證完整事件語意、COMMIT/ACK、競態及原子 Quarantine Fence。
    任一讀取／簽章／連續性失敗都丟出錯誤，不能以空清單當作安全恢復。
    """
    if (not _identifier(namespace) or not _identifier(epoch)
            or type(restored_sequence) is not int or restored_sequence < 1
            or not _digest(restored_world_digest)
            or type(publisher_public_key) is not bytes or len(publisher_public_key) != 32
            or type(head_public_key) is not bytes or len(head_public_key) != 32
            or hmac.compare_digest(publisher_public_key, head_public_key)):
        raise RestoreAnchorError("restore_anchor_verification_input_invalid")
    challenge = secrets.token_bytes(32)
    try:
        head = reader.observe_head(namespace, epoch, challenge)
        if (not isinstance(head, SignedAnchorHead) or head.namespace != namespace
                or head.epoch != epoch or not hmac.compare_digest(head.challenge, challenge)):
            raise RestoreAnchorError("restore_anchor_head_scope_or_nonce_mismatch")
        Ed25519PublicKey.from_public_bytes(head_public_key).verify(head.signature, head.payload())
        if head.sequence > _MAX_CHECKPOINTS or restored_sequence > head.sequence:
            raise RestoreAnchorError("restore_anchor_head_range_invalid")
        records = reader.read_checkpoints(namespace, epoch, 1, head.sequence)
        if not isinstance(records, list) or len(records) != head.sequence:
            raise RestoreAnchorError("restore_anchor_checkpoint_range_incomplete")
        previous, last_event = _ZERO_DIGEST, 0
        publications: set[str] = set()
        for sequence, record in enumerate(records, start=1):
            if (not isinstance(record, SignedAnchorCheckpoint)
                    or record.namespace != namespace or record.epoch != epoch
                    or record.sequence != sequence or record.previous_digest != previous
                    or record.first_event != last_event + 1
                    or record.status != "COMMITTED" or record.publication_id in publications):
                raise RestoreAnchorError("restore_anchor_chain_or_coverage_invalid")
            Ed25519PublicKey.from_public_bytes(publisher_public_key).verify(
                record.signature, record.payload())
            publications.add(record.publication_id)
            last_event = record.last_event
            previous = record.chain_digest()
        if not hmac.compare_digest(previous, head.checkpoint_digest):
            raise RestoreAnchorError("restore_anchor_latest_head_mismatch")
        restored = records[restored_sequence - 1]
        if not hmac.compare_digest(restored.world_digest, restored_world_digest):
            raise RestoreAnchorError("restore_anchor_restored_world_mismatch")
        # 此為核對前後的雙重獨立觀測，非 BD-05 原子 Release Fence；真正解禁
        # 仍須把 Head／World state 綁在不可被並行 Send/Purge 競爭繞過的條件轉移。
        final_challenge = secrets.token_bytes(32)
        final_head = reader.observe_head(namespace, epoch, final_challenge)
        if (not isinstance(final_head, SignedAnchorHead)
                or final_head.namespace != namespace or final_head.epoch != epoch
                or not hmac.compare_digest(final_head.challenge, final_challenge)):
            raise RestoreAnchorError("restore_anchor_final_head_scope_or_nonce_mismatch")
        Ed25519PublicKey.from_public_bytes(head_public_key).verify(
            final_head.signature, final_head.payload())
        if (final_head.sequence != head.sequence
                or not hmac.compare_digest(final_head.checkpoint_digest, head.checkpoint_digest)):
            raise RestoreAnchorError("restore_anchor_head_advanced_during_verification")
        return RestoreAnchorComparison(
            head_sequence=head.sequence, head_digest=previous,
            restored_sequence=restored_sequence,
            state="HEAD_MATCHED" if restored_sequence == head.sequence else "RESTORE_BEHIND",
        )
    except RestoreAnchorError:
        raise
    except (InvalidSignature, ValueError, TypeError, AttributeError, OSError, TimeoutError,
            ConnectionError) as exc:
        raise RestoreAnchorError("restore_anchor_unverifiable") from exc
