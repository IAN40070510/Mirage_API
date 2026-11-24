"""G5 域外 Anchor 的確定性密碼學負面案例；不等同實體 Restore 驗收。"""

from dataclasses import replace
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from deception.world.restore_anchor import (
    RestoreAnchorError, SignedAnchorCheckpoint, SignedAnchorHead, verify_restore_anchor,
)


def _public(private: Ed25519PrivateKey) -> bytes:
    """從測試期一次性私鑰取出原始 32-byte 公鑰，避免硬編任何金鑰。"""
    return private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)


def _checkpoint(private: Ed25519PrivateKey, *, seq: int, prior: str,
                world: str, first: int, last: int, status: str = "COMMITTED") -> SignedAnchorCheckpoint:
    """在測試中產生完整簽章 checkpoint 與明確事件序號範圍。"""
    candidate = SignedAnchorCheckpoint(
        namespace="mirage-isolated", epoch="epoch-1", sequence=seq,
        previous_digest=prior, world_digest=world, events_digest=f"{seq:064x}",
        first_event=first, last_event=last, publication_id=f"publish-{seq}",
        status=status, signature=bytes(64),
    )
    return replace(candidate, signature=private.sign(candidate.payload()))


class LabAnchorReader:
    """一次性記憶體域外 Reader；不宣稱具正式 Secret／host/DB 隔離。"""

    def __init__(self, head_private: Ed25519PrivateKey,
                 records: list[SignedAnchorCheckpoint]) -> None:
        """固定獨立 Head Authority 私鑰及要回傳的 checkpoint 歷史。"""
        self.head_private = head_private
        self.records = records
        self.bad_nonce = False
        self.bad_signature = False
        self.unavailable = False
        self.head_digest_override = None
        self.advance_after_read = None

    def observe_head(self, namespace: str, epoch: str, challenge: bytes) -> SignedAnchorHead:
        """按本次挑戰簽署測試最高 Head，供 Verifier 實測 nonce 防重播。"""
        if self.unavailable:
            raise ConnectionError("isolated anchor unavailable")
        candidate = SignedAnchorHead(
            namespace=namespace, epoch=epoch, sequence=len(self.records),
            checkpoint_digest=self.head_digest_override or self.records[-1].chain_digest(),
            challenge=bytes(32) if self.bad_nonce else challenge, signature=bytes(64),
        )
        signature = self.head_private.sign(candidate.payload())
        return replace(candidate, signature=(bytes(64) if self.bad_signature else signature))

    def read_checkpoints(self, namespace: str, epoch: str,
                         first: int, last: int) -> list[SignedAnchorCheckpoint]:
        """回傳指定範圍；缺少的節點不能被 Reader 自動補造。"""
        result = self.records[first - 1:last]
        if self.advance_after_read is not None:
            self.records.append(self.advance_after_read)
            self.advance_after_read = None
        return result


class RestoreAnchorContractTests(unittest.TestCase):
    """檢查鏈完整性、域外最新 Head、Restore 回退與 fail-closed 行為。"""

    def setUp(self) -> None:
        """每個案例建立兩組互不相同的即時 Ed25519 密鑰與兩個 checkpoint。"""
        self.publisher = Ed25519PrivateKey.generate()
        self.head_signer = Ed25519PrivateKey.generate()
        first = _checkpoint(self.publisher, seq=1, prior="0" * 64,
                            world="a" * 64, first=1, last=3)
        second = _checkpoint(self.publisher, seq=2, prior=first.chain_digest(),
                             world="b" * 64, first=4, last=7)
        self.reader = LabAnchorReader(self.head_signer, [first, second])

    def compare(self, *, sequence: int = 2, digest: str = "b" * 64):
        """以固定 Namespace/Epoch 與獨立信任根呼叫真簽章驗證器。"""
        return verify_restore_anchor(
            reader=self.reader, namespace="mirage-isolated", epoch="epoch-1",
            restored_sequence=sequence, restored_world_digest=digest,
            publisher_public_key=_public(self.publisher),
            head_public_key=_public(self.head_signer),
        )

    def test_matching_head_still_does_not_authorize_release(self) -> None:
        """世界資料與獨立 Head 完全相符，也不可直接視為 BD-05 自動解禁。"""
        verified = self.compare()
        self.assertEqual(verified.state, "HEAD_MATCHED")
        self.assertEqual(verified.head_sequence, 2)
        self.assertFalse(verified.release_authorized)

    def test_older_restored_world_is_explicitly_quarantined(self) -> None:
        """DB 回到合法舊 Head 1 而域外最新已到 2，回傳落後且不放行。"""
        verified = self.compare(sequence=1, digest="a" * 64)
        self.assertEqual(verified.state, "RESTORE_BEHIND")
        self.assertFalse(verified.release_authorized)

    def test_restored_digest_or_future_sequence_is_rejected(self) -> None:
        """還原資料被替換或聲稱超越域外 Head 時不得得到匹配結果。"""
        with self.assertRaises(RestoreAnchorError):
            self.compare(digest="c" * 64)
        with self.assertRaises(RestoreAnchorError):
            self.compare(sequence=3)

    def test_live_head_nonce_signature_and_pointer_are_verified(self) -> None:
        """拒絕重播 nonce、偽簽章與不指向最後一節的最新 Head。"""
        self.reader.bad_nonce = True
        with self.assertRaises(RestoreAnchorError):
            self.compare()
        self.reader.bad_nonce = False
        self.reader.bad_signature = True
        with self.assertRaises(RestoreAnchorError):
            self.compare()
        self.reader.bad_signature = False
        self.reader.head_digest_override = "a" * 64
        with self.assertRaises(RestoreAnchorError):
            self.compare()

    def test_checkpoint_signature_and_chain_link_are_verified(self) -> None:
        """拒絕簽章遭竄改或簽章有效但 previous_digest 指向錯誤節點。"""
        original = self.reader.records[1]
        self.reader.records[1] = replace(original, signature=bytes(64))
        with self.assertRaises(RestoreAnchorError):
            self.compare()
        self.reader.records[1] = _checkpoint(
            self.publisher, seq=2, prior="f" * 64, world="b" * 64,
            first=4, last=7)
        with self.assertRaises(RestoreAnchorError):
            self.compare()

    def test_missing_or_overlapping_event_coverage_is_rejected(self) -> None:
        """Checkpoint 事件序號缺口／重疊或整個鏈節遺失均拒絕。"""
        original = self.reader.records[1]
        self.reader.records[1] = _checkpoint(
            self.publisher, seq=2, prior=self.reader.records[0].chain_digest(),
            world="b" * 64, first=5, last=7)
        with self.assertRaises(RestoreAnchorError):
            self.compare()
        self.reader.records = [original]
        with self.assertRaises(RestoreAnchorError):
            self.compare()

    def test_prepared_checkpoint_cannot_impersonate_committed(self) -> None:
        """兩域交易尚未確認 COMMIT 的 PREPARED 項不得升格成 committed Head。"""
        self.reader.records[1] = _checkpoint(
            self.publisher, seq=2, prior=self.reader.records[0].chain_digest(),
            world="b" * 64, first=4, last=7, status="PREPARED")
        with self.assertRaises(RestoreAnchorError):
            self.compare()

    def test_anchor_outage_and_untrusted_keys_fail_closed(self) -> None:
        """域外權威無法存取、混用發行／Head 密鑰時拒絕驗收。"""
        self.reader.unavailable = True
        with self.assertRaises(RestoreAnchorError):
            self.compare()
        self.reader.unavailable = False
        with self.assertRaises(RestoreAnchorError):
            verify_restore_anchor(
                reader=self.reader, namespace="mirage-isolated", epoch="epoch-1",
                restored_sequence=2, restored_world_digest="b" * 64,
                publisher_public_key=_public(self.publisher),
                head_public_key=_public(self.publisher),
            )

    def test_head_advance_during_verification_invalidates_result(self) -> None:
        """兩次獨立最新 Head 觀測之間有新 checkpoint，舊 PASS 不可重用。"""
        self.reader.advance_after_read = _checkpoint(
            self.publisher, seq=3, prior=self.reader.records[1].chain_digest(),
            world="c" * 64, first=8, last=9)
        with self.assertRaises(RestoreAnchorError):
            self.compare()


if __name__ == "__main__":
    unittest.main()
