"""ResponseAdmission 的 Grant、Claim、Cutover 與 Send Authorization 控制。"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from threading import RLock
from uuid import uuid4

from .models import ResponseAdmission, ResponseSource


class AdmissionState(StrEnum):
    """列出可持久化的准入狀態，不把未知結果假裝成 Store 狀態。"""

    GRANTED = "GRANTED"
    CLAIMED = "CLAIMED"
    SEND_AUTHORIZED = "SEND_AUTHORIZED"
    SEND_STARTED = "SEND_STARTED"
    SEND_COMPLETED = "SEND_COMPLETED"
    EXPIRED = "EXPIRED"
    ABANDONED = "ABANDONED"
    SEND_FAILED = "SEND_FAILED"
    SEND_PARTIAL_FAILURE = "SEND_PARTIAL_FAILURE"


class AdmissionOperationResult(StrEnum):
    """列出操作回傳結果，包含不能可靠寫入狀態時的 UNVERIFIABLE。"""

    SUCCESS = "SUCCESS"
    ALREADY_CLAIMED = "ALREADY_CLAIMED"
    EXPIRED = "EXPIRED"
    REJECTED = "REJECTED"
    UNAVAILABLE = "UNAVAILABLE"
    UNVERIFIABLE = "UNVERIFIABLE"


@dataclass
class _Record:
    """保存可變的執行狀態，並將不可變 Grant 內容留在 ResponseAdmission。"""

    admission: ResponseAdmission
    state: AdmissionState
    claim_owner: str | None = None


class AdmissionControl:
    """以單一 Generation 控制序列提供一次性輸出准入。"""

    def __init__(self) -> None:
        """建立空的准入控制器與未封存的 Generation 集合。"""
        self._lock = RLock()
        self._revision = 0
        self._sealed: set[str] = set()
        self._cutover_revisions: dict[str, int] = {}
        self._records: dict[str, _Record] = {}

    def _next_revision(self) -> int:
        """在同一鎖內配置下一個可比較的控制 revision。"""
        self._revision += 1
        return self._revision

    def grant(
        self,
        *,
        world_generation_id: str,
        request_binding_digest: str,
        candidate_ref: str,
        candidate_hash: str,
        immutable_body_hash: str,
        semantic_headers_hash: str,
        projection_contract_hash: str,
        authorization_revision: str,
        authorization_deadline: int,
        transmission_deadline: int,
        source: ResponseSource,
    ) -> ResponseAdmission | None:
        """在 Generation 尚可發新准入時建立不可變 Grant，否則拒絕。"""
        with self._lock:
            if world_generation_id in self._sealed:
                return None
            admission = ResponseAdmission(
                admission_id=uuid4().hex,
                request_binding_digest=request_binding_digest,
                world_generation_id=world_generation_id,
                grant_revision=self._next_revision(),
                candidate_ref=candidate_ref,
                candidate_hash=candidate_hash,
                immutable_body_hash=immutable_body_hash,
                semantic_headers_hash=semantic_headers_hash,
                projection_contract_hash=projection_contract_hash,
                authorization_revision=authorization_revision,
                authorization_deadline=authorization_deadline,
                transmission_deadline=transmission_deadline,
                source=source,
            )
            self._records[admission.admission_id] = _Record(admission, AdmissionState.GRANTED)
            return admission

    def cutover(self, world_generation_id: str) -> int:
        """封存 Generation 並配置同一控制序列中的 Cutover revision。"""
        with self._lock:
            if world_generation_id in self._cutover_revisions:
                return self._cutover_revisions[world_generation_id]
            self._sealed.add(world_generation_id)
            revision = self._next_revision()
            self._cutover_revisions[world_generation_id] = revision
            return revision

    def cutover_revision(self, world_generation_id: str) -> int | None:
        """讀取 Generation 的 Cutover revision，供 Grant 先後順序稽核。"""
        with self._lock:
            return self._cutover_revisions.get(world_generation_id)

    def claim(self, admission_id: str, *, owner: str, now: int) -> AdmissionOperationResult:
        """原子取得一次 Claim；Cutover 後仍允許期限內的既有 Grant。"""
        with self._lock:
            record = self._records.get(admission_id)
            if record is None:
                return AdmissionOperationResult.REJECTED
            if record.state is not AdmissionState.GRANTED:
                return AdmissionOperationResult.ALREADY_CLAIMED
            if now >= record.admission.authorization_deadline:
                record.state = AdmissionState.EXPIRED
                return AdmissionOperationResult.EXPIRED
            record.state = AdmissionState.CLAIMED
            record.claim_owner = owner
            self._next_revision()
            return AdmissionOperationResult.SUCCESS

    def authorize_send(self, admission_id: str, *, now: int, revoked: bool = False) -> AdmissionOperationResult:
        """在 Send Authorization 邊界檢查期限與撤銷，通過後才允許發送。"""
        with self._lock:
            record = self._records.get(admission_id)
            if record is None or record.state is not AdmissionState.CLAIMED:
                return AdmissionOperationResult.REJECTED
            if revoked or now >= record.admission.transmission_deadline:
                record.state = AdmissionState.EXPIRED if not revoked else AdmissionState.ABANDONED
                return AdmissionOperationResult.REJECTED
            record.state = AdmissionState.SEND_AUTHORIZED
            self._next_revision()
            return AdmissionOperationResult.SUCCESS

    def state(self, admission_id: str) -> AdmissionState | None:
        """讀取准入的持久化狀態，找不到時不建立或恢復紀錄。"""
        with self._lock:
            record = self._records.get(admission_id)
            return None if record is None else record.state
