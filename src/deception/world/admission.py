"""ResponseAdmission 的 Grant、Claim、Cutover 與 Send Authorization 控制。"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from threading import RLock
from uuid import uuid4

from .models import ProjectionEvidence, ResponseAdmission, ResponseSource
from .projection_registry import ProjectionAuthorizationResult, ProjectionRegistryProtocol


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
    claim_revision: int | None = None
    send_authorization_revision: int | None = None


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
        projection_evidence: ProjectionEvidence,
        projection_registry: ProjectionRegistryProtocol,
    ) -> ResponseAdmission | None:
        """驗證投影 Registry 後，在 Generation 尚可發新准入時建立 Grant。"""
        with self._lock:
            if world_generation_id in self._sealed:
                return None
            authorization = projection_registry.authorize(
                projection_contract_hash=projection_contract_hash,
                source_spec_sha256=projection_evidence.source_spec_sha256,
                compatibility_profile_sha256=projection_evidence.compatibility_profile.profile_sha256,
            )
            if (
                authorization.result is not ProjectionAuthorizationResult.AUTHORIZED
                or authorization.authorization is None
                or projection_evidence.projection_contract_hash != projection_contract_hash
            ):
                return None
            admission = ResponseAdmission(
                admission_id=uuid4().hex,
                request_binding_digest=request_binding_digest,
                world_generation_id=world_generation_id,
                grant_revision=self._next_revision(),
                projection_registry_revision=authorization.authorization.registry_revision,
                candidate_ref=candidate_ref,
                candidate_hash=candidate_hash,
                immutable_body_hash=immutable_body_hash,
                semantic_headers_hash=semantic_headers_hash,
                projection_contract_hash=projection_contract_hash,
                authorization_revision=authorization_revision,
                authorization_deadline=authorization_deadline,
                transmission_deadline=transmission_deadline,
                source=source,
                projection_evidence=projection_evidence,
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
            record.claim_revision = self._next_revision()
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
            record.send_authorization_revision = self._next_revision()
            return AdmissionOperationResult.SUCCESS

    def state(self, admission_id: str) -> AdmissionState | None:
        """讀取准入的持久化狀態，找不到時不建立或恢復紀錄。"""
        with self._lock:
            record = self._records.get(admission_id)
            return None if record is None else record.state

    def event_revision(self, admission_id: str, event: str) -> int | None:
        """讀取准入事件在共同控制序列中的 revision，供順序驗證與稽核。"""
        with self._lock:
            record = self._records.get(admission_id)
            if record is None:
                return None
            if event == "grant":
                return record.admission.grant_revision
            if event == "claim":
                return record.claim_revision
            if event == "cutover":
                return self._cutover_revisions.get(record.admission.world_generation_id)
            if event == "send_authorization":
                return record.send_authorization_revision
            raise ValueError(f"unsupported admission event: {event}")

    def active_candidate_refs(self, *, now: int) -> frozenset[str]:
        """列出期限內仍可能被 Claim 或發送使用的 Candidate 引用。"""
        with self._lock:
            active: set[str] = set()
            for record in self._records.values():
                if record.state is AdmissionState.GRANTED:
                    deadline = record.admission.authorization_deadline
                else:
                    deadline = record.admission.transmission_deadline
                if record.state in {
                    AdmissionState.GRANTED,
                    AdmissionState.CLAIMED,
                    AdmissionState.SEND_AUTHORIZED,
                } and now < deadline:
                    active.add(record.admission.candidate_ref)
            return frozenset(active)
