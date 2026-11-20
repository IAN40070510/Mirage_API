"""最終 HTTP bytes 與一次性 Admission 的綁定及傳輸事件控制。"""

import hashlib
import time
from dataclasses import dataclass, field
from typing import Callable
from uuid import uuid4

from deception.api.fingerprint import fingerprint_request
from .admission import AdmissionOperationResult, AdmissionState
from .candidate import CandidateStoreStatus
from .models import ResponseAdmission, WorldScope


def encode_fields(*parts: bytes) -> bytes:
    """以八位元組長度前綴連接 bytes，保留欄位邊界與空欄位。"""
    return b"".join(len(part).to_bytes(8, "big") + part for part in parts)


def response_envelope(status: int, headers, body: bytes) -> bytes:
    """序列化 hash encoding v1 的 status、ordered headers 與精確 body bytes。"""
    encoded_headers = encode_fields(*(encode_fields(name.lower().encode("ascii"), value.encode("latin-1"))
                                     for name, value in headers))
    return encode_fields(b"1", str(status).encode("ascii"), encoded_headers, body)


def response_hashes(status: int, headers, body: bytes) -> tuple[str, str, str]:
    """計算精確最終封套、body 與 ordered semantic headers 的 SHA-256。"""
    envelope = response_envelope(status, headers, body)
    semantic = encode_fields(*(encode_fields(name.lower().encode("ascii"), value.encode("latin-1"))
                               for name, value in headers))
    return (hashlib.sha256(envelope).hexdigest(), hashlib.sha256(body).hexdigest(),
            hashlib.sha256(semantic).hexdigest())


def current_time() -> int:
    """取得與 Admission 期限一致的 Unix 秒。"""
    return int(time.time())


class TransmissionError(RuntimeError):
    """表示傳輸准入拒絕或操作結果無法確認，呼叫端不得自動重試。"""


@dataclass(frozen=True)
class AdmissionTransmission:
    """由可信整合端提供 Store、scope 與准入，供 Renderer 使用同一候選送出一次。"""

    control: object
    candidate_store: object
    scope: WorldScope
    admission: ResponseAdmission
    clock: Callable[[], int] = current_time
    # 每個傳輸物件使用獨立不可猜測 owner，避免同一准入被其他發送者領取。
    owner: str = field(default_factory=lambda: uuid4().hex)

    def prepare(self, candidate, request) -> None:
        """核對持久化准入與候選後才 Claim／Authorize；未知結果直接停止。"""
        now = self.clock()
        expected = response_hashes(candidate.status_code, candidate.headers, candidate.body_bytes)
        admission = ResponseAdmission.model_validate(self.admission.model_dump())
        if (self.control.get_admission(admission.admission_id) != admission
                or admission.world_generation_id != self.scope.world_generation_id
                or admission.request_binding_digest != fingerprint_request(request)
                or expected != (admission.candidate_hash, admission.immutable_body_hash,
                                admission.semantic_headers_hash)):
            raise TransmissionError("transmission_binding_mismatch")
        record = self.candidate_store.load(self.scope, admission.candidate_ref,
                                           expected_hash=admission.candidate_hash, now=now)
        envelope = response_envelope(candidate.status_code, candidate.headers, candidate.body_bytes)
        if (record.status is not CandidateStoreStatus.FOUND or record.record is None
                or record.record.expires_at < admission.transmission_deadline
                or record.record.body != envelope):
            raise TransmissionError("transmission_candidate_unavailable")
        self._require(self.control.claim(admission.admission_id, owner=self.owner, now=now))
        self._require(self.control.authorize_send(admission.admission_id, now=self.clock()))

    def start(self) -> None:
        """在任何 ASGI 訊息前確認已持久化的授權、owner 和期限，不二次撤銷。"""
        self._require(self.control.start_send(self.admission.admission_id, owner=self.owner, now=self.clock()))

    def check_deadline(self) -> None:
        """每次發送前重新檢查 Unix 傳輸期限，相等或超過時停止。"""
        if self.clock() >= self.admission.transmission_deadline:
            raise TransmissionError("transmission_deadline_exceeded")

    def finish(self, outcome: AdmissionState, *, attempted: bool = False) -> None:
        """記錄終態；失去儲存結果時拋錯，不推定傳輸或提交未發生。"""
        self._require(self.control.finish_send(self.admission.admission_id, owner=self.owner,
                                              outcome=outcome, attempted=attempted))

    @staticmethod
    def _require(result) -> None:
        """拒絕所有未明確成功的 Store 操作。"""
        if result is not AdmissionOperationResult.SUCCESS:
            raise TransmissionError("transmission_not_authorized")
