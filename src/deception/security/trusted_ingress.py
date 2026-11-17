"""把已驗證 Trusted Session JWS 轉成既有 pipeline 可消費的可信判定。"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timezone
from dataclasses import dataclass
from typing import TYPE_CHECKING

from deception.api.ingress import NormalizedRequest
from deception.api.fingerprint import fingerprint_request

from .trusted_session import TrustedSessionClaims, TrustedSessionError, TrustedSessionVerifier

if TYPE_CHECKING:
    from deception.scenarios.models import AttackAssessment


@dataclass(frozen=True)
class VerifiedAssessment:
    """同一請求驗證後的 claims 與判定；傳遞給 Runtime 時不再消費 JTI。"""

    claims: TrustedSessionClaims
    assessment: "AttackAssessment"


class TrustedSessionAssessmentProvider:
    """以固定部署設定驗證 HTTP Trusted Session，並建立 malicious 判定模型。"""

    def __init__(
        self,
        verifier: TrustedSessionVerifier,
        *,
        expected_issuer: str,
        expected_audience: str,
        environment_id: str,
        deployment_id: str,
        source_id: str,
        service_id: str,
        site_id: str,
        attack_types: tuple[str, ...] = (),
        header_name: str = "x-trusted-session",
        now: int | None = None,
        clock: Callable[[], int] | None = None,
    ) -> None:
        """建立只接受部署者設定的 JWS assessment provider；不得由請求覆寫身份。"""
        values = {
            "expected_issuer": expected_issuer,
            "expected_audience": expected_audience,
            "environment_id": environment_id,
            "deployment_id": deployment_id,
            "source_id": source_id,
            "service_id": service_id,
            "site_id": site_id,
        }
        if any(not isinstance(value, str) or not value for value in values.values()):
            raise ValueError("trusted assessment settings must be non-empty text")
        if now is not None and clock is not None:
            raise ValueError("provide either now or clock, not both")
        if not isinstance(header_name, str) or not header_name.strip():
            raise ValueError("header_name must be non-empty text")
        if any(not isinstance(value, str) or not value for value in attack_types):
            raise ValueError("attack_types must contain non-empty text")
        self._verifier = verifier
        self._expected_issuer = expected_issuer
        self._expected_audience = expected_audience
        self._environment_id = environment_id
        self._deployment_id = deployment_id
        self._source_id = source_id
        self._service_id = service_id
        self._site_id = site_id
        self._attack_types = list(attack_types)
        self._header_name = header_name.lower()
        self._now = now
        self._clock = clock

    def __call__(self, request: NormalizedRequest) -> "AttackAssessment":
        """驗證請求中的唯一 JWS，核對部署身份後回傳既有 malicious 判定。"""
        return self.verify_with_claims(request).assessment

    def verify_with_claims(self, request: NormalizedRequest) -> VerifiedAssessment:
        """只驗證並消費一次 JTI，回傳原始 claims 及接收端可使用的可信判定。

        驗證與判定使用同一接收端 Unix 時刻；驗證成功後，供 F 使用的 observed_at
        取 signed iat 與該時刻的較早者，使已核准 skew 內的授權可立即使用。
        原始 claims 完整保留，expires_at 維持 signed exp，不延長到期或放寬一般 F。
        """
        from deception.scenarios.models import AttackAssessment

        token = self._header(request)
        current = self._current_time()
        if current is None:
            current = int(datetime.now(timezone.utc).timestamp())
        claims = self._verifier.verify(
            token,
            expected_issuer=self._expected_issuer,
            expected_audience=self._expected_audience,
            request_fingerprint=fingerprint_request(request),
            environment_id=self._environment_id,
            deployment_id=self._deployment_id,
            now=current,
        )
        if (claims.environment_id, claims.deployment_id) != (
            self._environment_id,
            self._deployment_id,
        ):
            raise TrustedSessionError("trusted_session_context_mismatch")
        assessment = AttackAssessment(
            assessment_id=claims.assessment_id,
            source_id=self._source_id,
            request_id=request.request_id,
            request_fingerprint=claims.request_fingerprint,
            environment_id=claims.environment_id,
            deployment_id=claims.deployment_id,
            service_id=self._service_id,
            site_id=self._site_id,
            verdict="malicious",
            attack_types=list(self._attack_types),
            observed_at=datetime.fromtimestamp(min(claims.iat, current), tz=timezone.utc),
            expires_at=datetime.fromtimestamp(claims.exp, tz=timezone.utc),
        )
        return VerifiedAssessment(claims, assessment)

    def _current_time(self) -> int | None:
        """取得可注入的 Unix 時間，讓正式服務與固定向量使用同一時鐘語意。"""
        if self._clock is not None:
            value = self._clock()
            if type(value) is not int:
                raise TrustedSessionError("trusted_session_clock_invalid")
            return value
        return self._now

    def _header(self, request: NormalizedRequest) -> str:
        """從保留原始大小寫與重複欄位的請求中取出唯一 Trusted Session header。"""
        values = [
            value for name, value in request.headers
            if name.lower() == self._header_name
        ]
        if len(values) != 1 or not values[0]:
            raise TrustedSessionError("trusted_session_header_invalid")
        return values[0]
