"""已驗證 JWS 的 clock skew 到完整商品判定層之有效時間驗收。"""

import base64
from dataclasses import replace
from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import pytest

from deception.security import TrustedSessionError
from test_request_audit_http import audit_http
from test_postgres_conformance import isolated_test_dsn
from test_trusted_error_vectors import RecordedReplay
from test_trusted_ingress import VECTOR, provider, vector_request
from test_trusted_session import encode


def shifted_request(offset):
    """只改公開測試授權的 iat／nbf／exp 並重新簽章，維持相同原請求與完整 60 秒 signed lifetime。"""
    claims = dict(VECTOR["claims"])
    claims.update(iat=1000+offset, nbf=1000+offset, exp=1060+offset)
    material = encode(VECTOR["header"]) + "." + encode(claims)
    key = Ed25519PrivateKey.from_private_bytes(b"\x01"*32)
    value = material + "." + base64.urlsafe_b64encode(key.sign(material.encode())).decode().rstrip("=")
    request = vector_request()
    return replace(request, headers=tuple((name, text) for name, text in request.headers if name != "x-trusted-session")
                   + (("x-trusted-session", value),))


@pytest.mark.parametrize("offset", [-5, 0, 1, 30])
def test_verified_clock_window_is_usable_without_changing_original_claims(offset):
    """核准 skew 內的授權能供判定層立即使用，原始 iat／nbf／exp 及 signed lifetime 保持不變。"""
    checked = provider()
    result = checked.verify_with_claims(shifted_request(offset))
    receiver_time = datetime.fromtimestamp(1000, tz=timezone.utc)
    assert result.assessment.observed_at <= receiver_time < result.assessment.expires_at
    assert (result.claims.iat, result.claims.nbf, result.claims.exp) == (1000+offset, 1000+offset, 1060+offset)
    assert result.assessment.expires_at.timestamp() == result.claims.exp
    if offset <= 0:
        assert result.assessment.observed_at.timestamp() == result.claims.iat
    with pytest.raises(TrustedSessionError, match="trusted_session_replay"):
        checked.verify_with_claims(shifted_request(offset))


def test_outside_clock_window_still_rejects_before_replay():
    """不能以判定層的時間正規化放行超出部署核准 skew 的授權。"""
    replay = RecordedReplay()
    checked = provider(replay)
    with pytest.raises(TrustedSessionError, match="trusted_session_not_yet_valid"):
        checked.verify_with_claims(shifted_request(31))
    assert replay.calls == 0


def test_clock_normalization_never_extends_signed_expiry():
    """Verifier 的到期 skew 不延長業務截止時間；已過 signed exp 的 assessment 仍明確過期。"""
    checked = provider()
    checked._now = 1089
    result = checked.verify_with_claims(shifted_request(0))
    assert result.assessment.expires_at.timestamp() == result.claims.exp == 1060
    assert result.assessment.expires_at < datetime.fromtimestamp(1089, tz=timezone.utc)


def test_verification_and_effective_time_share_one_receiver_clock_sample():
    """驗章與判定生效不可各取一個跳動時鐘，使用同一次 Receiver 時刻避免邊界不一致。"""
    calls = []

    def clock():
        """若被重取便回下一秒，使測試能辨認同一請求錯用多個驗證時間。"""
        calls.append(1)
        return 999 + len(calls)

    checked = provider()
    checked._now = None
    checked._clock = clock
    result = checked.verify_with_claims(shifted_request(1))
    assert len(calls) == 1 and result.assessment.observed_at.timestamp() == 1000
    assert result.claims.iat == 1001


def test_future_signed_claim_reaches_product_gate_and_keeps_original_audit_context(audit_http):
    """在真實 ASGI／PG 完整流程驗證未來 15 秒但已核准的 JWS，避免只驗 DTO 而漏掉 F 的拒絕。"""
    import psycopg

    client, send, creator, requests, dsn = audit_http
    info = client.get("/demo/info").json()
    path = info["product_path_template"].replace("{id}", info["product_ids"][0])
    response = send("GET", path, creator, issued_offset=15)
    assert response.status_code == 200, response.text
    request_id, original_context, fingerprint = requests[-1]
    with psycopg.connect(dsn) as connection:
        assert connection.execute("SELECT r.outcome,a.state FROM request_observations o "
            "JOIN request_observation_results r USING(observation_id) JOIN response_admissions a USING(admission_id) "
            "WHERE request_id_digest=%s AND trusted_context_digest=%s AND o.request_binding_digest=%s",
            (request_id, original_context, fingerprint)).fetchone() == ("admitted", "SEND_COMPLETED")
        assert connection.execute("SELECT count(*) FROM world_events").fetchone() == (0,)
