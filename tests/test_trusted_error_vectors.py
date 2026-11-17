"""固定 JWS 拒絕碼、clock 邊界、Replay 不消費與 Node 簽發互通驗收。"""

from contextlib import nullcontext
import json
from pathlib import Path
import shutil
import subprocess

import pytest

from deception.security import TrustedKeyRegistry, TrustedSessionError, TrustedSessionVerifier
from deception.world import ReplayStore


def trusted_error_vectors():
    """讀取固定 raw JSON／Compact JWS 與預期拒絕碼，不在執行時重產 token 或答案。"""
    path = Path(__file__).parent / "fixtures/golden_vectors/trusted_session_errors.json"
    return json.loads(path.read_text(encoding="utf-8"))


class RecordedReplay(ReplayStore):
    """記錄真正程序內 Replay 的呼叫數，分辨前置拒絕與已提交的授權重放。"""

    def __init__(self):
        """建立獨立案例狀態與計數，避免不同固定 JTI 案例互相污染。"""
        super().__init__()
        self.calls = 0

    def consume(self, **kwargs):
        """計數後執行原子消費，保留實際期限及重放語意。"""
        self.calls += 1
        return super().consume(**kwargs)


class FixedKeyRevocation:
    """只為固定向量提供外部撤銷控制值，不取代共享 PostgreSQL 的獨立驗收。"""

    def __init__(self, revoked):
        """保存案例明列的控制值，測後可解除以證明拒絕沒有先消費 JTI。"""
        self.revoked = revoked

    def guard(self, issuer, kid):
        """核對名冊選中的固定身份，回傳可選墓碑但不執行 I/O。"""
        assert (issuer, kid) == ("gateway", "gateway-1")
        return nullcontext(object() if self.revoked else None)


@pytest.mark.parametrize("vector", trusted_error_vectors()["cases"], ids=[row["name"] for row in trusted_error_vectors()["cases"]])
def test_fixed_jws_acceptance_and_error_codes_preserve_replay_boundary(vector):
    """固定錯誤碼與期限邊界一致，前置拒絕不能耗用同 JTI 的合法授權。"""
    fixture = trusted_error_vectors()
    policy = dict(fixture["policy"])
    skew, lifetime = policy.pop("max_clock_skew"), policy.pop("max_lifetime")
    replay = RecordedReplay()
    revocation = FixedKeyRevocation(vector["key_revoked"])
    checked = TrustedSessionVerifier(keys=TrustedKeyRegistry({("gateway", "gateway-1"): bytes.fromhex(fixture["public_key_hex"])}),
        replay_store=replay, key_revocations=revocation, max_clock_skew=skew, max_lifetime=lifetime)
    if vector["preconsumed"]:
        replay.consume(issuer="gateway", audience="mirage", jti="jti-vector", expires_at=1090, now=1000)
        replay.calls = 0
    if vector["expected_error"] is None:
        claims = checked.verify(vector["token"], now=vector["now"], **policy)
        assert claims.session_id == json.loads(vector["payload_json"])["session_id"] and replay.calls == 1
        with pytest.raises(TrustedSessionError) as error:
            checked.verify(vector["token"], now=vector["now"], **policy)
        assert str(error.value) == "trusted_session_replay" and replay.calls == 2
        return
    with pytest.raises(TrustedSessionError) as error:
        checked.verify(vector["token"], now=vector["now"], **policy)
    assert str(error.value) == vector["expected_error"]
    if vector["preconsumed"]:
        assert replay.calls == 1
        return
    assert replay.calls == 0
    revocation.revoked = False
    assert checked.verify(fixture["cases"][0]["token"], now=1000, **policy).jti == "jti-vector"
    assert replay.calls == 1


def test_node_issues_every_fixed_refusal_vector_with_identical_wire():
    """Node 從同一 raw JSON 獨立簽發所有案例，涵蓋重複欄位、Unicode 及格式負例。"""
    node = shutil.which("node")
    if node is None:
        pytest.skip("requires Node.js for independent JWS refusal vector issuer")
    fixture = trusted_error_vectors()
    script = Path(__file__).parent / "fixtures/golden_vectors/sign_trusted_errors.mjs"
    result = subprocess.run([node, str(script)], check=True, capture_output=True, text=True, encoding="utf-8", timeout=10)
    issued = json.loads(result.stdout)
    assert issued["cases"] == len(fixture["cases"]) and issued["public_key_hex"] == fixture["public_key_hex"]
    assert issued["tokens"] == [{"name": row["name"], "token": row["token"]} for row in fixture["cases"]]
