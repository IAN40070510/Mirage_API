"""可信簽章 key 的跨程序撤銷、輪替、控制排序與未知提交結果驗收。"""

from contextlib import nullcontext
from unittest.mock import patch
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from deception.security import TrustedKeyRegistry, TrustedSessionError, TrustedSessionVerifier
from deception.security.key_revocation import KeyRevocationError, PostgresTrustedKeyRevocations
from deception.world import PostgresReplayStore
from test_postgres_conformance import isolated_test_dsn, ordered_transactions
from test_trusted_session import encode
from test_http_world_isolation import http_worlds


def registry(dsn, **scope):
    """建立固定環境與部署的管理器，個別測試可明確改變其中一個隔離維度。"""
    return PostgresTrustedKeyRevocations(dsn, **{"environment_id": "env", "deployment_id": "deploy", **scope})


def signed(key, *, kid="old", jti=None):
    """用獨立測試私鑰簽發固定時鐘 JWS，明確允許不同 kid 及業務無關的新 JTI。"""
    import base64

    content = encode(dict(alg="Ed25519", kid=kid, protocol_version="1.1", typ="mirage-trusted-session+jwt")) + "." + encode(
        dict(iss="gateway", aud="mirage", iat=1000, nbf=1000, exp=1060, jti=jti or uuid4().hex,
             environment_id="env", deployment_id="deploy", session_id="session", session_epoch=1,
             request_fingerprint="a" * 64, assessment_id="assessment", assessment_digest="b" * 64))
    return content + "." + base64.urlsafe_b64encode(key.sign(content.encode())).decode().rstrip("=")


def verifier(dsn, keys, manager=None):
    """組裝固定公鑰、共享撤銷及共享 Replay；不以建立新 verifier 清除資料庫事實。"""
    return TrustedSessionVerifier(keys=TrustedKeyRegistry({("gateway", kid): key.public_key().public_bytes_raw()
        for kid, key in keys.items()}), replay_store=PostgresReplayStore(dsn),
        key_revocations=manager or registry(dsn))


def verify(checker, token):
    """在固定合法期限內執行完整格式、簽章、撤銷及 Replay 驗證。"""
    return checker.verify(token, expected_issuer="gateway", expected_audience="mirage",
                          environment_id="env", deployment_id="deploy", request_fingerprint="a" * 64, now=1000)


@pytest.mark.parametrize("revision", [True, False, 0, -1, 1.5, "1", 2**63])
def test_invalid_key_revision_rejected_without_database(revision):
    """不合法管理版本在連線前拒絕，避免 bool 或溢位被當作單調序列。"""
    with pytest.raises(KeyRevocationError, match="invalid_key_revocation_revision"):
        registry("postgresql://unused.invalid/db").revoke("gateway", "old", revision=revision)


@pytest.mark.parametrize("issuer,kid", [("", "old"), ("gateway", " "), ("x" * 129, "old"), (None, "old")])
def test_invalid_key_identity_rejected_without_database(issuer, kid):
    """空白、過長及非字串身份不會觸發資料庫或形成另一個控制域。"""
    with pytest.raises(KeyRevocationError, match="identity"):
        registry("postgresql://unused.invalid/db").revocation(issuer, kid)


def test_running_verifiers_rotate_keys_without_reviving_retired_kid(isolated_test_dsn):
    """兩個已建立 verifier 接受重疊 key；撤銷舊 kid 後只新 key 有效，重建或換同名公鑰不復活。"""
    import psycopg

    old, new = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    managers = [registry(isolated_test_dsn) for _ in range(2)]
    checkers = [verifier(isolated_test_dsn, {"old": old, "new": new}, manager) for manager in managers]
    for checker in checkers:
        assert verify(checker, signed(old)).iss == "gateway"
        assert verify(checker, signed(new, kid="new")).iss == "gateway"
    pending_jti = uuid4().hex
    pending = signed(old, jti=pending_jti)
    state = managers[0].revoke("gateway", "old", revision=1)
    assert managers[1].revocation("gateway", "old") == state
    for checker in checkers + [verifier(isolated_test_dsn, {"old": old, "new": new})]:
        with pytest.raises(TrustedSessionError, match="trusted_key_revoked"):
            verify(checker, pending)
        assert verify(checker, signed(new, kid="new")).iss == "gateway"
    with pytest.raises(TrustedSessionError, match="trusted_key_revoked"):
        verify(verifier(isolated_test_dsn, {"old": new}), signed(new))
    with pytest.raises(KeyRevocationError, match="not_monotonic"):
        managers[0].revoke("gateway", "old", revision=1)
    assert managers[0].revoke("gateway", "old", revision=2).revision == 2
    with psycopg.connect(isolated_test_dsn) as connection:
        assert connection.execute("SELECT count(*) FROM replay_entries WHERE jti=%s", (pending_jti,)).fetchone() == (0,)


def test_unknown_key_can_be_preemptively_revoked_without_crossing_deployments(isolated_test_dsn):
    """未設定的 kid 也能先撤銷；其他部署、環境、issuer 或 kid 不受這個墓碑影響。"""
    manager = registry(isolated_test_dsn)
    manager.revoke("gateway", "future", revision=1)
    assert registry(isolated_test_dsn).revocation("gateway", "future") is not None
    assert manager.revocation("gateway", "unrelated") is None
    assert manager.revocation("other-issuer", "future") is None
    for scope in (dict(environment_id="other", deployment_id="deploy"),
                  dict(environment_id="env", deployment_id="other")):
        other = PostgresTrustedKeyRevocations(isolated_test_dsn, **scope)
        assert other.revocation("gateway", "future") is None
    key = Ed25519PrivateKey.generate()
    with pytest.raises(TrustedSessionError, match="trusted_key_revoked"):
        verify(verifier(isolated_test_dsn, {"future": key}), signed(key, kid="future"))


@pytest.mark.parametrize("verify_first", [True, False])
def test_key_revocation_orders_replay_consumption(isolated_test_dsn, verify_first):
    """確認真實控制鎖等待，驗證先行僅消費一次，撤銷先行則完全不消費 JTI。"""
    import psycopg

    reader, manager = registry(isolated_test_dsn), registry(isolated_test_dsn)
    key, jti = Ed25519PrivateKey.generate(), uuid4().hex
    checker = verifier(isolated_test_dsn, {"old": key}, reader)
    token = signed(key, jti=jti)

    def verify_once():
        """完整驗證後回傳標記，僅把預期的撤銷拒絕轉成可比較結果。"""
        try:
            verify(checker, token)
            return "accepted"
        except TrustedSessionError as error:
            assert str(error) == "trusted_key_revoked"
            return "revoked"

    def revoke_once():
        """以獨立連線提交永久墓碑，持鎖直到測試允許 COMMIT。"""
        return manager.revoke("gateway", "old", revision=1)

    operations = (reader, verify_once, manager, revoke_once) if verify_first else (manager, revoke_once, reader, verify_once)
    first, second = ordered_transactions(isolated_test_dsn, *operations)
    assert (first if verify_first else second) == ("accepted" if verify_first else "revoked")
    with psycopg.connect(isolated_test_dsn) as connection:
        assert connection.execute("SELECT count(*) FROM replay_entries WHERE jti=%s", (jti,)).fetchone() == (int(verify_first),)
    with pytest.raises(TrustedSessionError, match="trusted_key_revoked"):
        verify(checker, signed(key))


@pytest.mark.parametrize("mode", ["REPEATABLE_READ", "SERIALIZABLE", "AUTOCOMMIT"])
@pytest.mark.parametrize("write", [False, True])
def test_key_control_rejects_unsafe_transaction_mode(isolated_test_dsn, mode, write):
    """查詢與撤銷皆拒絕舊快照或自動提交，不允許讀不到已提交墓碑或立即釋鎖。"""
    import psycopg
    from psycopg import IsolationLevel

    manager = registry(isolated_test_dsn)
    with psycopg.connect(isolated_test_dsn, autocommit=mode == "AUTOCOMMIT") as connection:
        if mode != "AUTOCOMMIT":
            connection.isolation_level = getattr(IsolationLevel, mode)
            assert connection.execute("SELECT count(*) FROM trusted_key_revocations").fetchone() == (0,)
        committed = manager.revoke("gateway", "old", revision=1)
        with patch.object(manager, "_connection", return_value=nullcontext(connection)):
            with pytest.raises(KeyRevocationError, match="requires_"):
                if write:
                    manager.revoke("gateway", "old", revision=2)
                else:
                    manager.revocation("gateway", "old")
    assert manager.revocation("gateway", "old") == committed


def test_key_revocation_commit_reply_loss_is_read_back(isolated_test_dsn):
    """實際 TCP 丟棄 COMMIT 回覆後只以新連線查回墓碑，不重做或自動提升版本。"""
    import psycopg
    from test_postgres_network import lost_commit_proxy

    with lost_commit_proxy(isolated_test_dsn) as (proxied, dropped):
        with pytest.raises((psycopg.OperationalError, psycopg.InterfaceError)):
            registry(proxied).revoke("gateway", "old", revision=1)
        assert dropped.is_set()
    assert registry(isolated_test_dsn).revocation("gateway", "old").revision == 1


def test_revocation_database_failure_does_not_consume_replay(isolated_test_dsn):
    """共享墓碑無法查詢時向上拒絕，既有合法 JTI 未消費，沒有空名冊降級。"""
    import psycopg

    manager, key = registry(isolated_test_dsn), Ed25519PrivateKey.generate()
    checker = verifier(isolated_test_dsn, {"old": key}, manager)
    jti = uuid4().hex
    token = signed(key, jti=jti)
    with patch.object(manager, "_connection", side_effect=psycopg.OperationalError("injected unavailable")):
        with pytest.raises(psycopg.OperationalError):
            verify(checker, token)
    assert verify(checker, token).jti == jti


@pytest.mark.parametrize("guard_reply_lost", [False, True])
def test_unknown_commit_under_key_guard_never_authorizes(isolated_test_dsn, guard_reply_lost):
    """丟棄 Replay 或 key 控制交易的真實提交回覆都不得回傳可信 claims，已提交 JTI 仍不可重用。"""
    import psycopg
    from test_postgres_network import lost_commit_proxy

    key, jti = Ed25519PrivateKey.generate(), uuid4().hex
    token = signed(key, jti=jti)
    with lost_commit_proxy(isolated_test_dsn) as (proxied, dropped):
        checker = verifier(isolated_test_dsn, {"old": key}, registry(proxied if guard_reply_lost else isolated_test_dsn))
        if not guard_reply_lost:
            checker._replay_store = PostgresReplayStore(proxied)
        with pytest.raises((psycopg.OperationalError, psycopg.InterfaceError)):
            verify(checker, token)
        assert dropped.is_set()
    with psycopg.connect(isolated_test_dsn) as connection:
        assert connection.execute("SELECT count(*) FROM replay_entries WHERE jti=%s", (jti,)).fetchone() == (1,)
    with pytest.raises(TrustedSessionError, match="trusted_session_replay"):
        verify(verifier(isolated_test_dsn, {"old": key}), token)
    assert registry(isolated_test_dsn).revoke("gateway", "old", revision=1).revision == 1


@pytest.mark.parametrize("http_worlds", ["rotation"], indirect=True)
def test_two_live_services_retire_old_key_and_keep_same_world(http_worlds):
    """雙 TLS 業務程序不重啟即可拒絕舊 key，新 key 沿用原世界；拒絕不消費 Replay 或讀取准入。"""
    import psycopg

    lab = http_worlds
    binding = lab.create(0, "key-rotation-creator")
    path = "/store/carts/" + binding.resource_id
    before = lab.snapshot(binding)
    old = lab.signing
    for number in range(2):
        assert lab.send(number, binding, "GET", path).status_code == 200
        lab.signing = lab.next_signing
        assert lab.send(number, binding, "GET", path, kid="next").status_code == 200
        lab.signing = old
    manager = PostgresTrustedKeyRevocations(lab.dsn, environment_id="isolated-demo", deployment_id="isolated-demo")
    manager.revoke("gateway", "test", revision=1)
    counts = lab.counts()
    with psycopg.connect(lab.dsn) as connection:
        replay_before, = connection.execute("SELECT count(*) FROM replay_entries").fetchone()
    for number in range(2):
        response = lab.send(number, binding, "GET", path)
        assert response.status_code == 503 and response.json()["code"] == "pipeline_unavailable"
    assert lab.counts() == counts
    with psycopg.connect(lab.dsn) as connection:
        assert connection.execute("SELECT count(*) FROM replay_entries").fetchone() == (replay_before,)
        assert connection.execute("SELECT stage,reason FROM ingress_refusal_audit").fetchall() == [
            ("trusted_ingress", "unavailable"), ("trusted_ingress", "unavailable")]
    lab.signing = lab.next_signing
    for number in range(2):
        assert lab.send(number, binding, "GET", path, kid="next").status_code == 200
    assert lab.snapshot(binding) == before
