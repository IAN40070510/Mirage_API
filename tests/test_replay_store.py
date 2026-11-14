"""Replay Store 一次性消費、期限與清理測試。"""

from deception.world import ReplayConsumeResult, ReplayStore


def test_replay_store_consumes_jti_once_and_cleans_expired_entries():
    """確認同一 JTI 只能成功一次，過期後可由 GC 清理。"""
    store = ReplayStore()
    values = {"issuer": "gateway", "audience": "mirage", "jti": "jti-1", "expires_at": 100}
    assert store.consume(**values, now=1) is ReplayConsumeResult.ACCEPTED
    assert store.consume(**values, now=2) is ReplayConsumeResult.REPLAY
    assert store.consume(**{**values, "jti": "jti-expired"}, now=100) is ReplayConsumeResult.EXPIRED
    assert store.gc(now=100) == 1
