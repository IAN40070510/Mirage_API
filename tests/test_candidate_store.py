"""Candidate retention、scope 隔離與 hash 驗證測試。"""

from deception.world import CandidateStore, CandidateStoreStatus, WorldScope


def scope(session_id: str) -> WorldScope:
    """建立 Candidate retention 使用的完整隔離 scope。"""
    return WorldScope(
        environment_id="candidate",
        deployment_id="pytest",
        session_id=session_id,
        world_generation_id="generation-1",
    )


def test_candidate_requires_same_scope_and_hash():
    """確認 Candidate 不能跨 Session 讀取或以錯誤 hash 使用。"""
    store = CandidateStore()
    owner = scope("session-owner")
    record = store.put(owner, "candidate-1", b"immutable-body", expires_at=100)
    assert store.load(owner, record.candidate_ref, expected_hash=record.candidate_hash, now=99).status is CandidateStoreStatus.FOUND
    assert store.load(scope("session-other"), record.candidate_ref, expected_hash=record.candidate_hash, now=99).status is CandidateStoreStatus.SCOPE_MISMATCH
    assert store.load(owner, record.candidate_ref, expected_hash="0" * 64, now=99).status is CandidateStoreStatus.HASH_MISMATCH


def test_candidate_gc_preserves_protected_admission_reference():
    """確認 GC 不會清除仍被有效准入引用的過期 Candidate。"""
    store = CandidateStore()
    owner = scope("session-owner")
    protected = store.put(owner, "protected", b"protected", expires_at=10)
    removable = store.put(owner, "removable", b"removable", expires_at=10)
    removed = store.gc(now=10, protected_refs=(protected.candidate_ref,))
    assert removed == (removable,)
    assert store.load(owner, protected.candidate_ref, expected_hash=protected.candidate_hash, now=9).status is CandidateStoreStatus.FOUND
