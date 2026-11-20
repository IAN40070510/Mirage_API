"""P2 cross-instance original assessment, isolated PostgreSQL opt-in only."""

# ruff: noqa: S101, ANN

from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from deception.scenarios.models import AttackAssessment
from deception.security.original_assessment_store import (
    OriginalAssessmentStoreError,
    PostgresOriginalAssessmentStore,
)

StorePair = tuple[PostgresOriginalAssessmentStore, PostgresOriginalAssessmentStore]

SCOPE = dict(
    environment_id="isolated-demo",
    deployment_id="isolated-demo",
    source_id="local-demo-detector",
    service_id="synthetic-store",
    site_id="demo-store",
)


def assessment(*, request: str | None = None, expires: int = 25) -> AttackAssessment:
    """以當前 UTC 建立有效的真 Pydantic 原判定，無任何客戶資料。"""
    now = datetime.now(UTC)
    return AttackAssessment(
        assessment_id=str(uuid4()),
        request_id=request or f"synthetic-{uuid4()}",
        request_fingerprint="b" * 64,
        verdict="malicious",
        attack_types=["sql-injection"],
        observed_at=now,
        expires_at=now + timedelta(seconds=expires),
        **SCOPE,
    )


@pytest.fixture
def stores() -> StorePair:
    """必須明示 disposable 且 DB 名稱符合隔離標籤，禁止誤用 staging。"""
    if os.getenv("P2_ISOLATED_ORIGINAL_ASSESSMENT_TEST") != "true":
        pytest.skip("requires explicit isolated disposable PostgreSQL authorization")
    dsn = os.getenv("P2_ORIGINAL_ASSESSMENT_TEST_DSN", "")
    from psycopg.conninfo import conninfo_to_dict

    if not dsn or not conninfo_to_dict(dsn).get("dbname", "").startswith("p2_acceptance_"):
        pytest.skip("requires disposable p2_acceptance_ DB; never use staging")
    publisher_dsn = os.environ.get("P2_ORIGINAL_TEST_PUBLISHER_DSN", dsn)
    consumer_dsn = os.environ.get("P2_ORIGINAL_TEST_CONSUMER_DSN", dsn)
    return (
        PostgresOriginalAssessmentStore(publisher_dsn, mode="publisher", **SCOPE),
        PostgresOriginalAssessmentStore(consumer_dsn, mode="consumer", **SCOPE),
    )


def test_publish_then_consume_once(stores: StorePair) -> None:
    """跨連線讀回原判定，消耗兩次只能成功一次，無隱含記憶體 fallback。"""
    publisher, consumer = stores
    original = assessment()
    digest = publisher.publish(original)
    assert len(digest) == 64
    assert consumer(original.assessment_id) == original
    assert consumer(original.assessment_id) is None
    with pytest.raises(OriginalAssessmentStoreError, match="duplicate"):
        publisher.publish(original)


def test_multi_worker_atomic_consume(stores: StorePair) -> None:
    """多條 PostgreSQL 連線競爭同一 ID，最多一條能領取成功。"""
    publisher, consumer = stores
    original = assessment()
    publisher.publish(original)
    with ThreadPoolExecutor(max_workers=8) as executor:
        outcomes = list(executor.map(consumer, [original.assessment_id] * 8))
    assert sum(value is not None for value in outcomes) == 1
    assert any(value == original for value in outcomes)


def test_missing_and_scope_mismatch_are_not_consumed(stores: StorePair) -> None:
    """錯誤 environment 的查詢不得消耗合法判定。"""
    publisher, consumer = stores
    original = assessment()
    publisher.publish(original)
    wrong = PostgresOriginalAssessmentStore(
        consumer._dsn, mode="consumer", **{**SCOPE, "environment_id": "wrong-environment"}
    )
    assert wrong(original.assessment_id) is None
    assert consumer("does-not-exist") is None
    assert consumer(original.assessment_id) == original


def test_duplicate_request_id_fails_closed(stores: StorePair) -> None:
    """同一部署及 request_id 即使換 assessment ID，也不可再取得新簽章機會。"""
    publisher, _ = stores
    request = f"synthetic-{uuid4()}"
    publisher.publish(assessment(request=request))
    with pytest.raises(OriginalAssessmentStoreError, match="duplicate"):
        publisher.publish(assessment(request=request))


def test_expired_never_published_or_consumed(stores: StorePair) -> None:
    """DB 時鐘認定過期，不能使用本機時間自行延長。"""
    publisher, _ = stores
    past = datetime.now(UTC) - timedelta(seconds=15)
    expired = assessment().model_copy(update={
        "observed_at": past, "expires_at": past + timedelta(seconds=3)
    })
    with pytest.raises(OriginalAssessmentStoreError, match="expired"):
        publisher.publish(expired)


def test_mode_separation_fails_closed(stores: StorePair) -> None:
    """角色方向均拒絕；不會自動建表或退化為記憶體。"""
    publisher, consumer = stores
    with pytest.raises(OriginalAssessmentStoreError, match="publish_forbidden"):
        consumer.publish(assessment())
    with pytest.raises(OriginalAssessmentStoreError, match="consume_forbidden"):
        publisher("some-id")


def test_database_unavailable_fails_closed() -> None:
    """連線故障被包成固定錯誤，不能默默進入欺敵。"""
    store = PostgresOriginalAssessmentStore(
        "postgresql://invalid@127.0.0.1:1/not_a_real_db",
        mode="publisher",
        **SCOPE,
    )
    with pytest.raises(OriginalAssessmentStoreError, match="publish_unavailable"):
        store.publish(assessment())
