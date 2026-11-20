"""Explicit isolated PostgreSQL fault-injection acceptance for unknown COMMIT.

Inject loss of the acknowledgement at the transaction context boundary, both
before and after the database commit. Never use against shared/staging DBs.
"""

from __future__ import annotations

# ruff: noqa: S101, ANN
import os
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import psycopg
import pytest
from deception.scenarios.models import AttackAssessment
from deception.security.original_assessment_store import (
    OriginalAssessmentStoreError,
    PostgresOriginalAssessmentStore,
)
from psycopg.conninfo import conninfo_to_dict

SCOPE = dict(
    environment_id="isolated-demo",
    deployment_id="isolated-demo",
    source_id="local-demo-detector",
    service_id="synthetic-store",
    site_id="demo-store",
)


class LostCommitAck:
    """Real DB transaction with a controlled lost connection/commit ACK."""

    def __init__(self, connection: psycopg.Connection, *, after_commit: bool) -> None:
        """Store an independent real psycopg connection and the fault point."""
        self.connection = connection
        self.after_commit = after_commit

    def __enter__(self) -> psycopg.Connection:
        """Enter the underlying real PostgreSQL transaction context."""
        return self.connection.__enter__()

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        """Deliberately lose the ACK around COMMIT or ROLLBACK."""
        try:
            if exc_type is None and self.after_commit:
                self.connection.commit()
            else:
                self.connection.rollback()
        finally:
            self.connection.close()
        if exc_type is None:
            raise OSError("synthetic_connection_lost_at_commit_boundary")


class FaultStore(PostgresOriginalAssessmentStore):
    def __init__(self, dsn: str, *, mode: str, after_commit: bool) -> None:
        """Inject an acknowledgement fault into a selected publisher or consumer."""
        super().__init__(dsn, mode=mode, **SCOPE)
        self.after_commit = after_commit
        self.connections = 0

    def _connection(self) -> LostCommitAck:
        """Wrap one real connection, counting attempts to rule out hidden retries."""
        self.connections += 1
        return LostCommitAck(super()._connection(), after_commit=self.after_commit)


def synthetic_assessment(*, request_id: str | None = None) -> AttackAssessment:
    """Generate a scoped synthetic-only malicious assessment for the fault tests."""
    now = datetime.now(UTC)
    return AttackAssessment(
        assessment_id=str(uuid4()),
        request_id=request_id or f"synthetic-{uuid4()}",
        request_fingerprint="b" * 64,
        verdict="malicious",
        attack_types=["sql-injection"],
        observed_at=now,
        expires_at=now + timedelta(seconds=25),
        **SCOPE,
    )


@pytest.fixture(scope="module")
def roles() -> tuple[str, str]:
    """Require dedicated ephemeral PostgreSQL credentials for each service role."""
    if os.environ.get("P2_ISOLATED_ORIGINAL_ASSESSMENT_TEST") != "true":
        pytest.skip("explicit isolated PostgreSQL required")
    names = (
        ("P2_ORIGINAL_TEST_PUBLISHER_DSN", "p2_acl_writer"),
        ("P2_ORIGINAL_TEST_CONSUMER_DSN", "p2_acl_reader"),
    )
    dsns = []
    for env, expected_user in names:
        dsn = os.environ.get(env, "")
        info = conninfo_to_dict(dsn)
        if (
            info.get("dbname") != "p2_acceptance_acl"
            or info.get("host") != "127.0.0.1"
            or info.get("user") != expected_user
            or not info.get("password")
        ):
            pytest.fail(f"unexpected isolated database identity: {env}")
        dsns.append(dsn)
    return dsns[0], dsns[1]


@pytest.mark.parametrize("after_commit", [False, True], ids=["before-commit", "after-commit"])
def test_publisher_lost_ack_fails_closed_without_automatic_retry(
    roles: tuple[str, str], after_commit: bool
) -> None:
    """No publisher acknowledgement means no signable result or hidden retry."""
    writer_dsn, reader_dsn = roles
    original = synthetic_assessment()
    faulty = FaultStore(writer_dsn, mode="publisher", after_commit=after_commit)
    reader = PostgresOriginalAssessmentStore(reader_dsn, mode="consumer", **SCOPE)
    signatures_issued = 0

    # Gateway must not sign if durable publish did not return success.
    with pytest.raises(OriginalAssessmentStoreError, match="publish_unavailable"):
        faulty.publish(original)
        signatures_issued += 1
    assert faulty.connections == 1
    assert signatures_issued == 0

    if after_commit:
        # The row was committed, but Gateway did not receive the ACK.
        # A second publish cannot mint a second signature for same request.
        normal = PostgresOriginalAssessmentStore(writer_dsn, mode="publisher", **SCOPE)
        with pytest.raises(OriginalAssessmentStoreError, match="duplicate"):
            normal.publish(original)
        assert reader(original.assessment_id) == original
        assert reader(original.assessment_id) is None
    else:
        # No durable row; a recovery flow must not fabricate a signature.
        assert reader(original.assessment_id) is None


@pytest.mark.parametrize("after_commit", [False, True], ids=["before-commit", "after-commit"])
def test_consumer_lost_ack_does_not_replay_or_fallback(
    roles: tuple[str, str], after_commit: bool
) -> None:
    """Verify consume returns failure at both commit fault points and does not replay."""
    writer_dsn, reader_dsn = roles
    original = synthetic_assessment()
    writer = PostgresOriginalAssessmentStore(writer_dsn, mode="publisher", **SCOPE)
    writer.publish(original)
    faulty = FaultStore(reader_dsn, mode="consumer", after_commit=after_commit)
    with pytest.raises(OriginalAssessmentStoreError, match="consume_unavailable"):
        faulty(original.assessment_id)
    assert faulty.connections == 1

    fresh_host_reader = PostgresOriginalAssessmentStore(reader_dsn, mode="consumer", **SCOPE)
    if after_commit:
        # The consume committed despite the lost ACK: no second receiver wins.
        assert fresh_host_reader(original.assessment_id) is None
    else:
        # Rollback restored the row, but the failed receiver never served it.
        assert fresh_host_reader(original.assessment_id) == original
        assert fresh_host_reader(original.assessment_id) is None


def test_two_independent_readers_race_after_publisher_ack_loss(
    roles: tuple[str, str],
) -> None:
    """Two independent connections may consume a committed original only once."""
    writer_dsn, reader_dsn = roles
    original = synthetic_assessment()
    faulty = FaultStore(writer_dsn, mode="publisher", after_commit=True)
    with pytest.raises(OriginalAssessmentStoreError, match="publish_unavailable"):
        faulty.publish(original)

    # Model two independent service instances with distinct store objects and
    # independent database connections; this is not a physical cross-host test.
    reader_a = PostgresOriginalAssessmentStore(reader_dsn, mode="consumer", **SCOPE)
    reader_b = PostgresOriginalAssessmentStore(reader_dsn, mode="consumer", **SCOPE)
    with ThreadPoolExecutor(max_workers=2) as pool:
        result = list(pool.map(lambda reader: reader(original.assessment_id), (reader_a, reader_b)))
    assert sum(value == original for value in result) == 1
    assert sum(value is None for value in result) == 1
