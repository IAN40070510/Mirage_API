"""明確指定來源與已還原隔離 DB 時，核對邏輯備份的世界、收據及撤銷完整性。"""

import json
import os

import pytest

from deception.world import PostgresProjectionRegistry, PostgresWorldStore, ProjectionEvidence, ProjectionRegistryError, WorldScope
from deception.world.models import canonical_state_hash
from deception.security.key_revocation import PostgresTrustedKeyRevocations


def database_manifest(dsn):
    """在唯讀 Repeatable Read 快照比對全部業務表，只回傳筆數與摘要，不輸出原始資料。"""
    import psycopg
    from psycopg import sql, IsolationLevel

    result = {}
    with psycopg.connect(dsn) as connection:
        connection.read_only = True
        connection.isolation_level = IsolationLevel.REPEATABLE_READ
        database, schema = connection.execute("SELECT current_database(),current_schema()").fetchone()
        tables = connection.execute("SELECT tablename FROM pg_tables WHERE schemaname=current_schema() ORDER BY tablename").fetchall()
        for table, in tables:
            rows = [row[0] for row in connection.execute(
                sql.SQL("SELECT row_to_json(record) FROM {} AS record").format(sql.Identifier(table))).fetchall()]
            # 關聯的物理列順序不屬於備份語意；lambda 只建立穩定排序鍵，欄位仍完整參與摘要。
            rows.sort(key=lambda row: json.dumps(row, sort_keys=True, ensure_ascii=False, separators=(",", ":")))
            result[table] = {"rows": len(rows), "sha256": canonical_state_hash({"rows": rows})}
    return database, schema, result


def test_restore_preserves_world_receipts_and_profile_tombstones():
    """還原至不同命名 DB 後，資料摘要完全相同、快照完整且 Profile／key 墓碑保留。"""
    if os.environ.get("MIRAGE_BACKUP_RESTORE_TEST") != "true":
        pytest.skip("requires explicit disposable backup/restore acceptance opt-in")
    source, restored = [os.environ.get(name) for name in ("MIRAGE_BACKUP_SOURCE_TEST_DSN", "MIRAGE_BACKUP_RESTORE_TEST_DSN")]
    if not source or not restored:
        pytest.skip("requires source and already restored disposable databases")
    import psycopg

    source_name, source_schema, before = database_manifest(source)
    restored_name, restored_schema, after = database_manifest(restored)
    assert source_name != restored_name, "test requires a distinct named restore database, not a DSN alias"
    assert source_schema == restored_schema
    assert before == after
    for table in ("world_snapshots", "world_events", "world_commit_receipts", "projection_profile_revocations",
                  "response_audit", "ingress_refusal_audit", "trusted_key_revocations"):
        assert before[table]["rows"] > 0, table
    store, registry = PostgresWorldStore(restored), PostgresProjectionRegistry(restored)
    with psycopg.connect(restored) as connection:
        scopes = connection.execute("SELECT environment_id,deployment_id,session_id,world_generation_id FROM world_snapshots").fetchall()
        revoked = connection.execute("SELECT compatibility_profile_sha256 FROM projection_profile_revocations").fetchall()
        keys = connection.execute("SELECT environment_id,deployment_id,issuer,kid,revision FROM trusted_key_revocations").fetchall()
        for values in scopes:
            scope = WorldScope(**dict(zip(("environment_id", "deployment_id", "session_id", "world_generation_id"), values)))
            # 不傳 now 僅驗證保存資料的完整性；不是延長 lease 或授權已過期世界。
            loaded = store.load_result(scope, authorized_scope=scope)
            assert loaded.status.value == "world_found" and loaded.snapshot.compatibility is not None
        for profile, in revoked:
            evidence_json, = connection.execute("SELECT evidence FROM projection_registry WHERE compatibility_profile_sha256=%s LIMIT 1",
                                                (profile,)).fetchone()
            evidence = ProjectionEvidence.model_validate(evidence_json)
            assert registry.profile_revocation(profile) is not None
            assert registry.authorize(projection_contract_hash=evidence.projection_contract_hash,
                source_spec_sha256=evidence.source_spec_sha256, compatibility_profile_sha256=profile).result.value == "REVOKED"
            with pytest.raises(ProjectionRegistryError, match="bootstrap_profile_not_authorized"):
                registry.ensure_registered_batch([evidence])
        for environment, deployment, issuer, kid, revision in keys:
            manager = PostgresTrustedKeyRevocations(restored, environment_id=environment, deployment_id=deployment)
            assert manager.revocation(issuer, kid).revision == revision
            with manager.guard(issuer, kid) as state:
                assert state is not None and state.revision == revision
