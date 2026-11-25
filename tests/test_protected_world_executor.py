"""MIR-SEC-WORLD-001：以同一 PostgreSQL 交易保護 Read／Commit 來源的測試。"""

import time
import os
import secrets
import json
from copy import deepcopy
from dataclasses import replace
from pathlib import Path
from uuid import UUID, uuid4

import pytest

from deception.world import (CartCreationSource, CommitSource, SnapshotSource,
                             PostgresCandidatePromoter, PostgresCandidateStore,
                             PostgresEventWorldStore, PostgresProtectedAuthorizer,
                             PostgresProtectedWorldExecutor,
                             PostgresProjectionRegistry, ProtectedGrantError, SecurityErrorSource)
from deception.world.session import SessionBinding
from deception.world.models import WorldScope
from deception.world.protected_native_http import PostgresProtectedNativeProjector
from deception.world.transmission import response_envelope, response_hashes
from deception.domains.ecommerce.carts import SyntheticCarts
from deception.domains.ecommerce.inventory import SyntheticInventory
from deception.api.fingerprint import fingerprint_request
from deception.security.operation_binding import OperationBindingError, derive_verified_operation
from test_operation_binding import original_request
from test_postgres_conformance import (digest, isolated_test_dsn, projection_evidence)


def _counter_add(state, command):
    """以固定純函式增加合成庫存計數，不呼叫外部系統或執行 SQL。"""
    updated = deepcopy(state)
    updated["value"] += command["amount"]
    return updated, {"value": updated["value"]}, True


def _counter_reject(state, command):
    """固定測試 Handler 拒絕寫入，保留 World 版本並回傳業務錯誤碼。"""
    return state, {"code": "insufficient_synthetic_inventory"}, False


def _real_login(dsn):
    """從物理 PostgreSQL 連線取得目前測試登入身份，避免 SET ROLE 偽裝。"""
    import psycopg

    with psycopg.connect(dsn) as connection:
        return connection.execute("SELECT session_user").fetchone()[0]


def _trusted_world(dsn):
    """建立專用 Session／原生固定 handler／有效 JWS Receipt 的測試世界。"""
    import psycopg

    now = int(time.time())
    session = uuid4().hex
    binding = SessionBinding(environment_id="world-protected", deployment_id="isolated",
                             session_id=session, session_epoch=1, access_mode="inventory")
    store = PostgresEventWorldStore(dsn, handlers={"counter.add": _counter_add,
                                                   "counter.reject": _counter_reject},
                                    write_modes={"inventory"})
    snapshot = store.resolve(binding, {"value": 0}, now=now, ttl=120)
    receipt_id = uuid4()
    fingerprint = digest("a")
    with psycopg.connect(dsn) as connection:
        jti = uuid4().hex
        connection.execute("INSERT INTO replay_entries VALUES ('gateway','mirage',%s,%s)",
                           (jti, now + 120))
        connection.execute(
            """INSERT INTO ingress_receipts (
                   receipt_id,issuer,audience,jti,key_id,environment_id,deployment_id,
                   session_id,session_epoch,request_fingerprint,assessment_digest,
                   claims_digest,verification_policy_version,token_issued_at,
                   token_not_before,token_expires_at,access_mode)
               VALUES (%s,'gateway','mirage',%s,'kid',%s,%s,%s,1,%s,%s,%s,
                       'trusted-session-v1.1',%s,%s,%s,'inventory')""",
            (receipt_id, jti, binding.environment_id, binding.deployment_id,
             binding.session_id, fingerprint, digest("b"), digest("c"),
             now - 5, now - 5, now + 90),
        )
    executor = PostgresProtectedWorldExecutor(
        dsn, expected_login=_real_login(dsn), world_store=store,
        rejection_templates={"insufficient_synthetic_inventory": "synthetic-inventory-1"},
    )
    return executor, store, binding, snapshot, receipt_id, fingerprint, now


def _candidate(dsn, *, scope, source, receipt_id, fingerprint,
               status=200, body=b'{"ok":true}'):
    """將本交易的受保護來源交由 Candidate Validator 綁定，不採信舊業務列。"""
    evidence = projection_evidence()
    PostgresProjectionRegistry(dsn).ensure_registered_batch((evidence,))
    envelope = response_envelope(status, [("content-type", "application/json")], body)
    hashes = response_hashes(status, [("content-type", "application/json")], body)
    ref = uuid4().hex
    PostgresCandidateStore(dsn).put(scope, ref, envelope, expires_at=int(time.time()) + 80)
    validator = PostgresCandidatePromoter(dsn, expected_login=_real_login(dsn))
    return validator.promote(
        receipt_id=receipt_id, scope=scope, candidate_ref=ref,
        request_fingerprint=fingerprint, envelope_hash=hashes[0],
        immutable_body_hash=hashes[1], semantic_headers_hash=hashes[2],
        evidence=evidence, source=source,
    )


def test_inventory_http_proof_selects_handler_and_rejects_rpc_substitution(isolated_test_dsn):
    """真 PostgreSQL 只准 Receipt 原始 Body 的預留事件，RPC 參數替換不能寫入 World。"""
    import psycopg

    dsn, now = isolated_test_dsn, int(time.time())
    binding = SessionBinding(environment_id="inventory-http", deployment_id="isolated",
                             session_id=uuid4().hex, session_epoch=1, access_mode="inventory")
    store = SyntheticInventory(dsn)
    snapshot = store.resolve(binding, {"inventory": {"sku-1": 4}, "reservations": {}},
                             now=now, ttl=120)
    body = json.dumps(dict(sku="sku-1", quantity=2, expected_version=1,
                           idempotency_key="original-only", commit_attempt_id=str(uuid4()))).encode()
    request = replace(original_request(), body=body)
    proof = derive_verified_operation(request)
    receipt_id, jti = uuid4(), uuid4().hex
    with psycopg.connect(dsn) as connection:
        connection.execute("INSERT INTO replay_entries VALUES ('gateway','mirage',%s,%s)",
                           (jti, now + 120))
        connection.execute(
            """INSERT INTO ingress_receipts (
                   receipt_id,issuer,audience,jti,key_id,environment_id,deployment_id,
                   session_id,session_epoch,request_fingerprint,assessment_digest,
                   claims_digest,verification_policy_version,token_issued_at,
                   token_not_before,token_expires_at,access_mode)
               VALUES (%s,'gateway','mirage',%s,%s,%s,%s,%s,1,%s,%s,%s,
                       'trusted-session-v1.1',%s,%s,%s,'inventory')""",
            (receipt_id, jti, "kid", binding.environment_id, binding.deployment_id,
             binding.session_id, fingerprint_request(request), digest("b"), digest("c"),
             now - 5, now - 5, now + 90),
        )
        connection.execute(
            """INSERT INTO protected_http_operation_bindings (
                   receipt_id,platform,operation_id,method,path_template,
                   request_fingerprint,request_body_sha256,request_path,request_content_type)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
            (receipt_id, proof.platform, proof.operation_id, proof.method, proof.path_template,
             proof.request_fingerprint, proof.request_body_sha256,
             proof.request_path, proof.request_content_type),
        )
    executor = PostgresProtectedWorldExecutor(
        dsn, expected_login=_real_login(dsn), world_store=store,
        rejection_templates={"reservation_not_active": "synthetic-inventory-1"},
    )
    executor.admit_read(receipt_id=receipt_id, binding=binding,
                        request_fingerprint=proof.request_fingerprint, expires_at=now + 30)
    args = dict(receipt_id=receipt_id, binding=binding, authorized_scope=snapshot.scope,
                raw_path=request.raw_path, raw_body=request.body)
    with pytest.raises(OperationBindingError, match="snapshot_mismatch"):
        executor.commit_verified_inventory_http(**{**args, "raw_body": body.replace(b"sku-1", b"sku-2")})
    with pytest.raises(OperationBindingError, match="snapshot_mismatch"):
        executor.commit_verified_inventory_http(**{**args, "raw_path": b"/synthetic/other"})
    with psycopg.connect(dsn) as connection:
        assert connection.execute("SELECT version FROM world_snapshots WHERE world_generation_id=%s",
                                  (snapshot.scope.world_generation_id,)).fetchone()[0] == 1
    # HTTP Caller 只提供原始 bytes/Receipt，不允許提供 Handler、Binding 或 Scope。
    import base64
    from fastapi.testclient import TestClient
    from deception.security.protected_rpc import create_fixed_executor_app

    rpc = create_fixed_executor_app(executor=executor)
    wire = {"receipt_id": str(receipt_id),
            "raw_path_b64": base64.b64encode(request.raw_path).decode("ascii"),
            "raw_body_b64": base64.b64encode(request.body).decode("ascii")}
    with TestClient(rpc, base_url="https://executor.test") as client:
        assert client.post("/internal/v1/execute", json={**wire, "operation": "cancel"}).status_code == 400
        assert client.post("/internal/v1/execute", json={
            **wire, "raw_body_b64": base64.b64encode(b'{"different":true}').decode("ascii"),
        }).status_code == 503
        with TestClient(rpc, base_url="http://executor.test") as plaintext:
            assert plaintext.post("/internal/v1/execute", json=wire).status_code == 503
        accepted = client.post("/internal/v1/execute", json=wire)
        if accepted.status_code != 200:
            # 此處只供 PG CI 呈現底層失敗原因；不得把 Exception 回傳 HTTP Caller。
            executor.execute_verified_http(receipt_id=receipt_id, raw_path=request.raw_path,
                                           raw_body=request.body)
        assert accepted.status_code == 200
        outcome = accepted.json()
        assert outcome["kind"] == "world_mutation" and outcome["operation"] == "reserveSyntheticInventory"
        assert outcome["status"] == "committed" and outcome["state_version"] == 2
        assert client.post("/internal/v1/execute", json=wire).json()["status"] == "already_committed"
    with psycopg.connect(dsn) as connection:
        assert connection.execute("SELECT operation FROM world_operations WHERE commit_attempt_id=%s",
                                  (outcome["commit_attempt_id"],)).fetchone()[0] == "reserve"
        assert connection.execute("SELECT count(*) FROM protected_world_commit_sources WHERE receipt_id=%s",
                                  (receipt_id,)).fetchone()[0] == 1
        assert connection.execute("SELECT count(*) FROM protected_world_read_sources WHERE receipt_id=%s",
                                  (receipt_id,)).fetchone()[0] == 1
        assert connection.execute("SELECT state->'inventory'->>'sku-1' FROM world_snapshots WHERE world_generation_id=%s",
                                  (snapshot.scope.world_generation_id,)).fetchone()[0] == "2"

    # I-01：可信 Executor 的 Commit 只由獨立唯讀 Validator 重新投影精確 200。
    inventory_projector = PostgresProtectedNativeProjector(dsn, expected_login=_real_login(dsn))
    projected = inventory_projector.project_synthetic_success(receipt_id)
    assert inventory_projector.project_verified_receipt(receipt_id) == projected
    assert projected.operation_id == "reserveSyntheticInventory"
    assert projected.status_code == 200
    assert projected.source.operation_result_digest == outcome["result_digest"]
    assert projected.source.committed_state_version == outcome["state_version"]
    assert projected.body_bytes == json.dumps({
        "commit_attempt_id": outcome["commit_attempt_id"],
        "state_version": outcome["state_version"],
        "state_hash": outcome["state_hash"],
        "reservation": json.loads(projected.body_bytes)["reservation"],
    }, sort_keys=True, separators=(",", ":")).encode()
    with pytest.raises(ProtectedGrantError, match="source_missing"):
        PostgresProtectedNativeProjector(dsn, expected_login=_real_login(dsn)).project_synthetic_success(uuid4())

    # I-02：真 reserve 之後的 cancel 200 與重複取消 409，各自由 Receipt 決定。
    reservation_id = json.loads(projected.body_bytes)["reservation"]["reservation_id"]
    cancel_path = "/synthetic/inventory/reservations/" + reservation_id + "/cancel"

    def issue_cancel_attempt(*, version: int, idempotency_key: str) -> tuple[dict, UUID]:
        """以真 PostgreSQL 另一個 Receipt 固定取消操作，從 Executor 取內部結果。"""
        cancel_body = json.dumps({
            "expected_version": version, "idempotency_key": idempotency_key,
            "commit_attempt_id": str(uuid4()),
        }).encode()
        cancel_request = replace(original_request(path=cancel_path), body=cancel_body)
        cancel_proof = derive_verified_operation(cancel_request)
        cancel_receipt, cancel_jti = uuid4(), uuid4().hex
        with psycopg.connect(dsn) as connection:
            connection.execute("INSERT INTO replay_entries VALUES ('gateway','mirage',%s,%s)",
                               (cancel_jti, now + 120))
            connection.execute(
                """INSERT INTO ingress_receipts (
                       receipt_id,issuer,audience,jti,key_id,environment_id,deployment_id,
                       session_id,session_epoch,request_fingerprint,assessment_digest,
                       claims_digest,verification_policy_version,token_issued_at,
                       token_not_before,token_expires_at,access_mode)
                   VALUES (%s,'gateway','mirage',%s,'kid',%s,%s,%s,1,%s,%s,%s,
                           'trusted-session-v1.1',%s,%s,%s,'inventory')""",
                (cancel_receipt, cancel_jti, binding.environment_id, binding.deployment_id,
                 binding.session_id, cancel_proof.request_fingerprint, digest("b"), digest("c"),
                 now - 5, now - 5, now + 90),
            )
            connection.execute(
                """INSERT INTO protected_http_operation_bindings (
                       receipt_id,platform,operation_id,method,path_template,
                       request_fingerprint,request_body_sha256,request_path,request_content_type)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                (cancel_receipt, cancel_proof.platform, cancel_proof.operation_id,
                 cancel_proof.method, cancel_proof.path_template,
                 cancel_proof.request_fingerprint, cancel_proof.request_body_sha256,
                 cancel_proof.request_path, cancel_proof.request_content_type),
            )
        result = executor.execute_verified_http(
            receipt_id=cancel_receipt, raw_path=cancel_request.raw_path, raw_body=cancel_body,
        )
        return result, cancel_receipt

    cancelled, cancel_receipt = issue_cancel_attempt(version=2, idempotency_key="cancel-one")
    assert cancelled["operation"] == "cancelSyntheticInventory"
    assert cancelled["status"] == "committed" and cancelled["state_version"] == 3
    cancel_projection = PostgresProtectedNativeProjector(
        dsn, expected_login=_real_login(dsn)).project_synthetic_success(cancel_receipt)
    assert inventory_projector.project_verified_receipt(cancel_receipt) == cancel_projection
    assert cancel_projection.operation_id == "cancelSyntheticInventory"
    assert cancel_projection.status_code == 200
    cancel_payload = json.loads(cancel_projection.body_bytes)
    assert cancel_payload["reservation"]["reservation_id"] == reservation_id
    assert cancel_payload["reservation"]["status"] == "cancelled"

    repeated, rejected_receipt = issue_cancel_attempt(version=3, idempotency_key="cancel-again")
    # Executor 的拒絕結果不宣稱成功 Commit 版本；真實 World 版本另由 DB 查證。
    assert repeated["status"] == "rejected" and repeated["state_version"] is None
    rejection = PostgresProtectedNativeProjector(
        dsn, expected_login=_real_login(dsn)).project_synthetic_rejection(rejected_receipt)
    assert inventory_projector.project_verified_receipt(rejected_receipt) == rejection
    assert rejection.status_code == 409 and rejection.operation_id == "cancelSyntheticInventory"
    assert rejection.body_bytes == b'{"code":"reservation_not_active"}'
    with psycopg.connect(dsn) as connection:
        assert connection.execute(
            "SELECT version FROM world_snapshots WHERE world_generation_id=%s",
            (snapshot.scope.world_generation_id,),
        ).fetchone()[0] == 3


def test_inventory_http_legacy_receipt_cannot_select_operation(isolated_test_dsn):
    """舊 Receipt 即使持有有效 Inventory Scope，缺原始 Operation Proof 就不能執行。"""
    _, now = isolated_test_dsn, int(time.time())
    binding = SessionBinding(environment_id="inventory-legacy", deployment_id="isolated",
                             session_id=uuid4().hex, session_epoch=1, access_mode="inventory")
    store = SyntheticInventory(isolated_test_dsn)
    snapshot = store.resolve(binding, {"inventory": {"sku-1": 4}, "reservations": {}},
                             now=now, ttl=120)
    executor = PostgresProtectedWorldExecutor(isolated_test_dsn,
                                               expected_login=_real_login(isolated_test_dsn), world_store=store)
    with pytest.raises(ProtectedGrantError, match="operation_proof_missing"):
        executor.commit_verified_inventory_http(
            receipt_id=uuid4(), binding=binding, authorized_scope=snapshot.scope,
            raw_path=b"/synthetic/inventory/reservations", raw_body=b"{}",
        )


def test_fixed_inventory_409_has_independent_validator_and_promotable_source(
        isolated_test_dsn, request):
    """真 PostgreSQL Handler 拒絕才有可 Promotion 的 409；獨立唯讀 Login 重新建構。

    Client HTTP 仍是內部對帳 200，本測試只核對候選與受保護來源。
    """
    import psycopg
    from psycopg import sql
    from psycopg.conninfo import conninfo_to_dict, make_conninfo

    from deception.world.protected_native_http import (
        PostgresProtectedNativeProjector, fixed_synthetic_rejection_bytes,
    )

    dsn, now = isolated_test_dsn, int(time.time())
    binding = SessionBinding(environment_id="inventory-409-proof", deployment_id="isolated",
                             session_id=uuid4().hex, session_epoch=1, access_mode="inventory")
    world = SyntheticInventory(dsn)
    snapshot = world.resolve(binding, {"inventory": {"sku-1": 3}, "reservations": {}},
                             now=now, ttl=120)
    body = json.dumps(dict(sku="unknown-sku", quantity=1, expected_version=1,
                           idempotency_key="reject-once", commit_attempt_id=str(uuid4()))).encode()
    original = replace(original_request(), body=body)
    proof = derive_verified_operation(original)
    receipt, jti = uuid4(), uuid4().hex
    with psycopg.connect(dsn) as connection:
        connection.execute("INSERT INTO replay_entries VALUES ('gateway','mirage',%s,%s)",
                           (jti, now + 120))
        connection.execute(
            """INSERT INTO ingress_receipts (
                   receipt_id,issuer,audience,jti,key_id,environment_id,deployment_id,
                   session_id,session_epoch,request_fingerprint,assessment_digest,
                   claims_digest,verification_policy_version,token_issued_at,
                   token_not_before,token_expires_at,access_mode)
               VALUES (%s,'gateway','mirage',%s,'kid',%s,%s,%s,1,%s,%s,%s,
                       'trusted-session-v1.1',%s,%s,%s,'inventory')""",
            (receipt, jti, binding.environment_id, binding.deployment_id,
             binding.session_id, proof.request_fingerprint, digest("b"), digest("c"),
             now - 5, now - 5, now + 90),
        )
        connection.execute(
            """INSERT INTO protected_http_operation_bindings (
                   receipt_id,platform,operation_id,method,path_template,
                   request_fingerprint,request_body_sha256,request_path,request_content_type)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
            (receipt, proof.platform, proof.operation_id, proof.method, proof.path_template,
             proof.request_fingerprint, proof.request_body_sha256,
             proof.request_path, proof.request_content_type),
        )
    executor = PostgresProtectedWorldExecutor(
        dsn, expected_login=_real_login(dsn), world_store=world,
        rejection_templates={"unknown_synthetic_sku": "synthetic-inventory-1"},
    )
    outcome = executor.execute_verified_http(receipt_id=receipt,
                                             raw_path=original.raw_path, raw_body=body)
    assert outcome["status"] == "rejected" and outcome["kind"] == "world_mutation"
    assert outcome["operation"] == "reserveSyntheticInventory"
    with psycopg.connect(dsn) as connection:
        assert connection.execute(
            "SELECT count(*) FROM protected_world_rejection_sources WHERE receipt_id=%s",
            (receipt,),
        ).fetchone() == (1,)
        assert connection.execute("SELECT count(*) FROM world_events").fetchone() == (0,)
        assert connection.execute("SELECT state->'inventory'->>'sku-1' FROM world_snapshots").fetchone() == ("3",)
    projector_dsn, projector_login = dsn, _real_login(dsn)
    if os.environ.get("MIRAGE_WORLD_ROLE_TEST_ISOLATED") == "true":
        schema = conninfo_to_dict(dsn)["options"].split("search_path=", 1)[1].split(" ", 1)[0]
        projector_login = "mirage_g3b_inventory_validator_" + uuid4().hex[:10]
        password = secrets.token_urlsafe(32)
        with psycopg.connect(dsn, autocommit=True) as admin:
            admin.execute(sql.SQL(
                "CREATE ROLE {} LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE "
                "NOREPLICATION NOBYPASSRLS PASSWORD {}"
            ).format(sql.Identifier(projector_login), sql.Literal(password)))
            admin.execute(sql.SQL("GRANT USAGE ON SCHEMA {} TO {}").format(
                sql.Identifier(schema), sql.Identifier(projector_login)))
            admin.execute(sql.SQL(
                "GRANT SELECT ON protected_world_rejection_sources,protected_world_commit_sources,"
                "protected_medusa_rejection_sources,world_operations,"
                "ingress_receipts,protected_http_operation_bindings,protected_world_read_sources,"
                "read_admissions,session_heads,session_world_bindings,generation_controls,"
                "trusted_key_revocations,world_snapshots,world_commit_receipts TO {}"
            ).format(sql.Identifier(projector_login)))

        def cleanup_validator_role():
            """移除僅在拋棄式測試 Schema 內的獨立 SCRAM Validator Role。"""
            with psycopg.connect(dsn, autocommit=True) as admin:
                admin.execute(sql.SQL("DROP OWNED BY {}").format(sql.Identifier(projector_login)))
                admin.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(projector_login)))

        request.addfinalizer(cleanup_validator_role)
        projector_dsn = make_conninfo(dsn, user=projector_login, password=password)
        with psycopg.connect(projector_dsn) as isolated:
            assert isolated.execute("SELECT session_user,current_user").fetchone() == (
                projector_login, projector_login,
            )
            assert isolated.execute("SELECT has_table_privilege('protected_world_rejection_sources','INSERT')"
                                    ).fetchone() == (False,)
    projector = PostgresProtectedNativeProjector(projector_dsn, expected_login=projector_login)
    projection = projector.project_synthetic_rejection(receipt)
    assert projector.project_verified_receipt(receipt) == projection
    headers, expected_body = fixed_synthetic_rejection_bytes(
        "synthetic-inventory", "unknown_synthetic_sku",
    )
    assert projection.status_code == 409 and projection.headers == headers
    assert projection.body_bytes == expected_body and projection.envelope_hash == response_hashes(
        409, headers, expected_body,
    )[0]
    assert projection.operation_id == "reserveSyntheticInventory"
    assert projection.scope == snapshot.scope and projection.request_fingerprint == proof.request_fingerprint
    assert projection.source == SecurityErrorSource(
        template_id="unknown_synthetic_sku", contract_revision="synthetic-inventory-1",
    )
    assert _candidate(dsn, scope=snapshot.scope, source=projection.source,
                      receipt_id=receipt, fingerprint=proof.request_fingerprint,
                      status=409, body=projection.body_bytes) == 1
    with pytest.raises(ProtectedGrantError, match="candidate_source_unverifiable"):
        _candidate(dsn, scope=snapshot.scope, source=projection.source,
                   receipt_id=receipt, fingerprint=proof.request_fingerprint,
                   status=409, body=b'{"code":"runtime_forgery"}')
    with pytest.raises(ProtectedGrantError, match="source_missing"):
        projector.project_synthetic_rejection(uuid4())


@pytest.mark.parametrize("path,operation,expected_available", [
    ("/synthetic/inventory/sku-1", "getSyntheticInventory", 4),
    ("/synthetic/inventory/品項+特別:版", "getSyntheticInventory", 7),
    ("/synthetic/inventory/%E5%93%81%E9%A0%85+%E7%89%B9%E5%88%A5:%E7%89%88",
     "getSyntheticInventory", 7),
    ("/synthetic/inventory/unknown-sku", "getSyntheticInventory", None),
    ("/synthetic/operations/" + str(uuid4()), "getSyntheticOperation", None),
])
def test_inventory_get_receipt_admits_real_protected_read_without_native_http(
        isolated_test_dsn, path, operation, expected_available):
    """真 PostgreSQL I-03／I-04 經固定 RPC 建讀取來源，拒絕偽造 Bytes／跨 Session。

    只證明 ReadAdmission 存在，並未宣稱原生 200／409 或 Sender 可用。
    """
    import base64
    import psycopg
    from fastapi.testclient import TestClient
    from deception.security.protected_rpc import create_fixed_executor_app
    from urllib.parse import unquote

    dsn, now = isolated_test_dsn, int(time.time())
    binding = SessionBinding(environment_id="inventory-get-http", deployment_id="isolated",
                             session_id=uuid4().hex, session_epoch=1, access_mode="inventory")
    store = SyntheticInventory(dsn)
    snapshot = store.resolve(binding, {"inventory": {"sku-1": 4, "品項+特別:版": 7}, "reservations": {}},
                             now=now, ttl=120)
    decoded_path = unquote(path)
    request = replace(original_request(path=decoded_path, method="GET"),
                      raw_path=path.encode("utf-8"), body=b"")
    proof = derive_verified_operation(request)
    receipt, jti = uuid4(), uuid4().hex
    with psycopg.connect(dsn) as connection:
        connection.execute("INSERT INTO replay_entries VALUES ('gateway','mirage',%s,%s)",
                           (jti, now + 120))
        connection.execute(
            """INSERT INTO ingress_receipts (
                   receipt_id,issuer,audience,jti,key_id,environment_id,deployment_id,
                   session_id,session_epoch,request_fingerprint,assessment_digest,
                   claims_digest,verification_policy_version,token_issued_at,
                   token_not_before,token_expires_at,access_mode)
               VALUES (%s,'gateway','mirage',%s,'kid',%s,%s,%s,1,%s,%s,%s,
                       'trusted-session-v1.1',%s,%s,%s,'inventory')""",
            (receipt, jti, binding.environment_id, binding.deployment_id,
             binding.session_id, proof.request_fingerprint, digest("b"), digest("c"),
             now - 5, now - 5, now + 90),
        )
        connection.execute(
            """INSERT INTO protected_http_operation_bindings (
                   receipt_id,platform,operation_id,method,path_template,
                   request_fingerprint,request_body_sha256,request_path,request_content_type)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
            (receipt, proof.platform, proof.operation_id, proof.method, proof.path_template,
             proof.request_fingerprint, proof.request_body_sha256,
             proof.request_path, proof.request_content_type),
        )
    executor = PostgresProtectedWorldExecutor(dsn, expected_login=_real_login(dsn), world_store=store)
    args = dict(receipt_id=receipt, binding=binding,
                raw_path=request.raw_path, raw_body=b"", expires_at=now + 30)
    with pytest.raises(OperationBindingError, match="snapshot_mismatch"):
        executor.read_verified_inventory_http(**{**args, "raw_body": b"{}"})
    with pytest.raises(OperationBindingError, match="snapshot_mismatch"):
        executor.read_verified_inventory_http(**{**args, "raw_path": request.raw_path + b"x"})
    if request.raw_path != decoded_path.encode("utf-8"):
        # 即使 URL 解出相同 SKU，Receipt 只授權真正收到的 raw-path bytes。
        with pytest.raises(OperationBindingError, match="snapshot_mismatch"):
            executor.read_verified_inventory_http(**{
                **args, "raw_path": decoded_path.encode("utf-8"),
            })
    with pytest.raises(ProtectedGrantError):
        executor.read_verified_inventory_http(**{
            **args, "binding": binding.model_copy(update={"session_id": uuid4().hex}),
        })
    wire = {"receipt_id": str(receipt),
            "raw_path_b64": base64.b64encode(request.raw_path).decode("ascii"),
            "raw_body_b64": ""}
    with TestClient(create_fixed_executor_app(executor=executor), base_url="https://executor.test") as client:
        assert client.post("/internal/v1/execute", json={
            **wire, "raw_body_b64": base64.b64encode(b"{}").decode("ascii"),
        }).status_code == 503
        accepted = client.post("/internal/v1/execute", json=wire)
        if accepted.status_code != 200:
            executor.execute_verified_http(receipt_id=receipt, raw_path=request.raw_path, raw_body=b"")
        assert accepted.status_code == 200  # 內部 RPC；不是客戶端原生 200。
        outcome = accepted.json()
        assert outcome["kind"] == "inventory_read_admitted" and outcome["operation"] == operation
        assert outcome["resource_id"] == decoded_path.rsplit("/", 1)[-1]
        assert outcome["world_generation_id"] == snapshot.scope.world_generation_id
        assert outcome["state_version"] == 1 and outcome["state_hash"] == snapshot.state_hash
        assert "status_code" not in outcome and "body" not in outcome
    with psycopg.connect(dsn) as connection:
        assert connection.execute(
            "SELECT count(*) FROM protected_world_read_sources WHERE receipt_id=%s",
            (receipt,),
        ).fetchone()[0] == 1
        assert connection.execute("SELECT count(*) FROM world_operations").fetchone()[0] == 0
    if operation == "getSyntheticInventory":
        projector = PostgresProtectedNativeProjector(dsn, expected_login=_real_login(dsn))
        if expected_available is not None:
            projected = projector.project_inventory_snapshot(receipt)
            assert projector.project_verified_receipt(receipt) == projected
            assert projected.status_code == 200 and projected.source.kind == "snapshot"
            assert projected.source.state_hash == snapshot.state_hash
            assert json.loads(projected.body_bytes) == {
                "sku": decoded_path.rsplit("/", 1)[-1], "available": expected_available,
                "state_version": 1,
            }
        else:
            # 由獨立 Snapshot 證實 SKU 不存在，現在可以投影固定的業務 409；
            # 外層仍沒有原生 Client HTTP Send 授權。
            projected = projector.project_inventory_snapshot(receipt)
            assert projector.project_verified_receipt(receipt) == projected
            assert projected.status_code == 409 and projected.source.kind == "snapshot"
            assert projected.source.state_hash == snapshot.state_hash
            assert json.loads(projected.body_bytes) == {"code": "unknown_synthetic_sku"}
        with pytest.raises(ProtectedGrantError, match="read_source_missing"):
            projector.project_inventory_snapshot(uuid4())
    else:
        # I-03：當前 World 的確不存在該歷史 UUID4，獨立讀取來源產生固定 409 候選。
        projector = PostgresProtectedNativeProjector(dsn, expected_login=_real_login(dsn))
        projected = projector.project_inventory_operation(receipt)
        assert projector.project_verified_receipt(receipt) == projected
        assert projected.status_code == 409 and projected.source.kind == "snapshot"
        assert projected.source.state_hash == snapshot.state_hash
        assert json.loads(projected.body_bytes) == {"code": "operation_not_found"}
        with pytest.raises(ProtectedGrantError, match="read_source_missing"):
            projector.project_inventory_operation(uuid4())


def test_medusa_400_404_rejections_require_full_http_proof_and_real_world(isolated_test_dsn, request, tmp_path):
    """真 PG：核對 M-03 原生 400/404 來源及一次已知 Variant 受保護 Commit。"""
    import base64
    import psycopg
    from psycopg import sql
    from psycopg.conninfo import conninfo_to_dict, make_conninfo
    from fastapi.testclient import TestClient

    from deception.security.protected_rpc import (ProtectedRpcConfigurationError,
                                                  create_fixed_executor_app)
    from deception.security.protected_services import create_native_validator_service
    from deception.world.protected_native_http import PostgresProtectedNativeProjector

    dsn, now = isolated_test_dsn, int(time.time())
    creator = SessionBinding(environment_id="medusa-http", deployment_id="isolated",
                             session_id=uuid4().hex, session_epoch=1, access_mode="cart")
    store = SyntheticCarts(dsn)
    catalog = {"known": {"sku": "sku-1", "unit_price": 100}}
    inventory = {"sku-1": 7}
    store.resolve(creator, {"catalog": catalog, "inventory": inventory,
                            "reservations": {}}, now=now, ttl=180)
    creator_receipt, creator_jti = uuid4(), uuid4().hex
    with psycopg.connect(dsn) as connection:
        connection.execute("INSERT INTO replay_entries VALUES ('gateway','mirage',%s,%s)",
                           (creator_jti, now + 120))
        connection.execute(
            """INSERT INTO ingress_receipts (
                   receipt_id,issuer,audience,jti,key_id,environment_id,deployment_id,
                   session_id,session_epoch,request_fingerprint,assessment_digest,
                   claims_digest,verification_policy_version,token_issued_at,
                   token_not_before,token_expires_at,access_mode)
               VALUES (%s,'gateway','mirage',%s,'kid',%s,%s,%s,1,%s,%s,%s,
                       'trusted-session-v1.1',%s,%s,%s,'cart')""",
            (creator_receipt, creator_jti, creator.environment_id, creator.deployment_id,
             creator.session_id, digest("a"), digest("b"), digest("c"),
             now - 5, now - 5, now + 90),
        )
    executor = PostgresProtectedWorldExecutor(
        dsn, expected_login=_real_login(dsn), world_store=store,
        cart_initial_state={"catalog": catalog, "inventory": inventory,
                            "native_context": {"region_id": "reg_mirage_usd",
                                               "sales_channel_id": "sc_mirage",
                                               "email": "guest@example.invalid", "metadata": {}}},
        medusa_publishable_key="pk_only_executor",
    )
    created = executor.create_cart(
        receipt_id=creator_receipt, creator=creator, request_fingerprint=digest("a"),
        idempotency_key=uuid4(), commit_attempt_id=uuid4(),
        creation_digest=digest("d"), ttl=180,
    )
    binding = created.binding
    medusa_source = (Path(__file__).resolve().parents[1]
                     / "domains/ecommerce/inputs/sources/medusa/openapi.yaml")
    snapshot = store.inspect_binding(binding, now=now)
    path = "/store/carts/" + binding.resource_id + "/line-items"

    def prepare_request(body: bytes, *, route: str = path, method: str = "POST",
                        bound: SessionBinding | None = None, key: str = "pk_only_executor"):
        """存入只可由獨立 Verifier 寫出的測試 Receipt/Operation 原始證據。"""
        chosen_binding = bound or binding
        incoming = replace(original_request(path=route, method=method), body=body, headers=(
            ("host", "mirage.test"), ("content-type", "application/json"),
            ("x-publishable-api-key", key),
        ))
        proof = derive_verified_operation(incoming)
        receipt, jti = uuid4(), uuid4().hex
        with psycopg.connect(dsn) as connection:
            connection.execute("INSERT INTO replay_entries VALUES ('gateway','mirage',%s,%s)",
                               (jti, now + 120))
            connection.execute(
                """INSERT INTO ingress_receipts (
                       receipt_id,issuer,audience,jti,key_id,environment_id,deployment_id,
                       session_id,session_epoch,request_fingerprint,assessment_digest,
                       claims_digest,verification_policy_version,token_issued_at,
                       token_not_before,token_expires_at,access_mode,resource_id)
                   VALUES (%s,'gateway','mirage',%s,'kid',%s,%s,%s,1,%s,%s,%s,
                           'trusted-session-v1.1',%s,%s,%s,'cart',%s)""",
                (receipt, jti, chosen_binding.environment_id, chosen_binding.deployment_id,
                 chosen_binding.session_id, proof.request_fingerprint, digest("b"), digest("c"),
                 now - 5, now - 5, now + 90, chosen_binding.resource_id),
            )
            connection.execute(
                """INSERT INTO protected_http_operation_bindings (
                       receipt_id,platform,operation_id,method,path_template,
                       request_fingerprint,request_body_sha256,request_path,request_content_type)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                (receipt, proof.platform, proof.operation_id, proof.method, proof.path_template,
                 proof.request_fingerprint, proof.request_body_sha256,
                 proof.request_path, proof.request_content_type),
            )
        wire = {"receipt_id": str(receipt),
                "raw_path_b64": base64.b64encode(incoming.raw_path).decode(),
                "raw_body_b64": base64.b64encode(body).decode(),
                "original_http": {"request_id": incoming.request_id,
                                  "raw_url": incoming.raw_url,
                                  "headers": list(incoming.headers)}}
        return incoming, receipt, proof, wire

    bad, bad_receipt, bad_proof, bad_wire = prepare_request(b'{"quantity":0,"variant_id":"known"}')
    missing, missing_receipt, missing_proof, missing_wire = prepare_request(
        b'{"quantity":1,"variant_id":"missing"}',
    )
    for receipt, proof, status, body, template in (
            (bad_receipt, bad_proof, 400,
             b'{"message":"The requested cart operation is not supported.","type":"invalid_data"}',
             "native-cart-invalid"),
            (missing_receipt, missing_proof, 404,
             b'{"message":"The requested cart operation could not be completed.","type":"not_found"}',
             "native-cart-rejected")):
        with pytest.raises(ProtectedGrantError, match="candidate_source_unverifiable"):
            _candidate(dsn, scope=snapshot.scope,
                       source=SecurityErrorSource(template_id=template,
                                                  contract_revision="medusa-cart-1"),
                       receipt_id=receipt, fingerprint=proof.request_fingerprint,
                       status=status, body=body)
    rpc = create_fixed_executor_app(executor=executor)
    with TestClient(rpc, base_url="https://executor.test") as client:
        assert client.post("/internal/v1/execute", json={
            **bad_wire, "original_http": {**bad_wire["original_http"],
                                          "headers": [("host", "mirage.test"),
                                                      ("content-type", "application/json"),
                                                      ("x-publishable-api-key", "forged")]},
        }).status_code == 503
        assert client.post("/internal/v1/execute", json={
            **bad_wire, "original_http": {**bad_wire["original_http"],
                                          "raw_url": "https://forged.test" + path},
        }).status_code == 503
        assert client.post("/internal/v1/execute", json={
            key: value for key, value in bad_wire.items() if key != "original_http"
        }).status_code == 503
        accepted_400 = client.post("/internal/v1/execute", json=bad_wire)
        if accepted_400.status_code != 200:
            executor.execute_verified_http(receipt_id=bad_receipt,
                                           raw_path=bad.raw_path, raw_body=bad.body,
                                           original_http=bad)
        assert accepted_400.status_code == 200
        assert accepted_400.json()["status_code"] == 400
        accepted_404 = client.post("/internal/v1/execute", json=missing_wire)
        if accepted_404.status_code != 200:
            executor.execute_verified_http(receipt_id=missing_receipt,
                                           raw_path=missing.raw_path, raw_body=missing.body,
                                           original_http=missing)
        assert accepted_404.status_code == 200
        assert accepted_404.json()["status_code"] == 404
        assert client.post("/internal/v1/execute", json=missing_wire).json() == accepted_404.json()
        native_get, get_receipt, get_proof, get_wire = prepare_request(
            b"", route="/store/carts/" + binding.resource_id, method="GET",
        )
        assert get_proof.operation_id == "GetCartsId"
        for forged in (
            {**get_wire, "raw_body_b64": base64.b64encode(b"{}").decode()},
            {**get_wire, "original_http": {**get_wire["original_http"],
                "headers": [("host", "mirage.test"), ("content-type", "application/json"),
                            ("x-publishable-api-key", "attacker")] }},
            {**get_wire, "original_http": {**get_wire["original_http"],
                "raw_url": "https://attacker.test/store/carts/" + binding.resource_id}},
        ):
            assert client.post("/internal/v1/execute", json=forged).status_code == 503
        verified_read = client.post("/internal/v1/execute", json=get_wire)
        assert verified_read.status_code == 200
        read_metadata = verified_read.json()
        assert (read_metadata["kind"], read_metadata["operation"],
                read_metadata["resource_id"], read_metadata["world_generation_id"],
                read_metadata["state_version"], read_metadata["state_hash"]) == (
            "medusa_read_admitted", "GetCartsId", binding.resource_id,
            snapshot.scope.world_generation_id, snapshot.version, snapshot.state_hash,
        )
        get_projector = PostgresProtectedNativeProjector(
            dsn, expected_login=_real_login(dsn), medusa_source=medusa_source,
        )
        projected_get = get_projector.project_medusa_read(get_receipt)
        assert get_projector.project_verified_receipt(get_receipt) == projected_get
        assert (projected_get.status_code, projected_get.operation_id,
                projected_get.request_fingerprint, projected_get.source.kind) == (
            200, "GetCartsId", get_proof.request_fingerprint, "snapshot",
        )
        assert json.loads(projected_get.body_bytes)["cart"]["id"] == binding.resource_id
        assert _candidate(dsn, scope=snapshot.scope, source=projected_get.source,
                          receipt_id=get_receipt, fingerprint=get_proof.request_fingerprint,
                          status=200, body=projected_get.body_bytes) == 1
        # GET ReadAdmission 不可憑同 Receipt 盲目重做：第一次來源不可變，
        # 第二次必須固定 503，而不是多簽第二筆來源。
        assert client.post("/internal/v1/execute", json=get_wire).status_code == 503
        # M-03 已知 Variant：同張真 HTTP Proof／受保護派生 Cart 只可提交一次。
        native_add, add_receipt, add_proof, add_wire = prepare_request(
            b'{"variant_id":"known","quantity":2}',
        )
        assert add_proof.operation_id == "PostCartsIdLineItems"
        assert client.post("/internal/v1/execute", json={
            **add_wire, "raw_body_b64": base64.b64encode(
                b'{"variant_id":"known","quantity":3}',
            ).decode(),
        }).status_code == 503
        valid_add = client.post("/internal/v1/execute", json=add_wire)
        if valid_add.status_code != 200:
            executor.execute_verified_http(
                receipt_id=add_receipt, raw_path=native_add.raw_path,
                raw_body=native_add.body, original_http=native_add,
            )
        assert valid_add.status_code == 200
        add_metadata = valid_add.json()
        assert (add_metadata["kind"], add_metadata["operation"],
                add_metadata["status"], add_metadata["state_version"]) == (
            "medusa_mutation", "PostCartsIdLineItems", "committed", 2,
        )
        assert "body" not in add_metadata and "send_authorized" not in add_metadata
        # Validator 不接收自填 Cart JSON；同次 Commit Source／Native Context／
        # SHA 固定 Medusa 契約共同決定唯一候選，外層仍禁止 Client Send。
        add_projector = PostgresProtectedNativeProjector(
            dsn, expected_login=_real_login(dsn), medusa_source=medusa_source,
        )
        projected_add = add_projector.project_medusa_add_success(add_receipt)
        assert add_projector.project_verified_receipt(add_receipt) == projected_add
        native_cart = json.loads(projected_add.body_bytes)["cart"]
        assert (projected_add.status_code, projected_add.operation_id,
                projected_add.scope, projected_add.source.kind) == (
            200, "PostCartsIdLineItems", snapshot.scope, "committed_operation",
        )
        assert native_cart["id"] == binding.resource_id
        assert native_cart["total"] == 2.0
        assert len(native_cart["items"]) == 1
        assert native_cart["items"][0]["quantity"] == 2
        assert projected_add.source.operation_result_digest == add_metadata["result_digest"]
        assert projected_add.envelope_hash == response_hashes(
            200, projected_add.headers, projected_add.body_bytes,
        )[0]
        assert _candidate(dsn, scope=snapshot.scope, source=projected_add.source,
                          receipt_id=add_receipt, fingerprint=add_proof.request_fingerprint,
                          status=200, body=projected_add.body_bytes) == 1
        with pytest.raises(ProtectedGrantError, match="source_missing"):
            add_projector.project_medusa_add_success(uuid4())
        # 重複 ReadAdmission 的相同 Receipt 直接封閉；不可第二次更新數量。
        assert client.post("/internal/v1/execute", json=add_wire).status_code == 503
        with psycopg.connect(dsn) as connection:
            assert connection.execute(
                "SELECT operation,status FROM world_operations WHERE commit_attempt_id=%s",
                (add_metadata["commit_attempt_id"],),
            ).fetchone() == ("cart.add", "committed")
            assert connection.execute(
                "SELECT count(*) FROM protected_world_commit_sources WHERE receipt_id=%s",
                (add_receipt,),
            ).fetchone()[0] == 1
            assert connection.execute(
                "SELECT state->'cart'->'items' FROM world_snapshots "
                "WHERE world_generation_id=%s", (snapshot.scope.world_generation_id,),
            ).fetchone()[0] != {}
            assert connection.execute(
                "SELECT version FROM world_snapshots WHERE world_generation_id=%s",
                (snapshot.scope.world_generation_id,),
            ).fetchone()[0] == 2
        # M-04 由上一次受保護 Commit 的真 Item ID 更新；跨 Receipt 改 Body
        # 或重送都不得寫第二次，唯一 200 候選只能由獨立 Validator 投影。
        native_item_id = native_cart["items"][0]["id"]
        update_path = path + "/" + native_item_id
        native_update, update_receipt, update_proof, update_wire = prepare_request(
            b'{"quantity":3}', route=update_path,
        )
        assert update_proof.operation_id == "PostCartsIdLineItemsLine_id"
        assert client.post("/internal/v1/execute", json={
            **update_wire, "raw_body_b64": base64.b64encode(b'{"quantity":4}').decode(),
        }).status_code == 503
        updated = client.post("/internal/v1/execute", json=update_wire)
        assert updated.status_code == 200
        update_metadata = updated.json()
        assert (update_metadata["kind"], update_metadata["operation"],
                update_metadata["status"], update_metadata["state_version"]) == (
            "medusa_mutation", "PostCartsIdLineItemsLine_id", "committed", 3,
        )
        projected_update = add_projector.project_medusa_add_success(update_receipt)
        assert add_projector.project_verified_receipt(update_receipt) == projected_update
        updated_cart = json.loads(projected_update.body_bytes)["cart"]
        assert (projected_update.operation_id, projected_update.status_code,
                projected_update.source.kind, updated_cart["total"]) == (
            "PostCartsIdLineItemsLine_id", 200, "committed_operation", 3.0,
        )
        assert updated_cart["items"][0]["id"] == native_item_id
        assert updated_cart["items"][0]["quantity"] == 3
        assert projected_update.source.operation_result_digest == update_metadata["result_digest"]
        assert _candidate(dsn, scope=snapshot.scope, source=projected_update.source,
                          receipt_id=update_receipt,
                          fingerprint=update_proof.request_fingerprint,
                          status=200, body=projected_update.body_bytes) == 1
        assert client.post("/internal/v1/execute", json=update_wire).status_code == 503
        with psycopg.connect(dsn) as connection:
            assert connection.execute(
                "SELECT operation,status FROM world_operations WHERE commit_attempt_id=%s",
                (update_metadata["commit_attempt_id"],),
            ).fetchone() == ("cart.update", "committed")
            assert connection.execute(
                "SELECT version FROM world_snapshots WHERE world_generation_id=%s",
                (snapshot.scope.world_generation_id,),
            ).fetchone()[0] == 3
        # M-05 以真 M-03→M-04 派生品項執行原生 DELETE，只有 Commit 後才有
        # 獨立投影的刪除封套；Body 竄改、重放與缺 Item 一律不可假裝成功。
        native_delete, delete_receipt, delete_proof, delete_wire = prepare_request(
            b"", route=update_path, method="DELETE",
        )
        assert delete_proof.operation_id == "DeleteCartsIdLineItemsLine_id"
        assert client.post("/internal/v1/execute", json={
            **delete_wire, "raw_body_b64": base64.b64encode(b"{}").decode(),
        }).status_code == 503
        deleted = client.post("/internal/v1/execute", json=delete_wire)
        assert deleted.status_code == 200
        delete_metadata = deleted.json()
        assert (delete_metadata["kind"], delete_metadata["operation"],
                delete_metadata["status"], delete_metadata["state_version"]) == (
            "medusa_mutation", "DeleteCartsIdLineItemsLine_id", "committed", 4,
        )
        projected_delete = add_projector.project_medusa_add_success(delete_receipt)
        assert add_projector.project_verified_receipt(delete_receipt) == projected_delete
        deleted_payload = json.loads(projected_delete.body_bytes)
        assert set(deleted_payload) == {"id", "object", "deleted", "parent"}
        assert (deleted_payload["id"], deleted_payload["object"],
                deleted_payload["deleted"], deleted_payload["parent"]["id"],
                deleted_payload["parent"]["items"], deleted_payload["parent"]["total"]) == (
            native_item_id, "line-item", True, binding.resource_id, [], 0.0,
        )
        assert projected_delete.source.operation_result_digest == delete_metadata["result_digest"]
        assert _candidate(dsn, scope=snapshot.scope, source=projected_delete.source,
                          receipt_id=delete_receipt,
                          fingerprint=delete_proof.request_fingerprint,
                          status=200, body=projected_delete.body_bytes) == 1
        assert client.post("/internal/v1/execute", json=delete_wire).status_code == 503
        _, absent_delete_receipt, _, absent_delete_wire = prepare_request(
            b"", route=update_path, method="DELETE",
        )
        assert client.post("/internal/v1/execute", json=absent_delete_wire).status_code == 503
        with pytest.raises(ProtectedGrantError, match="source_missing"):
            add_projector.project_medusa_add_success(absent_delete_receipt)
        with psycopg.connect(dsn) as connection:
            assert connection.execute(
                "SELECT operation,status FROM world_operations WHERE commit_attempt_id=%s",
                (delete_metadata["commit_attempt_id"],),
            ).fetchone() == ("cart.remove", "committed")
            assert connection.execute(
                "SELECT version,state->'cart'->'items' FROM world_snapshots "
                "WHERE world_generation_id=%s", (snapshot.scope.world_generation_id,),
            ).fetchone() == (4, {})
        _, denied_receipt, _, denied_wire = prepare_request(
            b"", route="/store/carts/" + binding.resource_id,
            method="GET", key="incorrect_public_key",
        )
        assert client.post("/internal/v1/execute", json=denied_wire).status_code == 503
        with psycopg.connect(dsn) as connection:
            assert connection.execute(
                "SELECT count(*) FROM protected_world_read_sources WHERE receipt_id=%s",
                (denied_receipt,),
            ).fetchone()[0] == 0
    projector_dsn, projector_login = dsn, _real_login(dsn)
    if os.environ.get("MIRAGE_WORLD_ROLE_TEST_ISOLATED") == "true":
        # 僅限可拋棄的 CI PostgreSQL；正式 DB 禁止測試自行創建 Role。
        schema = conninfo_to_dict(dsn)["options"].split("search_path=", 1)[1].split(" ", 1)[0]
        projector_login = "mirage_g3b_validator_" + uuid4().hex[:12]
        password = secrets.token_urlsafe(32)
        with psycopg.connect(dsn, autocommit=True) as admin:
            admin.execute(sql.SQL(
                "CREATE ROLE {} LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE "
                "NOREPLICATION NOBYPASSRLS PASSWORD {}"
            ).format(sql.Identifier(projector_login), sql.Literal(password)))
            admin.execute(sql.SQL("GRANT USAGE ON SCHEMA {} TO {}").format(
                sql.Identifier(schema), sql.Identifier(projector_login)))
            admin.execute(sql.SQL(
                "GRANT SELECT ON protected_medusa_rejection_sources,ingress_receipts,"
                "protected_world_rejection_sources,world_operations,"
                "protected_http_operation_bindings,protected_world_read_sources,"
                "read_admissions,session_heads,session_world_bindings,"
                "generation_controls,trusted_key_revocations,world_snapshots,"
                "world_commit_receipts,protected_world_commit_sources,synthetic_resources,"
                "protected_cart_creations,guest_cart_creations,native_response_contexts TO {}"
            ).format(sql.Identifier(projector_login)))

        def cleanup_validator_role():
            """僅移除這筆測試產生的讀取專用角色，不影響既存部署身份。"""
            with psycopg.connect(dsn, autocommit=True) as admin:
                admin.execute(sql.SQL("DROP OWNED BY {}").format(sql.Identifier(projector_login)))
                admin.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(projector_login)))

        request.addfinalizer(cleanup_validator_role)
        projector_dsn = make_conninfo(dsn, user=projector_login, password=password)
        with psycopg.connect(projector_dsn) as isolated_validator:
            assert isolated_validator.execute("SELECT session_user,current_user").fetchone() == (
                projector_login, projector_login,
            )
            assert isolated_validator.execute(
                "SELECT has_table_privilege('protected_medusa_rejection_sources','INSERT')"
            ).fetchone() == (False,)
            assert isolated_validator.execute(
                "SELECT has_table_privilege('protected_cart_creations','SELECT'),"
                "has_table_privilege('protected_cart_creations','INSERT'),"
                "has_table_privilege('guest_cart_creations','SELECT'),"
                "has_table_privilege('guest_cart_creations','INSERT'),"
                "has_table_privilege('native_response_contexts','SELECT'),"
                "has_table_privilege('native_response_contexts','INSERT')"
            ).fetchone() == (True, False, True, False, True, False)
        validator_dsn_file = tmp_path / "native-validator.dsn"
        validator_dsn_file.write_text(projector_dsn, encoding="utf-8")
        validator_config = {
            "MIRAGE_G3B_VALIDATOR_DSN_FILE": str(validator_dsn_file),
            "MIRAGE_G3B_VALIDATOR_LOGIN": projector_login,
            "MIRAGE_G3B_WORLD_SCHEMA": schema,
        }
        # 將唯一新增權限暫時撤除，證明 Preflight 因此拒絕啟動，然後恢復
        # 此測試角色所需的純 SELECT。不能把角色權限缺失變成寬鬆投影。
        with psycopg.connect(dsn, autocommit=True) as admin:
            admin.execute(sql.SQL("REVOKE SELECT ON native_response_contexts FROM {}")
                          .format(sql.Identifier(projector_login)))
        with pytest.raises(ProtectedRpcConfigurationError, match="g3b_service_required_acl_missing"):
            create_native_validator_service(validator_config)
        with psycopg.connect(dsn, autocommit=True) as admin:
            admin.execute(sql.SQL("GRANT SELECT ON native_response_contexts TO {}")
                          .format(sql.Identifier(projector_login)))
        assert create_native_validator_service(validator_config).state is not None
    projector = PostgresProtectedNativeProjector(
        projector_dsn, expected_login=projector_login, medusa_source=medusa_source,
    )
    for receipt, proof, status, body, template in (
            (bad_receipt, bad_proof, 400,
             b'{"message":"The requested cart operation is not supported.","type":"invalid_data"}',
             "native-cart-invalid"),
            (missing_receipt, missing_proof, 404,
             b'{"message":"The requested cart operation could not be completed.","type":"not_found"}',
             "native-cart-rejected")):
        projection = projector.project_medusa_rejection(receipt)
        assert projector.project_verified_receipt(receipt) == projection
        assert (projection.status_code, projection.body_bytes, projection.scope,
                projection.request_fingerprint, projection.operation_id) == (
            status, body, snapshot.scope, proof.request_fingerprint, "PostCartsIdLineItems",
        )
        assert projection.source == SecurityErrorSource(
            template_id=template, contract_revision="medusa-cart-1",
        )
        assert _candidate(dsn, scope=snapshot.scope,
                          source=projection.source, receipt_id=projection.receipt_id,
                          fingerprint=projection.request_fingerprint,
                          status=projection.status_code, body=projection.body_bytes) == 1
    with pytest.raises(ProtectedGrantError, match="native_source_missing"):
        projector.project_medusa_rejection(uuid4())
    with psycopg.connect(dsn) as connection:
        assert connection.execute("SELECT status_code,reason_code,read_admission_id IS NOT NULL "
                                  "FROM protected_medusa_rejection_sources ORDER BY status_code").fetchall() == [
            (400, "native_bad_item_body", True), (404, "native_variant_absent", True)]
        assert connection.execute("SELECT count(*) FROM protected_world_read_sources ").fetchone()[0] == 7
        assert connection.execute("SELECT count(*) FROM world_events").fetchone()[0] == 3
    # M-06 不可完成剛由 M-05 刪空的 Cart；空購物車 4xx 尚無核准來源，固定 503。
    _, empty_receipt, empty_proof, empty_wire = prepare_request(
        b"", route="/store/carts/" + binding.resource_id + "/complete", method="POST",
    )
    assert empty_proof.operation_id == "PostCartsIdComplete"
    with TestClient(rpc, base_url="https://executor.test") as client:
        assert client.post("/internal/v1/execute", json=empty_wire).status_code == 503
    with pytest.raises(ProtectedGrantError, match="source_missing"):
        add_projector.project_medusa_add_success(empty_receipt)
    # 只為 M-06／M-07 回填合成品項；M-05 的真刪除版本已獨立核對。
    restored_item = store.mutate_cart(
        binding, action="add", command={"variant_id": "known", "quantity": 1},
        expected_version=4, idempotency_key="native-test-order-item",
        commit_attempt_id=uuid4(), now=now,
    )
    assert restored_item.status == "committed"
    # M-06 在原始 JWS／Receipt 與真 Derived Cart 的 Version 5 之上提交
    # cart.complete；Validator 必須重建官方 type=order 成功封套，不能提供 Send。
    native_complete, complete_receipt, complete_proof, complete_wire = prepare_request(
        b"", route="/store/carts/" + binding.resource_id + "/complete", method="POST",
    )
    with TestClient(rpc, base_url="https://executor.test") as client:
        assert client.post("/internal/v1/execute", json={
            **complete_wire, "raw_body_b64": base64.b64encode(b'{"cart":{}}').decode(),
        }).status_code == 503
        completed = client.post("/internal/v1/execute", json=complete_wire)
        assert completed.status_code == 200
        complete_meta = completed.json()
        assert (complete_meta["kind"], complete_meta["operation"],
                complete_meta["status"], complete_meta["state_version"]) == (
            "medusa_mutation", "PostCartsIdComplete", "committed", 6,
        )
        projected_complete = add_projector.project_medusa_add_success(complete_receipt)
        assert add_projector.project_verified_receipt(complete_receipt) == projected_complete
        complete_body = json.loads(projected_complete.body_bytes)
        assert set(complete_body) == {"type", "order"}
        assert (complete_body["type"], complete_body["order"]["status"],
                complete_body["order"]["payment_status"],
                complete_body["order"]["fulfillment_status"],
                complete_body["order"]["customer_id"]) == (
            "order", "pending", "not_paid", "not_fulfilled", None,
        )
        assert complete_body["order"]["items"]
        assert projected_complete.source.operation_result_digest == complete_meta["result_digest"]
        assert _candidate(dsn, scope=snapshot.scope, source=projected_complete.source,
                          receipt_id=complete_receipt,
                          fingerprint=complete_proof.request_fingerprint,
                          status=200, body=projected_complete.body_bytes) == 1
        assert client.post("/internal/v1/execute", json=complete_wire).status_code == 503
        _, duplicate_receipt, _, duplicate_wire = prepare_request(
            b"", route="/store/carts/" + binding.resource_id + "/complete", method="POST",
        )
        assert client.post("/internal/v1/execute", json=duplicate_wire).status_code == 503
        with pytest.raises(ProtectedGrantError, match="source_missing"):
            add_projector.project_medusa_add_success(duplicate_receipt)
    with psycopg.connect(dsn) as connection:
        assert connection.execute(
            "SELECT operation,status FROM world_operations WHERE commit_attempt_id=%s",
            (complete_meta["commit_attempt_id"],),
        ).fetchone() == ("cart.complete", "committed")
    # M-07 只能讀真正由 M-06 建立的 Order，不得拿假 Order 或 Creator 能力代替。
    order_id = complete_body["order"]["id"]
    order_binding = store.resource_binding(
        order_id, environment_id=binding.environment_id,
        deployment_id=binding.deployment_id, now=now,
    )
    _, order_receipt, order_proof, order_wire = prepare_request(
        b"", route="/store/orders/" + order_id, method="GET", bound=order_binding,
    )
    assert order_proof.operation_id == "GetOrdersId"
    with TestClient(rpc, base_url="https://executor.test") as client:
        order_read = client.post("/internal/v1/execute", json=order_wire)
        assert order_read.status_code == 200
        latest = store.inspect_binding(order_binding, now=now)
        assert (order_read.json()["kind"], order_read.json()["resource_id"],
                order_read.json()["state_version"], order_read.json()["state_hash"]) == (
            "medusa_read_admitted", order_id, latest.version, latest.state_hash,
        )
        native_order = projector.project_medusa_read(order_receipt)
        assert projector.project_verified_receipt(order_receipt) == native_order
        native_order_body = json.loads(native_order.body_bytes)
        assert (native_order.status_code, native_order.operation_id,
                native_order.source.kind, native_order_body["order"]["id"],
                native_order_body["order"]["payment_status"]) == (
            200, "GetOrdersId", "snapshot", order_id, "not_paid",
        )
        assert _candidate(dsn, scope=latest.scope, source=native_order.source,
                          receipt_id=order_receipt, fingerprint=order_proof.request_fingerprint,
                          status=200, body=native_order.body_bytes) == 1
        assert client.post("/internal/v1/execute", json=order_wire).status_code == 503


def test_cart_http_verified_receipt_drives_real_fixed_world_handler(isolated_test_dsn):
    """真 PostgreSQL Cart 派生 Scope 與固定 add Handler 一致，重送／換品項／換資源不能再寫入。"""
    import psycopg

    dsn, now = isolated_test_dsn, int(time.time())
    creator = SessionBinding(environment_id="cart-http", deployment_id="isolated",
                             session_id=uuid4().hex, session_epoch=1, access_mode="cart")
    store = SyntheticCarts(dsn)
    catalog = {"v1": {"sku": "sku-1", "unit_price": 100}}
    inventory = {"sku-1": 6}
    store.resolve(creator, {"catalog": catalog, "inventory": inventory,
                            "reservations": {}}, now=now, ttl=180)
    creator_receipt, creator_jti = uuid4(), uuid4().hex
    with psycopg.connect(dsn) as connection:
        connection.execute("INSERT INTO replay_entries VALUES ('gateway','mirage',%s,%s)",
                           (creator_jti, now + 120))
        connection.execute(
            """INSERT INTO ingress_receipts (
                   receipt_id,issuer,audience,jti,key_id,environment_id,deployment_id,
                   session_id,session_epoch,request_fingerprint,assessment_digest,
                   claims_digest,verification_policy_version,token_issued_at,
                   token_not_before,token_expires_at,access_mode)
               VALUES (%s,'gateway','mirage',%s,'kid',%s,%s,%s,1,%s,%s,%s,
                       'trusted-session-v1.1',%s,%s,%s,'cart')""",
            (creator_receipt, creator_jti, creator.environment_id, creator.deployment_id,
             creator.session_id, digest("a"), digest("b"), digest("c"),
             now - 5, now - 5, now + 90),
        )
    executor = PostgresProtectedWorldExecutor(dsn, expected_login=_real_login(dsn),
                                               world_store=store,
                                               cart_initial_state={"catalog": catalog, "inventory": inventory},
                                               rejection_templates={
                                                   code: "synthetic-carts-1" for code in (
                                                       "cart_item_not_found", "unknown_synthetic_variant",
                                                       "insufficient_synthetic_inventory", "empty_synthetic_cart",
                                                       "cart_not_active", "order_not_cancellable",
                                                   )
                                               })
    created = executor.create_cart(receipt_id=creator_receipt, creator=creator,
                                   request_fingerprint=digest("a"), idempotency_key=uuid4(),
                                   commit_attempt_id=uuid4(), creation_digest=digest("d"), ttl=180)
    binding = created.binding
    snapshot = store.inspect_binding(binding, now=now)
    path = "/synthetic/carts/" + binding.resource_id + "/line-items"
    body = json.dumps(dict(variant_id="v1", quantity=2, expected_version=1,
                           idempotency_key="single-add")).encode()
    request = replace(original_request(path=path), body=body)
    proof = derive_verified_operation(request)
    receipt, jti = uuid4(), uuid4().hex
    with psycopg.connect(dsn) as connection:
        connection.execute("INSERT INTO replay_entries VALUES ('gateway','mirage',%s,%s)",
                           (jti, now + 120))
        connection.execute(
            """INSERT INTO ingress_receipts (
                   receipt_id,issuer,audience,jti,key_id,environment_id,deployment_id,
                   session_id,session_epoch,request_fingerprint,assessment_digest,
                   claims_digest,verification_policy_version,token_issued_at,
                   token_not_before,token_expires_at,access_mode,resource_id)
               VALUES (%s,'gateway','mirage',%s,'kid',%s,%s,%s,1,%s,%s,%s,
                       'trusted-session-v1.1',%s,%s,%s,'cart',%s)""",
            (receipt, jti, binding.environment_id, binding.deployment_id,
             binding.session_id, proof.request_fingerprint, digest("b"), digest("c"),
             now - 5, now - 5, now + 90, binding.resource_id),
        )
        connection.execute(
            """INSERT INTO protected_http_operation_bindings (
                   receipt_id,platform,operation_id,method,path_template,
                   request_fingerprint,request_body_sha256,request_path,request_content_type)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
            (receipt, proof.platform, proof.operation_id, proof.method, proof.path_template,
             proof.request_fingerprint, proof.request_body_sha256,
             proof.request_path, proof.request_content_type),
        )
    executor.admit_read(receipt_id=receipt, binding=binding,
                        request_fingerprint=proof.request_fingerprint, expires_at=now + 30)
    args = dict(receipt_id=receipt, binding=binding, authorized_scope=snapshot.scope,
                raw_path=request.raw_path, raw_body=request.body)
    with pytest.raises(OperationBindingError, match="snapshot_mismatch"):
        executor.commit_verified_cart_http(**{**args, "raw_body": body.replace(b'"v1"', b'"v2"')})
    with pytest.raises(OperationBindingError, match="resource_denied"):
        executor.commit_verified_cart_http(**{**args, "binding": binding.model_copy(
            update={"resource_id": "cart_" + "f" * 32})})
    outcome = executor.commit_verified_cart_http(**args)
    assert outcome.status == "committed" and outcome.committed_state_version == 2
    assert executor.commit_verified_cart_http(**args).status == "already_committed"
    with psycopg.connect(dsn) as connection:
        assert connection.execute("SELECT operation FROM world_operations WHERE commit_attempt_id=%s",
                                  (outcome.commit_attempt_id,)).fetchone()[0] == "cart.add"
        assert connection.execute("SELECT count(*) FROM protected_world_commit_sources WHERE receipt_id=%s",
                                  (receipt,)).fetchone()[0] == 1
        row = connection.execute("SELECT state->'cart'->'items' FROM world_snapshots WHERE world_generation_id=%s",
                                 (snapshot.scope.world_generation_id,)).fetchone()[0]
        assert len(row) == 1 and next(iter(row.values()))["quantity"] == 2

    # C-03：只讀 Validator 經 Commit Source、WorldOperation、ReadAdmission 建立原生 200。
    cart_success = PostgresProtectedNativeProjector(dsn, expected_login=_real_login(dsn)).project_synthetic_success(
        receipt)
    assert cart_success.operation_id == "addGuestCartItem" and cart_success.status_code == 200
    assert cart_success.source.operation_result_digest == outcome.result_digest
    assert cart_success.source.committed_state_hash == outcome.committed_state_hash
    cart_payload = json.loads(cart_success.body_bytes)
    assert cart_payload["cart"]["id"] == binding.resource_id
    assert cart_payload["cart"]["items"][0]["quantity"] == 2
    assert cart_payload["commit_attempt_id"] == str(outcome.commit_attempt_id)

    # C-09：真 Commit 後的歷史操作 GET，必須重建受保護 Commit Source，
    # 不能以同一 World 的普通 ReadAdmission 或 Runtime 自填 status 冒充。
    operation_path = ("/synthetic/carts/" + binding.resource_id
                      + "/operations/" + str(outcome.commit_attempt_id))
    operation_request = replace(original_request(path=operation_path, method="GET"), body=b"")
    operation_proof = derive_verified_operation(operation_request)
    operation_receipt, operation_jti = uuid4(), uuid4().hex
    with psycopg.connect(dsn) as connection:
        connection.execute("INSERT INTO replay_entries VALUES ('gateway','mirage',%s,%s)",
                           (operation_jti, now + 120))
        connection.execute(
            """INSERT INTO ingress_receipts (
                   receipt_id,issuer,audience,jti,key_id,environment_id,deployment_id,
                   session_id,session_epoch,request_fingerprint,assessment_digest,
                   claims_digest,verification_policy_version,token_issued_at,
                   token_not_before,token_expires_at,access_mode,resource_id)
               VALUES (%s,'gateway','mirage',%s,'kid',%s,%s,%s,1,%s,%s,%s,
                       'trusted-session-v1.1',%s,%s,%s,'cart',%s)""",
            (operation_receipt, operation_jti, binding.environment_id,
             binding.deployment_id, binding.session_id,
             operation_proof.request_fingerprint, digest("b"), digest("c"),
             now - 5, now - 5, now + 90, binding.resource_id),
        )
        connection.execute(
            """INSERT INTO protected_http_operation_bindings (
                   receipt_id,platform,operation_id,method,path_template,
                   request_fingerprint,request_body_sha256,request_path,request_content_type)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
            (operation_receipt, operation_proof.platform, operation_proof.operation_id,
             operation_proof.method, operation_proof.path_template,
             operation_proof.request_fingerprint, operation_proof.request_body_sha256,
             operation_proof.request_path, operation_proof.request_content_type),
        )
    read, query = executor.read_verified_cart_http(
        receipt_id=operation_receipt, binding=binding,
        raw_path=operation_request.raw_path, raw_body=b"", expires_at=now + 30,
    )
    assert query.operation == "getCartOperation" and query.attempt_id == outcome.commit_attempt_id
    projector = PostgresProtectedNativeProjector(dsn, expected_login=_real_login(dsn))
    projected = projector.project_cart_read(operation_receipt)
    assert projector.project_verified_receipt(operation_receipt) == projected
    payload = json.loads(projected.body_bytes)
    assert projected.status_code == 200 and projected.operation_id == "getCartOperation"
    assert projected.source.read_admission_id == read.source.read_admission_id
    assert payload["commit_attempt_id"] == str(outcome.commit_attempt_id)
    assert payload["state_version"] == outcome.committed_state_version
    assert payload["state_hash"] == outcome.committed_state_hash
    assert payload["cart"]["id"] == binding.resource_id
    assert payload["cart"]["items"][0]["quantity"] == 2
    # 修改 lookup ID 不能誤配合法操作；不存在的操作不可偽裝成原生 409。
    with pytest.raises(ProtectedGrantError, match="source_missing"):
        projector.project_cart_read(uuid4())

    # C-04／C-05 先更新與刪除真品項，再以新 add 建立可供下單的同世代品項；
    # C-06／C-07／C-08 沿用該受保護派生世代完成 Cart→Order 生命週期。
    def issue_cart_http_proof(path: str, *, body: bytes, resource: SessionBinding,
                              method: str = "POST") -> tuple[UUID, bytes]:
        """在實驗室真 PG 登錄不可變原始 HTTP Proof 與對應 Cart／Order Receipt。"""
        original = replace(original_request(path=path, method=method), body=body)
        operation_proof = derive_verified_operation(original)
        new_receipt, jti = uuid4(), uuid4().hex
        with psycopg.connect(dsn) as connection:
            connection.execute("INSERT INTO replay_entries VALUES ('gateway','mirage',%s,%s)",
                               (jti, now + 120))
            connection.execute(
                """INSERT INTO ingress_receipts (
                       receipt_id,issuer,audience,jti,key_id,environment_id,deployment_id,
                       session_id,session_epoch,request_fingerprint,assessment_digest,
                       claims_digest,verification_policy_version,token_issued_at,
                       token_not_before,token_expires_at,access_mode,resource_id)
                   VALUES (%s,'gateway','mirage',%s,'kid',%s,%s,%s,1,%s,%s,%s,
                           'trusted-session-v1.1',%s,%s,%s,'cart',%s)""",
                (new_receipt, jti, resource.environment_id, resource.deployment_id,
                 resource.session_id, operation_proof.request_fingerprint, digest("b"), digest("c"),
                 now - 5, now - 5, now + 90, resource.resource_id),
            )
            connection.execute(
                """INSERT INTO protected_http_operation_bindings (
                       receipt_id,platform,operation_id,method,path_template,
                       request_fingerprint,request_body_sha256,request_path,request_content_type)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                (new_receipt, operation_proof.platform, operation_proof.operation_id,
                 operation_proof.method, operation_proof.path_template,
                 operation_proof.request_fingerprint, operation_proof.request_body_sha256,
                 operation_proof.request_path, operation_proof.request_content_type),
            )
        return new_receipt, original.raw_path

    def assert_fixed_cart_rejection(*, request_path: str, body: dict,
                                    resource: SessionBinding, expected_operation: str,
                                    expected_code: str, version: int) -> None:
        """在真 PG 由獨立 Receipt 重建固定 409，並核對重送未建立第二份來源或世界事件。"""
        raw_body = json.dumps({**body, "commit_attempt_id": str(uuid4())}).encode()
        rejection_receipt, rejection_path = issue_cart_http_proof(
            request_path, body=raw_body, resource=resource,
        )
        rejected = executor.execute_verified_http(
            receipt_id=rejection_receipt, raw_path=rejection_path, raw_body=raw_body,
        )
        assert rejected["operation"] == expected_operation
        assert rejected["status"] == "rejected" and rejected["state_version"] is None
        projection = projector.project_synthetic_rejection(rejection_receipt)
        assert projector.project_verified_receipt(rejection_receipt) == projection
        assert projection.operation_id == expected_operation and projection.status_code == 409
        assert projection.body_bytes == json.dumps({"code": expected_code}, sort_keys=True,
                                                  separators=(",", ":")).encode()
        assert executor.execute_verified_http(
            receipt_id=rejection_receipt, raw_path=rejection_path, raw_body=raw_body,
        )["status"] == "rejected"
        with psycopg.connect(dsn) as connection:
            assert connection.execute(
                "SELECT version FROM world_snapshots WHERE world_generation_id=%s",
                (snapshot.scope.world_generation_id,),
            ).fetchone()[0] == version
            assert connection.execute(
                "SELECT count(*) FROM protected_world_rejection_sources WHERE receipt_id=%s",
                (rejection_receipt,),
            ).fetchone()[0] == 1

    # CAS：另一個有效原始 Receipt 若仍聲稱舊版本，必須停在不可驗證狀態。
    # 不能把版本衝突偽裝成 Handler 的 409，也不能發出 Commit/Rejection Source。
    from deception.world.store import WorldStoreError

    stale_attempt = uuid4()
    stale_body = json.dumps({"variant_id": "v1", "quantity": 1,
                             "expected_version": 1, "idempotency_key": "stale-version",
                             "commit_attempt_id": str(stale_attempt)}).encode()
    stale_receipt, stale_path = issue_cart_http_proof(path, body=stale_body, resource=binding)
    for _ in range(2):
        with pytest.raises(WorldStoreError, match="version_conflict"):
            executor.execute_verified_http(
                receipt_id=stale_receipt, raw_path=stale_path, raw_body=stale_body,
            )
        with pytest.raises(ProtectedGrantError, match="rejection_source_missing"):
            projector.project_synthetic_rejection(stale_receipt)
    with psycopg.connect(dsn) as connection:
        assert connection.execute(
            "SELECT version FROM world_snapshots WHERE world_generation_id=%s",
            (snapshot.scope.world_generation_id,),
        ).fetchone()[0] == 2
        assert connection.execute(
            "SELECT count(*) FROM world_operations WHERE commit_attempt_id=%s",
            (stale_attempt,),
        ).fetchone()[0] == 0
        assert connection.execute(
            "SELECT count(*) FROM protected_world_commit_sources WHERE receipt_id=%s",
            (stale_receipt,),
        ).fetchone()[0] == 0

    # C-03：只准由已提交的真正 Handler 拒絕核發 409；未知變體與庫存不足
    # 都不能改動已存在的 Cart 品項或假稱一次成功 Commit。
    for variant, quantity, code, idempotency in (
            ("absent", 1, "unknown_synthetic_variant", "unknown-variant"),
            ("v1", 99, "insufficient_synthetic_inventory", "overstocked")):
        assert_fixed_cart_rejection(
            request_path=path,
            body={"variant_id": variant, "quantity": quantity,
                  "expected_version": 2, "idempotency_key": idempotency},
            resource=binding, expected_operation="addGuestCartItem",
            expected_code=code, version=2,
        )

    item_id = cart_payload["cart"]["items"][0]["id"]
    item_path = path + "/" + item_id
    update_body = json.dumps({"quantity": 3, "expected_version": 2,
                              "idempotency_key": "update-real-item",
                              "commit_attempt_id": str(uuid4())}).encode()
    update_receipt, update_path = issue_cart_http_proof(
        item_path, body=update_body, resource=binding,
    )
    with pytest.raises(OperationBindingError, match="snapshot_mismatch"):
        executor.execute_verified_http(
            receipt_id=update_receipt, raw_path=update_path, raw_body=update_body.replace(b'"quantity": 3', b'"quantity": 5'),
        )
    with pytest.raises(OperationBindingError, match="snapshot_mismatch"):
        executor.execute_verified_http(
            receipt_id=update_receipt, raw_path=update_path.replace(item_id.encode(), b"item_" + b"e" * 32),
            raw_body=update_body,
        )
    update_result = executor.execute_verified_http(
        receipt_id=update_receipt, raw_path=update_path, raw_body=update_body,
    )
    assert update_result["operation"] == "updateGuestCartItem"
    assert update_result["status"] == "committed" and update_result["state_version"] == 3
    assert executor.execute_verified_http(
        receipt_id=update_receipt, raw_path=update_path, raw_body=update_body,
    )["status"] == "already_committed"
    updated = projector.project_synthetic_success(update_receipt)
    assert projector.project_verified_receipt(update_receipt) == updated
    updated_payload = json.loads(updated.body_bytes)
    assert updated.operation_id == "updateGuestCartItem" and updated.status_code == 200
    assert updated_payload["cart"]["items"][0]["id"] == item_id
    assert updated_payload["cart"]["items"][0]["quantity"] == 3
    assert updated_payload["cart"]["total"] == 300

    # 不存在的 item_id 是真正 Handler 409，不能靠 RPC 選擇錯誤來源；
    # 失敗不推進 World 版本，同時驗證原始路徑對應的不可變 Proof。
    absent_item_path = path + "/item_" + "f" * 32
    absent_body = json.dumps({"quantity": 1, "expected_version": 3,
                              "idempotency_key": "update-absent-item",
                              "commit_attempt_id": str(uuid4())}).encode()
    absent_receipt, absent_path = issue_cart_http_proof(
        absent_item_path, body=absent_body, resource=binding,
    )
    absent_result = executor.execute_verified_http(
        receipt_id=absent_receipt, raw_path=absent_path, raw_body=absent_body,
    )
    assert absent_result["operation"] == "updateGuestCartItem"
    assert absent_result["status"] == "rejected" and absent_result["state_version"] is None
    absent_projection = projector.project_synthetic_rejection(absent_receipt)
    assert projector.project_verified_receipt(absent_receipt) == absent_projection
    assert absent_projection.operation_id == "updateGuestCartItem"
    assert absent_projection.status_code == 409
    assert absent_projection.body_bytes == b'{"code":"cart_item_not_found"}'
    with psycopg.connect(dsn) as connection:
        assert connection.execute(
            "SELECT version FROM world_snapshots WHERE world_generation_id=%s",
            (snapshot.scope.world_generation_id,),
        ).fetchone()[0] == 3

    remove_body = json.dumps({"expected_version": 3, "idempotency_key": "remove-real-item",
                              "commit_attempt_id": str(uuid4())}).encode()
    remove_receipt, remove_path = issue_cart_http_proof(
        item_path, body=remove_body, resource=binding, method="DELETE",
    )
    with pytest.raises(OperationBindingError, match="snapshot_mismatch"):
        executor.execute_verified_http(
            receipt_id=remove_receipt, raw_path=remove_path, raw_body=remove_body + b" ",
        )
    remove_result = executor.execute_verified_http(
        receipt_id=remove_receipt, raw_path=remove_path, raw_body=remove_body,
    )
    assert remove_result["operation"] == "removeGuestCartItem"
    assert remove_result["status"] == "committed" and remove_result["state_version"] == 4
    assert executor.execute_verified_http(
        receipt_id=remove_receipt, raw_path=remove_path, raw_body=remove_body,
    )["status"] == "already_committed"
    removed = projector.project_synthetic_success(remove_receipt)
    assert projector.project_verified_receipt(remove_receipt) == removed
    removed_payload = json.loads(removed.body_bytes)
    assert removed.operation_id == "removeGuestCartItem" and removed.status_code == 200
    assert removed_payload["cart"]["items"] == [] and removed_payload["cart"]["total"] == 0

    removed_again_body = json.dumps({"expected_version": 4,
                                     "idempotency_key": "remove-already-removed",
                                     "commit_attempt_id": str(uuid4())}).encode()
    removed_again_receipt, removed_again_path = issue_cart_http_proof(
        item_path, body=removed_again_body, resource=binding, method="DELETE",
    )
    removed_again_result = executor.execute_verified_http(
        receipt_id=removed_again_receipt, raw_path=removed_again_path,
        raw_body=removed_again_body,
    )
    assert removed_again_result["status"] == "rejected"
    assert removed_again_result["state_version"] is None
    removed_again_projection = projector.project_synthetic_rejection(removed_again_receipt)
    assert projector.project_verified_receipt(removed_again_receipt) == removed_again_projection
    assert removed_again_projection.operation_id == "removeGuestCartItem"
    assert removed_again_projection.status_code == 409
    assert removed_again_projection.body_bytes == b'{"code":"cart_item_not_found"}'
    with psycopg.connect(dsn) as connection:
        assert connection.execute(
            "SELECT version FROM world_snapshots WHERE world_generation_id=%s",
            (snapshot.scope.world_generation_id,),
        ).fetchone()[0] == 4

    # C-06：Cart 品項確實已空，empty_synthetic_cart 只能來自真 Handler。
    assert_fixed_cart_rejection(
        request_path="/synthetic/carts/" + binding.resource_id + "/complete",
        body={"expected_version": 4, "idempotency_key": "complete-empty-cart"},
        resource=binding, expected_operation="completeGuestCart",
        expected_code="empty_synthetic_cart", version=4,
    )

    refill_body = json.dumps({"variant_id": "v1", "quantity": 2, "expected_version": 4,
                              "idempotency_key": "refill-for-complete",
                              "commit_attempt_id": str(uuid4())}).encode()
    refill_receipt, refill_path = issue_cart_http_proof(path, body=refill_body, resource=binding)
    refill_result = executor.execute_verified_http(
        receipt_id=refill_receipt, raw_path=refill_path, raw_body=refill_body,
    )
    assert refill_result["operation"] == "addGuestCartItem"
    assert refill_result["status"] == "committed" and refill_result["state_version"] == 5
    assert projector.project_synthetic_success(refill_receipt).status_code == 200

    complete_body = json.dumps({"expected_version": 5, "idempotency_key": "complete-cart",
                                "commit_attempt_id": str(uuid4())}).encode()
    complete_receipt, complete_path = issue_cart_http_proof(
        "/synthetic/carts/" + binding.resource_id + "/complete",
        body=complete_body, resource=binding,
    )
    complete_result = executor.execute_verified_http(
        receipt_id=complete_receipt, raw_path=complete_path,
        raw_body=complete_body,
    )
    assert complete_result["operation"] == "completeGuestCart"
    assert complete_result["status"] == "committed" and complete_result["state_version"] == 6
    completed = projector.project_synthetic_success(complete_receipt)
    assert projector.project_verified_receipt(complete_receipt) == completed
    complete_payload = json.loads(completed.body_bytes)
    assert completed.operation_id == "completeGuestCart" and completed.status_code == 200
    assert complete_payload["state_version"] == 6
    assert complete_payload["order"]["cart_id"] == binding.resource_id
    assert complete_payload["order"]["status"] == "placed"
    order_id = complete_payload["order"]["id"]

    # C-06：已完成的 Cart 不能再次完成，沒有新 Order 或新 World 版本。
    assert_fixed_cart_rejection(
        request_path="/synthetic/carts/" + binding.resource_id + "/complete",
        body={"expected_version": 6, "idempotency_key": "complete-twice"},
        resource=binding, expected_operation="completeGuestCart",
        expected_code="cart_not_active", version=6,
    )

    order_binding = store.resource_binding(
        order_id, environment_id=binding.environment_id,
        deployment_id=binding.deployment_id, now=now,
    )
    order_receipt, order_path = issue_cart_http_proof(
        "/synthetic/orders/" + order_id, body=b"", resource=order_binding, method="GET",
    )
    order_result = executor.execute_verified_http(
        receipt_id=order_receipt, raw_path=order_path, raw_body=b"",
    )
    assert order_result["kind"] == "cart_read_admitted"
    assert order_result["operation"] == "getSyntheticOrder" and order_result["resource_id"] == order_id
    order_projection = projector.project_cart_read(order_receipt)
    assert projector.project_verified_receipt(order_receipt) == order_projection
    order_payload = json.loads(order_projection.body_bytes)
    assert order_projection.operation_id == "getSyntheticOrder" and order_projection.status_code == 200
    assert order_projection.source.read_admission_id == order_result["read_admission_id"]
    assert order_payload["order"] == complete_payload["order"]
    assert order_payload["state_version"] == 6 and order_payload["commit_attempt_id"] is None

    cancel_body = json.dumps({"expected_version": 6, "idempotency_key": "cancel-order",
                              "commit_attempt_id": str(uuid4())}).encode()
    cancel_receipt, cancel_path = issue_cart_http_proof(
        "/synthetic/orders/" + order_id + "/cancel", body=cancel_body, resource=order_binding,
    )
    cancel_result = executor.execute_verified_http(
        receipt_id=cancel_receipt, raw_path=cancel_path, raw_body=cancel_body,
    )
    assert cancel_result["status"] == "committed" and cancel_result["state_version"] == 7
    cancelled = projector.project_synthetic_success(cancel_receipt)
    assert projector.project_verified_receipt(cancel_receipt) == cancelled
    cancelled_payload = json.loads(cancelled.body_bytes)
    assert cancelled.operation_id == "cancelSyntheticOrder" and cancelled.status_code == 200
    assert cancelled_payload["order"]["id"] == order_id
    assert cancelled_payload["order"]["cart_id"] == binding.resource_id
    assert cancelled_payload["order"]["status"] == "cancelled"
    assert cancelled_payload["state_version"] == 7

    # C-08：已取消的 Order 不能再次釋回庫存；拒絕來源仍和原 Order ID 綁定。
    assert_fixed_cart_rejection(
        request_path="/synthetic/orders/" + order_id + "/cancel",
        body={"expected_version": 7, "idempotency_key": "cancel-order-twice"},
        resource=order_binding, expected_operation="cancelSyntheticOrder",
        expected_code="order_not_cancellable", version=7,
    )


def test_untrusted_legacy_cart_cannot_enter_verified_http_executor(isolated_test_dsn):
    """即使舊 Cart World 有有效資源映射，缺 Creator 的受保護 Lineage 不得成為 RPC 目標。"""
    import psycopg

    dsn, now = isolated_test_dsn, int(time.time())
    creator = SessionBinding(environment_id="legacy-cart", deployment_id="isolated",
                             session_id=uuid4().hex, session_epoch=1, access_mode="cart")
    store = SyntheticCarts(dsn)
    catalog = {"v1": {"sku": "sku-1", "unit_price": 100}}
    inventory = {"sku-1": 6}
    store.resolve(creator, {"catalog": catalog, "inventory": inventory,
                            "reservations": {}}, now=now, ttl=180)
    created = store.create_cart(creator, catalog=catalog, inventory=inventory,
                                idempotency_key=uuid4(), commit_attempt_id=uuid4(), now=now, ttl=180)
    snapshot = store.inspect_binding(created.binding, now=now)
    executor = PostgresProtectedWorldExecutor(dsn, expected_login=_real_login(dsn), world_store=store)
    receipt, jti = uuid4(), uuid4().hex
    with psycopg.connect(dsn) as connection:
        connection.execute("INSERT INTO replay_entries VALUES ('gateway','mirage',%s,%s)",
                           (jti, now + 120))
        connection.execute(
            """INSERT INTO ingress_receipts (
                   receipt_id,issuer,audience,jti,key_id,environment_id,deployment_id,
                   session_id,session_epoch,request_fingerprint,assessment_digest,
                   claims_digest,verification_policy_version,token_issued_at,
                   token_not_before,token_expires_at,access_mode,resource_id)
               VALUES (%s,'gateway','mirage',%s,'kid',%s,%s,%s,1,%s,%s,%s,
                       'trusted-session-v1.1',%s,%s,%s,'cart',%s)""",
            (receipt, jti, created.binding.environment_id, created.binding.deployment_id,
             created.binding.session_id, digest("a"), digest("b"), digest("c"),
             now - 5, now - 5, now + 90, created.binding.resource_id),
        )
    with pytest.raises(ProtectedGrantError, match="cart_lineage_missing"):
        executor.admit_read(receipt_id=receipt, binding=created.binding,
                            request_fingerprint=digest("a"), expires_at=now + 30)
    with pytest.raises(ProtectedGrantError, match="derived_lineage_missing"):
        executor.commit_verified_cart_http(
            receipt_id=uuid4(), binding=created.binding, authorized_scope=snapshot.scope,
            raw_path=b"/synthetic/carts/legacy/line-items", raw_body=b"{}",
        )


def test_verified_cart_creator_http_mints_one_derived_world(isolated_test_dsn):
    """真正的 createGuestCart Proof 從 Receipt 固定建立鍵，重試只有同一個衍生世界。"""
    import psycopg

    dsn, now = isolated_test_dsn, int(time.time())
    creator = SessionBinding(environment_id="cart-create-http", deployment_id="isolated",
                             session_id=uuid4().hex, session_epoch=1, access_mode="cart")
    initial = {"catalog": {"v1": {"sku": "sku-1", "unit_price": 100}},
               "inventory": {"sku-1": 5}}
    service = SyntheticCarts(dsn)
    service.resolve(creator, {**initial, "reservations": {}}, now=now, ttl=180)
    request = replace(original_request(path="/synthetic/carts"), body=b"{}")
    proof = derive_verified_operation(request)
    receipt, jti = uuid4(), uuid4().hex
    with psycopg.connect(dsn) as connection:
        connection.execute("INSERT INTO replay_entries VALUES ('gateway','mirage',%s,%s)",
                           (jti, now + 120))
        connection.execute(
            """INSERT INTO ingress_receipts (
                   receipt_id,issuer,audience,jti,key_id,environment_id,deployment_id,
                   session_id,session_epoch,request_fingerprint,assessment_digest,
                   claims_digest,verification_policy_version,token_issued_at,
                   token_not_before,token_expires_at,access_mode)
               VALUES (%s,'gateway','mirage',%s,'kid',%s,%s,%s,1,%s,%s,%s,
                       'trusted-session-v1.1',%s,%s,%s,'cart')""",
            (receipt, jti, creator.environment_id, creator.deployment_id,
             creator.session_id, proof.request_fingerprint, digest("b"), digest("c"),
             now - 5, now - 5, now + 90),
        )
        connection.execute(
            """INSERT INTO protected_http_operation_bindings (
                   receipt_id,platform,operation_id,method,path_template,
                   request_fingerprint,request_body_sha256,request_path,request_content_type)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
            (receipt, proof.platform, proof.operation_id, proof.method, proof.path_template,
             proof.request_fingerprint, proof.request_body_sha256,
             proof.request_path, proof.request_content_type),
        )
    executor = PostgresProtectedWorldExecutor(dsn, expected_login=_real_login(dsn),
                                               world_store=service, cart_initial_state=initial)
    args = dict(receipt_id=receipt, creator=creator,
                raw_path=request.raw_path, raw_body=request.body)
    with pytest.raises(OperationBindingError, match="snapshot_mismatch"):
        executor.create_verified_cart_http(**{**args, "raw_body": b'{"different":true}'})
    created = executor.create_verified_cart_http(**args)
    repeated = executor.create_verified_cart_http(**args)
    assert created.binding == repeated.binding
    assert repeated.outcome.replayed
    with psycopg.connect(dsn) as connection:
        assert connection.execute("SELECT count(*) FROM protected_cart_creations WHERE receipt_id=%s",
                                  (receipt,)).fetchone()[0] == 1
        assert connection.execute("SELECT count(*) FROM synthetic_resources WHERE resource_id=%s",
                                  (created.binding.resource_id,)).fetchone()[0] == 1
    projector = PostgresProtectedNativeProjector(dsn, expected_login=_real_login(dsn))
    projected = projector.project_cart_creation(receipt)
    assert projector.project_verified_receipt(receipt) == projected
    creator_scope = service.inspect_binding(creator, now=now).scope
    derived_scope = service.inspect_binding(created.binding, now=now).scope
    payload = json.loads(projected.body_bytes)
    assert projected.scope == creator_scope
    assert projected.scope != derived_scope
    assert projected.status_code == 200 and projected.operation_id == "createGuestCart"
    assert projected.source == CartCreationSource(
        derived_session_id=created.binding.session_id,
        derived_world_generation_id=derived_scope.world_generation_id,
        resource_id=created.binding.resource_id,
        commit_attempt_id=str(created.outcome.commit_attempt_id),
        state_version=created.outcome.state_version,
        state_hash=created.outcome.state_hash,
    )
    assert payload == {"cart": created.outcome.result,
                       "state_version": created.outcome.state_version,
                       "state_hash": created.outcome.state_hash,
                       "commit_attempt_id": str(created.outcome.commit_attempt_id)}
    assert _candidate(dsn, scope=projected.scope, source=projected.source,
                      receipt_id=receipt, fingerprint=proof.request_fingerprint,
                      body=projected.body_bytes) == 1
    # 在真正 Authorizer 交易中核准 Creator Candidate，來源才引用 Derived Cart。
    candidate_ref, evidence = uuid4().hex, projection_evidence()
    envelope = response_envelope(200, projected.headers, projected.body_bytes)
    envelope_hash, body_hash, header_hash = response_hashes(
        200, projected.headers, projected.body_bytes)
    PostgresCandidateStore(dsn).put(creator_scope, candidate_ref, envelope,
                                    expires_at=now + 80)
    assert PostgresCandidatePromoter(dsn, expected_login=_real_login(dsn)).promote(
        receipt_id=receipt, scope=creator_scope, candidate_ref=candidate_ref,
        request_fingerprint=proof.request_fingerprint, envelope_hash=envelope_hash,
        immutable_body_hash=body_hash, semantic_headers_hash=header_hash,
        evidence=evidence, source=projected.source,
    ) == 1
    admitted = PostgresProtectedAuthorizer(dsn, expected_login=_real_login(dsn)).grant(
        operation_id=uuid4(), receipt_id=receipt, scope=creator_scope,
        candidate_ref=candidate_ref, candidate_version=1,
        authorization_revision="cart-creation-candidate-only-v1",
        authorization_deadline=now + 40, transmission_deadline=now + 50,
        evidence=evidence,
    )
    assert admitted.world_generation_id == creator_scope.world_generation_id
    assert admitted.source == projected.source
    with pytest.raises(ProtectedGrantError, match="candidate_source_unverifiable"):
        _candidate(dsn, scope=derived_scope, source=projected.source,
                   receipt_id=receipt, fingerprint=proof.request_fingerprint,
                   body=projected.body_bytes)
    with pytest.raises(ProtectedGrantError, match="candidate_source_unverifiable"):
        _candidate(dsn, scope=creator_scope, source=projected.source.model_copy(
            update={"derived_session_id": uuid4().hex}),
            receipt_id=receipt, fingerprint=proof.request_fingerprint,
            body=projected.body_bytes)
    with psycopg.connect(dsn) as connection:
        connection.execute(
            "UPDATE guest_cart_creations SET operation_result=%s::jsonb WHERE cart_id=%s",
            (json.dumps({"id": "cart_" + uuid4().hex}), created.binding.resource_id),
        )
    with pytest.raises(ProtectedGrantError, match="cart_creation_grant_source_unverifiable"):
        PostgresProtectedAuthorizer(dsn, expected_login=_real_login(dsn)).grant(
            operation_id=uuid4(), receipt_id=receipt, scope=creator_scope,
            candidate_ref=candidate_ref, candidate_version=1,
            authorization_revision="stale-cart-creation-must-fail",
            authorization_deadline=now + 40, transmission_deadline=now + 50,
            evidence=evidence,
        )
    with pytest.raises(ProtectedGrantError, match="protected_cart_creation_result_mismatch"):
        projector.project_cart_creation(receipt)
    with pytest.raises(ProtectedGrantError, match="candidate_source_unverifiable"):
        _candidate(dsn, scope=creator_scope, source=projected.source,
                   receipt_id=receipt, fingerprint=proof.request_fingerprint,
                   body=projected.body_bytes)


def test_medusa_creator_empty_cart_is_independently_projected_and_promotable(isolated_test_dsn):
    """M-01 真 PG：原生空建立→唯一派生 Cart→唯讀 Validator 200→Creator Promotion。"""
    import psycopg

    dsn, now = isolated_test_dsn, int(time.time())
    creator = SessionBinding(environment_id="medusa-create-http", deployment_id="isolated",
                             session_id=uuid4().hex, session_epoch=1, access_mode="cart")
    state = {"catalog": {"known": {"sku": "sku-1", "unit_price": 100}},
             "inventory": {"sku-1": 5},
             "native_context": {"region_id": "reg_mirage_usd", "sales_channel_id": "sc_mirage",
                                "email": "ci@example.invalid", "metadata": {}}}
    store = SyntheticCarts(dsn)
    store.resolve(creator, {"catalog": state["catalog"], "inventory": state["inventory"],
                            "reservations": {}}, now=now, ttl=180)
    body = b'{"email":"ci@example.invalid","items":[]}'
    request = replace(original_request(path="/store/carts"), body=body,
                      headers=(("host", "mirage.test"), ("content-type", "application/json"),
                               ("x-publishable-api-key", "pk_only_executor")))
    proof = derive_verified_operation(request)
    receipt, jti = uuid4(), uuid4().hex
    with psycopg.connect(dsn) as connection:
        connection.execute("INSERT INTO replay_entries VALUES ('gateway','mirage',%s,%s)",
                           (jti, now + 120))
        connection.execute(
            """INSERT INTO ingress_receipts (
                   receipt_id,issuer,audience,jti,key_id,environment_id,deployment_id,
                   session_id,session_epoch,request_fingerprint,assessment_digest,
                   claims_digest,verification_policy_version,token_issued_at,
                   token_not_before,token_expires_at,access_mode)
               VALUES (%s,'gateway','mirage',%s,'kid',%s,%s,%s,1,%s,%s,%s,
                       'trusted-session-v1.1',%s,%s,%s,'cart')""",
            (receipt, jti, creator.environment_id, creator.deployment_id,
             creator.session_id, proof.request_fingerprint, digest("b"), digest("c"),
             now - 5, now - 5, now + 90),
        )
        connection.execute(
            """INSERT INTO protected_http_operation_bindings (
                   receipt_id,platform,operation_id,method,path_template,
                   request_fingerprint,request_body_sha256,request_path,request_content_type)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
            (receipt, proof.platform, proof.operation_id, proof.method, proof.path_template,
             proof.request_fingerprint, proof.request_body_sha256,
             proof.request_path, proof.request_content_type),
        )
    executor = PostgresProtectedWorldExecutor(
        dsn, expected_login=_real_login(dsn), world_store=store,
        cart_initial_state=state, medusa_publishable_key="pk_only_executor",
    )
    with pytest.raises(OperationBindingError, match="fingerprint_denied"):
        executor.execute_verified_http(
            receipt_id=receipt, raw_path=request.raw_path,
            raw_body=b'{"email":"attacker@example.invalid"}', original_http=request,
        )
    outcome = executor.execute_verified_http(
        receipt_id=receipt, raw_path=request.raw_path, raw_body=body, original_http=request,
    )
    assert outcome["kind"] == "cart_created" and outcome["operation"] == "PostCarts"
    assert outcome["status"] == "committed"
    source_path = (Path(__file__).resolve().parents[1]
                   / "domains/ecommerce/inputs/sources/medusa/openapi.yaml")
    projector = PostgresProtectedNativeProjector(
        dsn, expected_login=_real_login(dsn), medusa_source=source_path,
    )
    projected = projector.project_medusa_creation(receipt)
    assert projector.project_verified_receipt(receipt) == projected
    payload = json.loads(projected.body_bytes)
    creator_scope = store.inspect_binding(creator, now=now).scope
    assert projected.scope == creator_scope and projected.operation_id == "PostCarts"
    assert projected.status_code == 200 and projected.source.kind == "cart_creation"
    assert projected.source.resource_id == outcome["resource_id"]
    assert projected.source.commit_attempt_id == outcome["commit_attempt_id"]
    assert payload["cart"]["id"] == outcome["resource_id"]
    assert payload["cart"]["email"] == "ci@example.invalid"
    assert payload["cart"]["items"] == []
    assert set(payload) == {"cart"}
    assert projected.source.derived_session_id != creator.session_id
    assert _candidate(dsn, scope=projected.scope, source=projected.source,
                      receipt_id=receipt, fingerprint=proof.request_fingerprint,
                      body=projected.body_bytes) == 1
    evidence = projection_evidence()
    PostgresProjectionRegistry(dsn).ensure_registered_batch((evidence,))
    ref = uuid4().hex
    envelope = response_envelope(200, projected.headers, projected.body_bytes)
    envelope_hash, body_hash, header_hash = response_hashes(
        200, projected.headers, projected.body_bytes,
    )
    PostgresCandidateStore(dsn).put(creator_scope, ref, envelope, expires_at=now + 80)
    assert PostgresCandidatePromoter(dsn, expected_login=_real_login(dsn)).promote(
        receipt_id=receipt, scope=creator_scope, candidate_ref=ref,
        request_fingerprint=proof.request_fingerprint, envelope_hash=envelope_hash,
        immutable_body_hash=body_hash, semantic_headers_hash=header_hash,
        evidence=evidence, source=projected.source,
    ) == 1
    authorized = PostgresProtectedAuthorizer(dsn, expected_login=_real_login(dsn)).grant(
        operation_id=uuid4(), receipt_id=receipt, scope=creator_scope,
        candidate_ref=ref, candidate_version=1,
        authorization_revision="medusa-creation-candidate-only-v1",
        authorization_deadline=now + 40, transmission_deadline=now + 50,
        evidence=evidence,
    )
    assert authorized.source == projected.source
    with pytest.raises(ProtectedGrantError, match="candidate_source_unverifiable"):
        _candidate(dsn, scope=WorldScope(environment_id=creator.environment_id,
                                        deployment_id=creator.deployment_id,
                                        session_id=projected.source.derived_session_id,
                                        world_generation_id=projected.source.derived_world_generation_id),
                   source=projected.source, receipt_id=receipt,
                   fingerprint=proof.request_fingerprint, body=projected.body_bytes)


def test_verified_cart_get_requires_creator_lineage_and_original_receipt(isolated_test_dsn):
    """真 PostgreSQL 只有已派生的 Cart 與精確 GET Receipt 能建立可信讀取。"""
    import psycopg

    dsn, now = isolated_test_dsn, int(time.time())
    creator = SessionBinding(environment_id="cart-get-http", deployment_id="isolated",
                             session_id=uuid4().hex, session_epoch=1, access_mode="cart")
    initial = {"catalog": {}, "inventory": {}}
    service = SyntheticCarts(dsn)
    service.resolve(creator, {**initial, "reservations": {}}, now=now, ttl=180)
    create_request = replace(original_request(path="/synthetic/carts"), body=b"{}")
    creator_proof = derive_verified_operation(create_request)
    creator_receipt, creator_jti = uuid4(), uuid4().hex
    with psycopg.connect(dsn) as connection:
        connection.execute("INSERT INTO replay_entries VALUES ('gateway','mirage',%s,%s)",
                           (creator_jti, now + 120))
        connection.execute(
            """INSERT INTO ingress_receipts (
                   receipt_id,issuer,audience,jti,key_id,environment_id,deployment_id,
                   session_id,session_epoch,request_fingerprint,assessment_digest,
                   claims_digest,verification_policy_version,token_issued_at,
                   token_not_before,token_expires_at,access_mode)
               VALUES (%s,'gateway','mirage',%s,'kid',%s,%s,%s,1,%s,%s,%s,
                       'trusted-session-v1.1',%s,%s,%s,'cart')""",
            (creator_receipt, creator_jti, creator.environment_id, creator.deployment_id,
             creator.session_id, creator_proof.request_fingerprint, digest("b"), digest("c"),
             now - 5, now - 5, now + 90),
        )
        connection.execute(
            """INSERT INTO protected_http_operation_bindings (
                   receipt_id,platform,operation_id,method,path_template,
                   request_fingerprint,request_body_sha256,request_path,request_content_type)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
            (creator_receipt, creator_proof.platform, creator_proof.operation_id,
             creator_proof.method, creator_proof.path_template,
             creator_proof.request_fingerprint, creator_proof.request_body_sha256,
             creator_proof.request_path, creator_proof.request_content_type),
        )
    executor = PostgresProtectedWorldExecutor(dsn, expected_login=_real_login(dsn),
                                               world_store=service, cart_initial_state=initial)
    created = executor.create_verified_cart_http(
        receipt_id=creator_receipt, creator=creator,
        raw_path=create_request.raw_path, raw_body=create_request.body,
    )
    get_path = "/synthetic/carts/" + created.binding.resource_id
    get_request = replace(original_request(path=get_path, method="GET"), body=b"")
    proof = derive_verified_operation(get_request)
    get_receipt, get_jti = uuid4(), uuid4().hex
    with psycopg.connect(dsn) as connection:
        connection.execute("INSERT INTO replay_entries VALUES ('gateway','mirage',%s,%s)",
                           (get_jti, now + 120))
        connection.execute(
            """INSERT INTO ingress_receipts (
                   receipt_id,issuer,audience,jti,key_id,environment_id,deployment_id,
                   session_id,session_epoch,request_fingerprint,assessment_digest,
                   claims_digest,verification_policy_version,token_issued_at,
                   token_not_before,token_expires_at,access_mode,resource_id)
               VALUES (%s,'gateway','mirage',%s,'kid',%s,%s,%s,1,%s,%s,%s,
                       'trusted-session-v1.1',%s,%s,%s,'cart',%s)""",
            (get_receipt, get_jti, created.binding.environment_id,
             created.binding.deployment_id, created.binding.session_id,
             proof.request_fingerprint, digest("b"), digest("c"),
             now - 5, now - 5, now + 90, created.binding.resource_id),
        )
        connection.execute(
            """INSERT INTO protected_http_operation_bindings (
                   receipt_id,platform,operation_id,method,path_template,
                   request_fingerprint,request_body_sha256,request_path,request_content_type)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
            (get_receipt, proof.platform, proof.operation_id, proof.method, proof.path_template,
             proof.request_fingerprint, proof.request_body_sha256,
             proof.request_path, proof.request_content_type),
        )
    args = dict(receipt_id=get_receipt, binding=created.binding,
                raw_path=get_request.raw_path, raw_body=get_request.body, expires_at=now + 30)
    with pytest.raises(OperationBindingError, match="snapshot_mismatch"):
        executor.read_verified_cart_http(**{**args, "raw_body": b"{}"})
    read, query = executor.read_verified_cart_http(**args)
    assert query.operation == "getGuestCart"
    assert read.snapshot.state["cart"]["id"] == created.binding.resource_id
    projected = PostgresProtectedNativeProjector(dsn, expected_login=_real_login(dsn)).project_cart_read(
        get_receipt)
    assert projected.status_code == 200
    assert projected.operation_id == "getGuestCart"
    assert projected.request_fingerprint == proof.request_fingerprint
    assert projected.source.state_hash == read.snapshot.state_hash
    assert projected.source.read_admission_id == read.source.read_admission_id
    assert json.loads(projected.body_bytes) == {
        "cart": SyntheticCarts.public_cart(read.snapshot.state["cart"]),
        "state_version": read.snapshot.version, "state_hash": read.snapshot.state_hash,
        "commit_attempt_id": None,
    }
    with pytest.raises(ProtectedGrantError, match="cart_read_source_missing"):
        PostgresProtectedNativeProjector(dsn, expected_login=_real_login(dsn)).project_cart_read(uuid4())
    with psycopg.connect(dsn) as connection:
        assert connection.execute(
            "SELECT count(*) FROM protected_world_read_sources WHERE receipt_id=%s",
            (get_receipt,),
        ).fetchone()[0] == 1

    # C-09：有效 Cart 世代內確定沒有該歷史 UUID4，才允許唯讀來源投影 409。
    missing_path = "/synthetic/carts/" + created.binding.resource_id + "/operations/" + str(uuid4())
    missing_request = replace(original_request(path=missing_path, method="GET"), body=b"")
    missing_proof = derive_verified_operation(missing_request)
    missing_receipt, missing_jti = uuid4(), uuid4().hex
    with psycopg.connect(dsn) as connection:
        connection.execute("INSERT INTO replay_entries VALUES ('gateway','mirage',%s,%s)",
                           (missing_jti, now + 120))
        connection.execute(
            """INSERT INTO ingress_receipts (
                   receipt_id,issuer,audience,jti,key_id,environment_id,deployment_id,
                   session_id,session_epoch,request_fingerprint,assessment_digest,
                   claims_digest,verification_policy_version,token_issued_at,
                   token_not_before,token_expires_at,access_mode,resource_id)
               VALUES (%s,'gateway','mirage',%s,'kid',%s,%s,%s,1,%s,%s,%s,
                       'trusted-session-v1.1',%s,%s,%s,'cart',%s)""",
            (missing_receipt, missing_jti, created.binding.environment_id,
             created.binding.deployment_id, created.binding.session_id,
             missing_proof.request_fingerprint, digest("b"), digest("c"),
             now - 5, now - 5, now + 90, created.binding.resource_id),
        )
        connection.execute(
            """INSERT INTO protected_http_operation_bindings (
                   receipt_id,platform,operation_id,method,path_template,
                   request_fingerprint,request_body_sha256,request_path,request_content_type)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
            (missing_receipt, missing_proof.platform, missing_proof.operation_id,
             missing_proof.method, missing_proof.path_template,
             missing_proof.request_fingerprint, missing_proof.request_body_sha256,
             missing_proof.request_path, missing_proof.request_content_type),
        )
    unknown_read, unknown_query = executor.read_verified_cart_http(
        receipt_id=missing_receipt, binding=created.binding,
        raw_path=missing_request.raw_path, raw_body=b"", expires_at=now + 30,
    )
    assert unknown_query.operation == "getCartOperation"
    missing_projection = PostgresProtectedNativeProjector(
        dsn, expected_login=_real_login(dsn)).project_cart_read(missing_receipt)
    assert missing_projection.status_code == 409
    assert missing_projection.source.read_admission_id == unknown_read.source.read_admission_id
    assert missing_projection.body_bytes == b'{"code":"operation_not_found"}'


def test_protected_cart_creator_receipt_mints_one_derived_scope(isolated_test_dsn):
    """Creator Receipt 只能原子建立一個衍生 Cart，重試查回且不能改綁新的建立鍵。"""
    import psycopg

    dsn = isolated_test_dsn
    now = int(time.time())
    creator = SessionBinding(environment_id="cart-protected", deployment_id="isolated",
                             session_id=uuid4().hex, session_epoch=1, access_mode="cart")
    service = SyntheticCarts(dsn)
    initial = {"catalog": {"v1": {"sku": "sku-1", "unit_price": 100}},
               "inventory": {"sku-1": 5}}
    service.resolve(creator, {**initial, "reservations": {}}, now=now, ttl=180)
    receipt, fingerprint = uuid4(), digest("a")
    with psycopg.connect(dsn) as connection:
        jti = uuid4().hex
        connection.execute("INSERT INTO replay_entries VALUES ('gateway','mirage',%s,%s)",
                           (jti, now + 120))
        connection.execute(
            """INSERT INTO ingress_receipts (
                   receipt_id,issuer,audience,jti,key_id,environment_id,deployment_id,
                   session_id,session_epoch,request_fingerprint,assessment_digest,
                   claims_digest,verification_policy_version,token_issued_at,
                   token_not_before,token_expires_at,access_mode)
               VALUES (%s,'gateway','mirage',%s,'kid',%s,%s,%s,1,%s,%s,%s,
                       'trusted-session-v1.1',%s,%s,%s,'cart')""",
            (receipt, jti, creator.environment_id, creator.deployment_id,
             creator.session_id, fingerprint, digest("b"), digest("c"),
             now - 5, now - 5, now + 90),
        )
    executor = PostgresProtectedWorldExecutor(
        dsn, expected_login=_real_login(dsn), world_store=service,
        cart_initial_state=initial,
    )
    key, attempt = uuid4(), uuid4()
    args = dict(receipt_id=receipt, creator=creator, request_fingerprint=fingerprint,
                idempotency_key=key, commit_attempt_id=attempt,
                creation_digest=digest("d"), ttl=60)
    created = executor.create_cart(**args)
    repeated = executor.create_cart(**args)
    assert created.binding == repeated.binding
    assert repeated.outcome.replayed
    assert created.binding.session_id != creator.session_id
    with pytest.raises(ProtectedGrantError, match="receipt_rebound"):
        executor.create_cart(**{**args, "idempotency_key": uuid4()})
    with psycopg.connect(dsn) as connection:
        assert connection.execute("SELECT count(*) FROM protected_cart_creations").fetchone()[0] == 1
        assert connection.execute("SELECT count(*) FROM guest_cart_creations").fetchone()[0] == 1


def test_protected_read_and_commit_sources_remain_distinct_and_usable(isolated_test_dsn):
    """可信 ReadAdmission 與完整 World Mutation 都產生同交易證據，可供 Validator 使用。"""
    import psycopg

    executor, store, binding, snapshot, receipt, fingerprint, now = _trusted_world(isolated_test_dsn)
    read = executor.admit_read(receipt_id=receipt, binding=binding,
                               request_fingerprint=fingerprint, expires_at=now + 30)
    assert read.snapshot.scope == snapshot.scope
    assert _candidate(isolated_test_dsn, scope=snapshot.scope, source=read.source,
                      receipt_id=receipt, fingerprint=fingerprint) == 1
    attempt = uuid4()
    outcome = executor.commit_event(
        receipt_id=receipt, binding=binding, request_fingerprint=fingerprint,
        authorized_scope=snapshot.scope, operation="counter.add", command={"amount": 1},
        expected_version=1, idempotency_key="add-once", commit_attempt_id=attempt,
    )
    assert outcome.status == "committed" and outcome.committed_state_version == 2
    with psycopg.connect(isolated_test_dsn) as connection:
        assert connection.execute("SELECT count(*) FROM protected_world_read_sources").fetchone()[0] == 1
        assert connection.execute("SELECT count(*) FROM protected_world_commit_sources").fetchone()[0] == 1
    # CommitSource 對應另一份 Candidate，不能把同一 Candidate/Hash 偷換成第二份來源。
    source = CommitSource(world_generation_id=snapshot.scope.world_generation_id,
                          operation_result_digest=outcome.result_digest,
                          committed_state_version=outcome.committed_state_version,
                          committed_state_hash=outcome.committed_state_hash)
    assert _candidate(isolated_test_dsn, scope=snapshot.scope, source=source,
                      receipt_id=receipt, fingerprint=fingerprint) == 1


def test_protected_409_requires_real_rejected_handler_and_exact_envelope(isolated_test_dsn):
    """合法業務拒絕可 Promotion；錯封套、錯模板及無來源的錯誤不能升格。"""
    import psycopg

    executor, _, binding, snapshot, receipt, fingerprint, now = _trusted_world(isolated_test_dsn)
    executor.admit_read(receipt_id=receipt, binding=binding,
                        request_fingerprint=fingerprint, expires_at=now + 30)
    attempt = uuid4()
    args = dict(receipt_id=receipt, binding=binding, request_fingerprint=fingerprint,
                authorized_scope=snapshot.scope, operation="counter.reject", command={},
                expected_version=1, idempotency_key="reject-once", commit_attempt_id=attempt)
    rejected = executor.commit_event(**args)
    assert rejected.status == "rejected"
    assert executor.commit_event(**args).result_digest == rejected.result_digest
    source = SecurityErrorSource(template_id="insufficient_synthetic_inventory",
                                 contract_revision="synthetic-inventory-1")
    with pytest.raises(ProtectedGrantError, match="candidate_source_unverifiable"):
        _candidate(isolated_test_dsn, scope=snapshot.scope, source=source,
                   receipt_id=receipt, fingerprint=fingerprint, status=409,
                   body=b'{"code":"forged"}')
    wrong_revision = source.model_copy(update={"contract_revision": "synthetic-inventory-2"})
    with pytest.raises(ProtectedGrantError, match="candidate_source_unverifiable"):
        _candidate(isolated_test_dsn, scope=snapshot.scope, source=wrong_revision,
                   receipt_id=receipt, fingerprint=fingerprint, status=409,
                   body=b'{"code":"insufficient_synthetic_inventory"}')
    assert _candidate(isolated_test_dsn, scope=snapshot.scope, source=source,
                      receipt_id=receipt, fingerprint=fingerprint, status=409,
                      body=b'{"code":"insufficient_synthetic_inventory"}') == 1
    with psycopg.connect(isolated_test_dsn) as connection:
        assert connection.execute("SELECT count(*) FROM protected_world_rejection_sources").fetchone()[0] == 1
        assert connection.execute("SELECT version FROM world_snapshots WHERE world_generation_id=%s",
                                  (snapshot.scope.world_generation_id,)).fetchone()[0] == 1


def test_protected_world_refuses_forged_mode_and_request_fingerprint(isolated_test_dsn):
    """Runtime 自填 cart 能力或不同 Request Fingerprint 無法創造可信業務副作用。"""
    import psycopg

    executor, _, binding, snapshot, receipt, fingerprint, now = _trusted_world(isolated_test_dsn)
    forged_mode = binding.model_copy(update={"access_mode": "cart"})
    with pytest.raises(ProtectedGrantError, match="capability_mismatch"):
        executor.admit_read(receipt_id=receipt, binding=forged_mode,
                            request_fingerprint=fingerprint, expires_at=now + 30)
    with pytest.raises(ProtectedGrantError, match="capability_mismatch"):
        executor.admit_read(receipt_id=receipt, binding=binding,
                            request_fingerprint=digest("d"), expires_at=now + 30)
    with psycopg.connect(isolated_test_dsn) as connection:
        assert connection.execute("SELECT count(*) FROM protected_world_read_sources").fetchone()[0] == 0
        assert connection.execute("SELECT version FROM world_snapshots WHERE world_generation_id=%s",
                                  (snapshot.scope.world_generation_id,)).fetchone()[0] == 1


def test_runtime_written_read_admission_without_proof_cannot_promote(isolated_test_dsn):
    """舊 ReadAdmission 即使完整 Scope 與 Hash 都正確，缺可信 Executor 證據仍拒絕。"""
    import psycopg

    _, _, _, snapshot, receipt, fingerprint, now = _trusted_world(isolated_test_dsn)
    read_id = uuid4().hex
    with psycopg.connect(isolated_test_dsn) as connection:
        connection.execute(
            """INSERT INTO read_admissions VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
            (read_id, snapshot.scope.environment_id, snapshot.scope.deployment_id,
             snapshot.scope.session_id, snapshot.scope.world_generation_id,
             fingerprint, snapshot.version, snapshot.state_hash, now + 30),
        )
    forged = SnapshotSource(read_admission_id=read_id,
                            world_generation_id=snapshot.scope.world_generation_id,
                            state_version=snapshot.version, state_hash=snapshot.state_hash)
    with pytest.raises(ProtectedGrantError, match="candidate_source_unverifiable"):
        _candidate(isolated_test_dsn, scope=snapshot.scope, source=forged,
                   receipt_id=receipt, fingerprint=fingerprint)


def test_protected_world_commit_proof_failure_rolls_back_business_mutation(isolated_test_dsn):
    """提交證據被拒絕時整個 World 事件／快照更新回滾，不留下未證明的 Mutation。"""
    import psycopg

    executor, _, binding, snapshot, receipt, fingerprint, now = _trusted_world(isolated_test_dsn)
    executor.admit_read(receipt_id=receipt, binding=binding,
                        request_fingerprint=fingerprint, expires_at=now + 30)
    with psycopg.connect(isolated_test_dsn) as connection:
        connection.execute(
            """CREATE TRIGGER injected_protected_source_failure
               BEFORE INSERT ON protected_world_commit_sources FOR EACH ROW
               EXECUTE FUNCTION reject_protected_mutation()""",
        )
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        executor.commit_event(
            receipt_id=receipt, binding=binding, request_fingerprint=fingerprint,
            authorized_scope=snapshot.scope, operation="counter.add", command={"amount": 1},
            expected_version=1, idempotency_key="fail-provenance", commit_attempt_id=uuid4(),
        )
    with psycopg.connect(isolated_test_dsn) as connection:
        assert connection.execute("SELECT count(*) FROM world_operations").fetchone()[0] == 0
        assert connection.execute("SELECT count(*) FROM world_events").fetchone()[0] == 0
        assert connection.execute("SELECT version FROM world_snapshots WHERE world_generation_id=%s",
                                  (snapshot.scope.world_generation_id,)).fetchone()[0] == 1


def test_unprotected_world_commit_cannot_be_promoted(isolated_test_dsn):
    """保留舊業務方法相容性，但管理身份產生的舊列沒有新的來源證據就不能授權。"""
    executor, store, binding, snapshot, receipt, fingerprint, now = _trusted_world(isolated_test_dsn)
    read = executor.admit_read(receipt_id=receipt, binding=binding,
                               request_fingerprint=fingerprint, expires_at=now + 30)
    old = store.commit_event(
        binding, authorized_scope=snapshot.scope, operation="counter.add",
        command={"amount": 1}, expected_version=1, idempotency_key="legacy-key",
        commit_attempt_id=uuid4(), now=now,
    )
    assert old.status == "committed"
    source = CommitSource(world_generation_id=snapshot.scope.world_generation_id,
                          operation_result_digest=old.result_digest,
                          committed_state_version=old.committed_state_version,
                          committed_state_hash=old.committed_state_hash)
    with pytest.raises(ProtectedGrantError, match="candidate_source_unverifiable"):
        _candidate(isolated_test_dsn, scope=snapshot.scope, source=source,
                   receipt_id=receipt, fingerprint=fingerprint)


def test_world_executor_uses_separate_real_login_and_minimum_acl(isolated_test_dsn):
    """實體 SCRAM 角色證明 Runtime 不能偽造證據，而 Executor 可保留正常業務寫入。"""
    if os.environ.get("MIRAGE_WORLD_ROLE_TEST_ISOLATED") != "true":
        pytest.skip("requires disposable PostgreSQL cluster for login role creation")
    import psycopg
    from psycopg import sql
    from psycopg.conninfo import conninfo_to_dict, make_conninfo

    _, _, binding, snapshot, receipt, fingerprint, now = _trusted_world(isolated_test_dsn)
    suffix = uuid4().hex[:12]
    users = {kind: (f"mirage_world_{kind}_{suffix}", secrets.token_urlsafe(32))
             for kind in ("runtime", "executor")}
    schema = conninfo_to_dict(isolated_test_dsn)["options"].split("search_path=", 1)[1].split(" ", 1)[0]
    with psycopg.connect(isolated_test_dsn, autocommit=True) as admin:
        try:
            for login, password in users.values():
                admin.execute(sql.SQL("CREATE ROLE {} LOGIN NOINHERIT NOSUPERUSER NOCREATEDB "
                                      "NOCREATEROLE NOBYPASSRLS PASSWORD {}").format(
                                          sql.Identifier(login), sql.Literal(password)))
                admin.execute(sql.SQL("GRANT USAGE ON SCHEMA {} TO {}").format(
                    sql.Identifier(schema), sql.Identifier(login)))
            executor_role = sql.Identifier(users["executor"][0])
            admin.execute(sql.SQL("GRANT SELECT ON ingress_receipts,session_heads,session_world_bindings,"
                                  "generation_controls,trusted_key_revocations,world_snapshots,"
                                  "world_operations,protected_world_read_sources,"
                                  "protected_world_commit_sources TO {}").format(executor_role))
            admin.execute(sql.SQL("GRANT UPDATE ON session_heads,session_world_bindings,"
                                  "generation_controls,world_snapshots TO {}").format(executor_role))
            admin.execute(sql.SQL("GRANT INSERT ON read_admissions,protected_world_read_sources,"
                                  "world_operations,world_events,world_commit_receipts,"
                                  "protected_world_commit_sources TO {}").format(executor_role))
            admin.execute(sql.SQL("GRANT EXECUTE ON FUNCTION "
                                  "protected_lock_reference(text,jsonb) TO {}").format(executor_role))
            dsns = {kind: make_conninfo(isolated_test_dsn, user=login, password=password)
                    for kind, (login, password) in users.items()}
            world_store = PostgresEventWorldStore(dsns["executor"],
                handlers={"counter.add": _counter_add}, write_modes={"inventory"})
            protected = PostgresProtectedWorldExecutor(dsns["executor"],
                expected_login=users["executor"][0], world_store=world_store)
            read = protected.admit_read(receipt_id=receipt, binding=binding,
                                       request_fingerprint=fingerprint, expires_at=now + 30)
            assert read.snapshot.scope == snapshot.scope
            result = protected.commit_event(
                receipt_id=receipt, binding=binding, request_fingerprint=fingerprint,
                authorized_scope=snapshot.scope, operation="counter.add",
                command={"amount": 1}, expected_version=1,
                idempotency_key="role-commit", commit_attempt_id=uuid4(),
            )
            assert result.status == "committed"
            with psycopg.connect(dsns["runtime"]) as connection:
                with pytest.raises(psycopg.errors.InsufficientPrivilege):
                    connection.execute("INSERT INTO protected_world_read_sources(read_admission_id) "
                                       "VALUES ('forged')")
            with psycopg.connect(dsns["runtime"]) as connection:
                with pytest.raises(psycopg.errors.InsufficientPrivilege):
                    connection.execute(sql.SQL("SET ROLE {}").format(executor_role))
        finally:
            for login, _ in users.values():
                admin.execute(sql.SQL("DROP OWNED BY {}").format(sql.Identifier(login)))
                admin.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(login)))
