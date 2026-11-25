"""G5 第二個實體 PostgreSQL 的簽章 Anchor 發布／讀取與隔離 ACL 子驗收。"""

from dataclasses import replace
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import os
import secrets
from uuid import uuid4

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import psycopg
from psycopg import sql
import pytest

from deception.world.postgres_restore_anchor import PostgresAnchorPublisher, PostgresAnchorHeadReader
from deception.world.restore_anchor import (
    RestoreAnchorError, SignedAnchorCheckpoint, verify_restore_anchor,
)


def _public(key: Ed25519PrivateKey) -> bytes:
    """提供驗章用途的原生 Ed25519 公鑰，私鑰只存在測試程序。"""
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw,
    )


def _checkpoint(key: Ed25519PrivateKey, *, namespace: str, sequence: int,
                prior: str, first: int, last: int,
                epoch: str = "epoch-test") -> SignedAnchorCheckpoint:
    """建立簽章有效且具有事件範圍的單一測試 Checkpoint。"""
    unsigned = SignedAnchorCheckpoint(
        namespace=namespace, epoch=epoch, sequence=sequence,
        previous_digest=prior, world_digest=f"{sequence:064x}",
        events_digest=f"{sequence + 100:064x}", first_event=first,
        last_event=last, publication_id=f"publication-{sequence}",
        status="COMMITTED", signature=bytes(64),
    )
    return replace(unsigned, signature=key.sign(unsigned.payload()))


@pytest.fixture(scope="module")
def fence_lab():
    """只在第二個一次性 PG 服務建立臨時 Schema 與三個實體無繼承 SCRAM Login。"""
    admin_dsn = os.environ.get("MIRAGE_G5_FENCE_TEST_DSN")
    if not admin_dsn:
        pytest.skip("requires separate MIRAGE_G5_FENCE_TEST_DSN")
    suffix = uuid4().hex[:12]
    roles = {kind: f"g5_{kind}_{suffix}" for kind in ("publisher", "reader", "runtime")}
    passwords = {kind: secrets.token_urlsafe(32) for kind in roles}
    with psycopg.connect(admin_dsn, autocommit=True) as admin:
        # 專用 ephemeral database 第一次啟動時，Schema 不得已有另一份資料。
        assert admin.execute(
            "SELECT to_regnamespace('mirage_restore_fence')"
        ).fetchone()[0] is None
        ddl = (Path(__file__).parents[1] / "deploy/security-lab/g5-fence-schema.sql").read_text()
        admin.execute(ddl)
        for kind, role in roles.items():
            admin.execute(sql.SQL("CREATE ROLE {} LOGIN NOINHERIT NOSUPERUSER NOCREATEDB "
                                  "NOCREATEROLE PASSWORD {}").format(
                                      sql.Identifier(role), sql.Literal(passwords[kind])))
        for kind in ("publisher", "reader"):
            admin.execute(sql.SQL("GRANT USAGE ON SCHEMA mirage_restore_fence TO {}").format(
                sql.Identifier(roles[kind])))
            admin.execute(sql.SQL("GRANT SELECT ON mirage_restore_fence.authority_epochs TO {}").format(
                sql.Identifier(roles[kind])))
        admin.execute(sql.SQL("GRANT SELECT ON mirage_restore_fence.checkpoints, "
                              "mirage_restore_fence.heads TO {}, {}").format(
                                  sql.Identifier(roles["publisher"]), sql.Identifier(roles["reader"])))
        admin.execute(sql.SQL("GRANT INSERT ON mirage_restore_fence.checkpoints, "
                              "mirage_restore_fence.heads TO {}").format(
                                  sql.Identifier(roles["publisher"])))
        admin.execute(sql.SQL("GRANT UPDATE ON mirage_restore_fence.heads TO {}").format(
            sql.Identifier(roles["publisher"])))
    dsns = {kind: psycopg.conninfo.make_conninfo(admin_dsn, user=roles[kind],
                                                password=passwords[kind]) for kind in roles}
    dsns["admin"] = admin_dsn
    try:
        yield dsns, roles
    finally:
        with psycopg.connect(admin_dsn, autocommit=True) as admin:
            admin.execute("DROP SCHEMA mirage_restore_fence CASCADE")
            for role in roles.values():
                admin.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(role)))


def _register_authority(dsns: dict, namespace: str, *, epoch: str = "epoch-test",
                        generation: int = 1) -> None:
    """只由獨立管理者在 Fence DB 追加目前權威世代，絕不從 World 複製。"""
    with psycopg.connect(dsns["admin"], autocommit=True) as admin:
        admin.execute(
            "INSERT INTO mirage_restore_fence.authority_epochs "
            "(namespace,generation,epoch) VALUES (%s,%s,%s)",
            (namespace, generation, epoch),
        )


def test_fence_lab_persists_latest_head_and_rejects_restored_world_rollback(fence_lab):
    """真第二個 PostgreSQL 保留更新 Head；回退 World 的歷史摘要只能判為落後。"""
    dsns, roles = fence_lab
    namespace = f"isolated-{uuid4().hex}"
    _register_authority(dsns, namespace)
    publisher_key, head_key = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    publisher = PostgresAnchorPublisher(
        dsns["publisher"], expected_login=roles["publisher"],
        trusted_namespace=namespace, trusted_epoch="epoch-test",
        publisher_public_key=_public(publisher_key))
    reader = PostgresAnchorHeadReader(dsns["reader"], expected_login=roles["reader"],
                                      trusted_namespace=namespace, trusted_epoch="epoch-test",
                                      head_private_key=head_key)
    first = _checkpoint(publisher_key, namespace=namespace, sequence=1,
                        prior="0" * 64, first=1, last=3)
    second = _checkpoint(publisher_key, namespace=namespace, sequence=2,
                         prior=first.chain_digest(), first=4, last=7)
    assert publisher.append(first) == first.chain_digest()
    assert publisher.append(second) == second.chain_digest()
    args = dict(reader=reader, namespace=namespace, epoch="epoch-test",
                publisher_public_key=_public(publisher_key), head_public_key=_public(head_key))
    behind = verify_restore_anchor(restored_sequence=1,
                                   restored_world_digest=first.world_digest, **args)
    assert behind.state == "RESTORE_BEHIND" and not behind.release_authorized
    matched = verify_restore_anchor(restored_sequence=2,
                                    restored_world_digest=second.world_digest, **args)
    assert matched.state == "HEAD_MATCHED" and not matched.release_authorized


def test_fence_lab_refuses_replay_gap_signature_and_direct_mutation(fence_lab):
    """重送、事件缺口、錯簽章與 SQL 直接改寫不可推進最高 Head。"""
    dsns, roles = fence_lab
    namespace = f"isolated-{uuid4().hex}"
    _register_authority(dsns, namespace)
    publisher_key = Ed25519PrivateKey.generate()
    publisher = PostgresAnchorPublisher(
        dsns["publisher"], expected_login=roles["publisher"],
        trusted_namespace=namespace, trusted_epoch="epoch-test",
        publisher_public_key=_public(publisher_key))
    first = _checkpoint(publisher_key, namespace=namespace, sequence=1,
                        prior="0" * 64, first=1, last=3)
    assert publisher.append(first) == first.chain_digest()
    with pytest.raises(RestoreAnchorError, match="sequence_or_coverage"):
        publisher.append(first)
    gap = _checkpoint(publisher_key, namespace=namespace, sequence=2,
                      prior=first.chain_digest(), first=5, last=7)
    with pytest.raises(RestoreAnchorError, match="sequence_or_coverage"):
        publisher.append(gap)
    invalid = _checkpoint(publisher_key, namespace=namespace, sequence=2,
                          prior=first.chain_digest(), first=4, last=7)
    with pytest.raises(RestoreAnchorError, match="signature_invalid"):
        publisher.append(replace(invalid, signature=bytes(64)))
    with psycopg.connect(dsns["publisher"]) as conn:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute("UPDATE mirage_restore_fence.checkpoints SET world_digest=%s "
                         "WHERE namespace=%s", ("f" * 64, namespace))
    with psycopg.connect(dsns["runtime"]) as conn:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute("SELECT * FROM mirage_restore_fence.heads")
    with psycopg.connect(dsns["publisher"]) as conn:
        assert conn.execute("SELECT sequence FROM mirage_restore_fence.heads "
                            "WHERE namespace=%s", (namespace,)).fetchone()[0] == 1


def test_fence_lab_reader_cannot_write_or_forge_latest_head(fence_lab):
    """Head Reader 的真 SCRAM 角色只有 SELECT，簽錯的 Head 金鑰不能通過驗證。"""
    dsns, roles = fence_lab
    namespace = f"isolated-{uuid4().hex}"
    _register_authority(dsns, namespace)
    publisher_key, head_key = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    publisher = PostgresAnchorPublisher(
        dsns["publisher"], expected_login=roles["publisher"],
        trusted_namespace=namespace, trusted_epoch="epoch-test",
        publisher_public_key=_public(publisher_key))
    first = _checkpoint(publisher_key, namespace=namespace, sequence=1,
                        prior="0" * 64, first=1, last=3)
    publisher.append(first)
    with psycopg.connect(dsns["reader"]) as conn:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute("DELETE FROM mirage_restore_fence.checkpoints WHERE namespace=%s",
                         (namespace,))
    reader = PostgresAnchorHeadReader(dsns["reader"], expected_login=roles["reader"],
                                      trusted_namespace=namespace, trusted_epoch="epoch-test",
                                      head_private_key=head_key)
    with pytest.raises(RestoreAnchorError):
        verify_restore_anchor(
            reader=reader, namespace=namespace, epoch="epoch-test", restored_sequence=1,
            restored_world_digest=first.world_digest, publisher_public_key=_public(publisher_key),
            head_public_key=_public(Ed25519PrivateKey.generate()),
        )


def test_fence_lab_publisher_cannot_advance_head_without_linked_checkpoint(fence_lab):
    """Even the Publisher's legitimate UPDATE grant cannot forge Head progress."""
    dsns, roles = fence_lab
    namespace = f"isolated-{uuid4().hex}"
    _register_authority(dsns, namespace)
    key = Ed25519PrivateKey.generate()
    publisher = PostgresAnchorPublisher(
        dsns["publisher"], expected_login=roles["publisher"],
        trusted_namespace=namespace, trusted_epoch="epoch-test",
        publisher_public_key=_public(key),
    )
    first = _checkpoint(key, namespace=namespace, sequence=1,
                        prior="0" * 64, first=1, last=3)

    # A Head without an immutable first checkpoint must not even be created.
    with psycopg.connect(dsns["publisher"]) as conn:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute(
                "INSERT INTO mirage_restore_fence.heads "
                "(namespace,epoch,sequence,checkpoint_digest) VALUES (%s,%s,1,%s)",
                (namespace, "epoch-test", "f" * 64),
            )
    assert publisher.append(first) == first.chain_digest()

    # A sequence increment by itself cannot reference a nonexistent chain link.
    with psycopg.connect(dsns["publisher"]) as conn:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute(
                "UPDATE mirage_restore_fence.heads "
                "SET sequence=2,checkpoint_digest=%s WHERE namespace=%s",
                ("f" * 64, namespace),
            )

    # Direct SQL may append a syntactically valid signed checkpoint with a bad
    # predecessor; the database must reject promoting that orphan to Head.
    orphan = _checkpoint(key, namespace=namespace, sequence=2,
                         prior="e" * 64, first=4, last=5)
    with psycopg.connect(dsns["publisher"]) as conn:
        conn.execute(
            """INSERT INTO mirage_restore_fence.checkpoints (
                   namespace,epoch,sequence,previous_digest,world_digest,events_digest,
                   first_event,last_event,publication_id,status,signature,checkpoint_digest)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
            (orphan.namespace, orphan.epoch, orphan.sequence, orphan.previous_digest,
             orphan.world_digest, orphan.events_digest, orphan.first_event,
             orphan.last_event, orphan.publication_id, orphan.status,
             orphan.signature, orphan.chain_digest()),
        )
    with psycopg.connect(dsns["publisher"]) as conn:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute(
                "UPDATE mirage_restore_fence.heads "
                "SET sequence=2,checkpoint_digest=%s WHERE namespace=%s",
                (orphan.chain_digest(), namespace),
            )
    with psycopg.connect(dsns["reader"]) as conn:
        assert conn.execute(
            "SELECT sequence,checkpoint_digest FROM mirage_restore_fence.heads "
            "WHERE namespace=%s", (namespace,),
        ).fetchone() == (1, first.chain_digest())


def test_fence_lab_two_publishers_compete_for_one_next_head(fence_lab):
    """兩個獨立 DB 連線同時發布同一下一節，只能成功一次且無重複 Ledger。"""
    dsns, roles = fence_lab
    namespace = f"isolated-{uuid4().hex}"
    _register_authority(dsns, namespace)
    publisher_key = Ed25519PrivateKey.generate()
    publisher = PostgresAnchorPublisher(
        dsns["publisher"], expected_login=roles["publisher"],
        trusted_namespace=namespace, trusted_epoch="epoch-test",
        publisher_public_key=_public(publisher_key))
    first = _checkpoint(publisher_key, namespace=namespace, sequence=1,
                        prior="0" * 64, first=1, last=3)
    second = _checkpoint(publisher_key, namespace=namespace, sequence=2,
                         prior=first.chain_digest(), first=4, last=7)
    assert publisher.append(first) == first.chain_digest()

    def attempt():
        """以獨立連線競爭同一固定下一個 Head，不盲目 retry 不明結果。"""
        try:
            return publisher.append(second)
        except RestoreAnchorError:
            return "refused"

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(lambda _: attempt(), range(2)))
    assert sorted(outcomes) == [second.chain_digest(), "refused"]
    with psycopg.connect(dsns["reader"]) as conn:
        assert conn.execute("SELECT count(*) FROM mirage_restore_fence.checkpoints "
                            "WHERE namespace=%s", (namespace,)).fetchone()[0] == 2
        assert conn.execute("SELECT sequence,checkpoint_digest FROM mirage_restore_fence.heads "
                            "WHERE namespace=%s", (namespace,)).fetchone() == (
                                2, second.chain_digest())


def test_fence_lab_independent_epoch_rollover_retires_old_signed_head(fence_lab):
    """獨立 DBA 世代追加後，原本簽章有效的舊 Head 不再可簽、讀或續寫。"""
    dsns, roles = fence_lab
    namespace = f"isolated-{uuid4().hex}"
    _register_authority(dsns, namespace)
    publisher_key, head_key = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    old_publisher = PostgresAnchorPublisher(
        dsns["publisher"], expected_login=roles["publisher"],
        trusted_namespace=namespace, trusted_epoch="epoch-test",
        publisher_public_key=_public(publisher_key),
    )
    old_reader = PostgresAnchorHeadReader(
        dsns["reader"], expected_login=roles["reader"],
        trusted_namespace=namespace, trusted_epoch="epoch-test",
        head_private_key=head_key,
    )
    first = _checkpoint(publisher_key, namespace=namespace, sequence=1,
                        prior="0" * 64, first=1, last=3)
    old_publisher.append(first)
    assert old_reader.observe_head(namespace, "epoch-test", b"a" * 32).sequence == 1

    _register_authority(dsns, namespace, epoch="epoch-next", generation=2)
    second_old = _checkpoint(publisher_key, namespace=namespace, sequence=2,
                             prior=first.chain_digest(), first=4, last=5)
    with pytest.raises(RestoreAnchorError, match="publisher_epoch_retired"):
        old_publisher.append(second_old)
    with pytest.raises(RestoreAnchorError, match="publisher_epoch_retired"):
        old_publisher.confirm_committed(first)
    with pytest.raises(RestoreAnchorError, match="head_missing"):
        old_reader.observe_head(namespace, "epoch-test", b"b" * 32)
    with pytest.raises(RestoreAnchorError, match="checkpoint_missing_or_epoch_retired"):
        old_reader.read_checkpoints(namespace, "epoch-test", 1, 1)

    new_publisher = PostgresAnchorPublisher(
        dsns["publisher"], expected_login=roles["publisher"],
        trusted_namespace=namespace, trusted_epoch="epoch-next",
        publisher_public_key=_public(publisher_key),
    )
    new_reader = PostgresAnchorHeadReader(
        dsns["reader"], expected_login=roles["reader"],
        trusted_namespace=namespace, trusted_epoch="epoch-next",
        head_private_key=head_key,
    )
    new_first = _checkpoint(publisher_key, namespace=namespace, epoch="epoch-next",
                            sequence=1, prior="0" * 64, first=1, last=2)
    assert new_publisher.append(new_first) == new_first.chain_digest()
    assert new_reader.observe_head(namespace, "epoch-next", b"c" * 32).sequence == 1
    assert new_reader.read_checkpoints(namespace, "epoch-next", 1, 1) == [new_first]

    with psycopg.connect(dsns["publisher"]) as connection:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            connection.execute(
                "INSERT INTO mirage_restore_fence.authority_epochs VALUES (%s,3,%s)",
                (namespace, "publisher-forged"),
            )
    with psycopg.connect(dsns["admin"]) as connection:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            connection.execute(
                "UPDATE mirage_restore_fence.authority_epochs SET epoch=%s "
                "WHERE namespace=%s", ("old-epoch", namespace),
            )
    with psycopg.connect(dsns["admin"]) as connection:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            connection.execute(
                "INSERT INTO mirage_restore_fence.authority_epochs VALUES (%s,4,%s)",
                (namespace, "skipped-generation"),
            )


def test_fence_lab_lost_commit_ack_fails_closed_and_does_not_republish(
    fence_lab, monkeypatch,
):
    """真 PG COMMIT 成功但回覆遺失時，回報固定失敗且不重寫同一鏈節。"""
    from deception.world import postgres_restore_anchor as anchor_module

    dsns, roles = fence_lab
    namespace = f"isolated-{uuid4().hex}"
    _register_authority(dsns, namespace)
    key = Ed25519PrivateKey.generate()
    publisher = PostgresAnchorPublisher(
        dsns["publisher"], expected_login=roles["publisher"],
        trusted_namespace=namespace, trusted_epoch="epoch-test",
        publisher_public_key=_public(key),
    )
    first = _checkpoint(key, namespace=namespace, sequence=1,
                        prior="0" * 64, first=1, last=3)
    second = _checkpoint(key, namespace=namespace, sequence=2,
                         prior=first.chain_digest(), first=4, last=5)
    real_connect = psycopg.connect

    class DropCommittedAck:
        """只將測試連線的真 COMMIT 回覆改為遺失，不攔截資料庫寫入。"""

        def __init__(self, connection):
            """持有單一已建立的真 PostgreSQL 連線。"""
            self.connection = connection

        def __enter__(self):
            """原封不動進入真正的 psycopg 交易。"""
            return self.connection.__enter__()

        def __exit__(self, error_type, error, traceback):
            """先由 psycopg 真提交，再丟棄觀察者收到的 ACK。"""
            result = self.connection.__exit__(error_type, error, traceback)
            if error_type is None:
                raise OSError("synthetic_commit_ack_lost")
            return result

    def lost_ack_connect(*args, **kwargs):
        """僅在一次 Publisher append 呼叫中包裝連線。"""
        return DropCommittedAck(real_connect(*args, **kwargs))

    with monkeypatch.context() as patcher:
        patcher.setattr(anchor_module.psycopg, "connect", lost_ack_connect)
        with pytest.raises(RestoreAnchorError, match="publish_unverifiable"):
            publisher.append(first)

    with psycopg.connect(dsns["reader"]) as connection:
        assert connection.execute(
            "SELECT sequence,checkpoint_digest FROM mirage_restore_fence.heads "
            "WHERE namespace=%s", (namespace,),
        ).fetchone() == (1, first.chain_digest())
        assert connection.execute(
            "SELECT count(*) FROM mirage_restore_fence.checkpoints WHERE namespace=%s",
            (namespace,),
        ).fetchone()[0] == 1
    assert publisher.confirm_committed(first) == first.chain_digest()
    with pytest.raises(RestoreAnchorError, match="publication_unresolved"):
        publisher.confirm_committed(second)
    with pytest.raises(RestoreAnchorError, match="sequence_or_coverage"):
        publisher.append(first)
    assert publisher.append(second) == second.chain_digest()
    assert publisher.confirm_committed(second) == second.chain_digest()
    # 後續 Head 已前進，舊出版證據仍須能由不可改寫鏈節獨立確認。
    assert publisher.confirm_committed(first) == first.chain_digest()


def test_fence_lab_publication_reconcile_rejects_conflict_and_orphan(fence_lab):
    """真 Fence DB 已存在同 Publication 的不同簽章內容或無 Head 時不能算 COMMIT。"""
    dsns, roles = fence_lab
    namespace = f"isolated-{uuid4().hex}"
    _register_authority(dsns, namespace)
    key = Ed25519PrivateKey.generate()
    publisher = PostgresAnchorPublisher(
        dsns["publisher"], expected_login=roles["publisher"],
        trusted_namespace=namespace, trusted_epoch="epoch-test",
        publisher_public_key=_public(key),
    )
    first = _checkpoint(key, namespace=namespace, sequence=1,
                        prior="0" * 64, first=1, last=3)
    assert publisher.append(first) == first.chain_digest()
    changed_unsigned = replace(first, world_digest="f" * 64, signature=bytes(64))
    conflicting = replace(changed_unsigned, signature=key.sign(changed_unsigned.payload()))
    with pytest.raises(RestoreAnchorError, match="publication_conflict"):
        publisher.confirm_committed(conflicting)

    orphan_namespace = f"isolated-{uuid4().hex}"
    _register_authority(dsns, orphan_namespace)
    orphan_publisher = PostgresAnchorPublisher(
        dsns["publisher"], expected_login=roles["publisher"],
        trusted_namespace=orphan_namespace, trusted_epoch="epoch-test",
        publisher_public_key=_public(key),
    )
    orphan = _checkpoint(key, namespace=orphan_namespace, sequence=1,
                         prior="0" * 64, first=1, last=3)
    with psycopg.connect(dsns["admin"], autocommit=True) as admin:
        admin.execute(
            "INSERT INTO mirage_restore_fence.checkpoints "
            "(namespace,epoch,sequence,previous_digest,world_digest,events_digest,"
            " first_event,last_event,publication_id,status,signature,checkpoint_digest) "
            "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
            (orphan.namespace, orphan.epoch, orphan.sequence, orphan.previous_digest,
             orphan.world_digest, orphan.events_digest, orphan.first_event,
             orphan.last_event, orphan.publication_id, orphan.status,
             orphan.signature, orphan.chain_digest()),
        )
    with pytest.raises(RestoreAnchorError, match="publication_unresolved"):
        orphan_publisher.confirm_committed(orphan)


def test_fence_publication_confirmation_never_trusts_unverified_input_or_network(monkeypatch):
    """錯簽章須在查庫前拒絕；合法簽章遇 Fence 網路故障只能維持 Unknown。"""
    from deception.world import postgres_restore_anchor as anchor_module

    key = Ed25519PrivateKey.generate()
    publisher = PostgresAnchorPublisher(
        "postgresql://unreachable.invalid/not-used", expected_login="fence_publisher",
        trusted_namespace="isolated-test", trusted_epoch="epoch-test",
        publisher_public_key=_public(key),
    )
    valid = _checkpoint(key, namespace="isolated-test", sequence=1,
                        prior="0" * 64, first=1, last=3)

    def reject_connection(*args, **kwargs):
        """測試所有不被簽章前置檢查拒絕的情況，一律不能從網路讀取成功。"""
        raise OSError("synthetic_fence_connection_lost")

    monkeypatch.setattr(anchor_module.psycopg, "connect", reject_connection)
    with pytest.raises(RestoreAnchorError, match="publisher_signature_invalid"):
        publisher.confirm_committed(replace(valid, signature=bytes(64)))
    with pytest.raises(RestoreAnchorError, match="publication_unverifiable"):
        publisher.confirm_committed(valid)


def test_fence_head_transport_oserror_is_fail_closed(monkeypatch):
    """Head Authority 連線中斷必須回傳固定不可驗證錯誤，不能宣告安全復原。"""
    from deception.world import postgres_restore_anchor as anchor_module

    reader = PostgresAnchorHeadReader(
        "postgresql://unreachable.invalid/not-used", expected_login="fence_reader",
        trusted_namespace="isolated-test", trusted_epoch="epoch-test",
        head_private_key=Ed25519PrivateKey.generate(),
    )

    def fail_connection(*args, **kwargs):
        """在任何真實網路連線前模擬底層 Transport OSError。"""
        raise OSError("synthetic_fence_network_failure")

    monkeypatch.setattr(anchor_module.psycopg, "connect", fail_connection)
    with pytest.raises(RestoreAnchorError, match="head_unverifiable"):
        reader.observe_head("isolated-test", "epoch-test", b"x" * 32)


def test_fence_authority_rejects_restored_epoch_and_namespace_before_database(monkeypatch):
    """舊 World 傳來的 epoch/namespace 不能誘使獨立 Head 簽章或 Publisher 寫鏈。"""
    namespace = "deployed-namespace"
    epoch = "deployed-epoch"
    publisher_key, head_key = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    reader = PostgresAnchorHeadReader(
        "postgresql://unreachable.invalid/not-used", expected_login="fence_reader",
        trusted_namespace=namespace, trusted_epoch=epoch, head_private_key=head_key,
    )
    publisher = PostgresAnchorPublisher(
        "postgresql://unreachable.invalid/not-used", expected_login="fence_publisher",
        trusted_namespace=namespace, trusted_epoch=epoch,
        publisher_public_key=_public(publisher_key),
    )
    queried = []

    def observed_query(statement, args):
        """以不連線的可信 Head 模擬正常唯讀查詢，核對拒絕是否在查詢前。"""
        queried.append(args)
        return [(1, "a" * 64)]

    monkeypatch.setattr(reader, "_query", observed_query)
    valid = reader.observe_head(namespace, epoch, b"x" * 32)
    head_key.public_key().verify(valid.signature, valid.payload())
    assert queried == [(namespace, namespace, epoch)]

    for bad_namespace, bad_epoch in (("retired-namespace", epoch),
                                     (namespace, "retired-epoch")):
        with pytest.raises(RestoreAnchorError, match="head_scope_mismatch"):
            reader.observe_head(bad_namespace, bad_epoch, b"y" * 32)
        with pytest.raises(RestoreAnchorError, match="head_scope_mismatch"):
            reader.read_checkpoints(bad_namespace, bad_epoch, 1, 1)
    assert queried == [(namespace, namespace, epoch)]

    retired_epoch = _checkpoint(
        publisher_key, namespace=namespace, epoch="retired-epoch", sequence=1,
        prior="0" * 64, first=1, last=3,
    )
    retired_namespace = _checkpoint(
        publisher_key, namespace="retired-namespace", epoch=epoch, sequence=1,
        prior="0" * 64, first=1, last=3,
    )
    with pytest.raises(RestoreAnchorError, match="publisher_scope_mismatch"):
        publisher.append(retired_epoch)
    with pytest.raises(RestoreAnchorError, match="publisher_scope_mismatch"):
        publisher.append(retired_namespace)


def test_fence_authority_requires_pinned_deployment_scope():
    """獨立權威啟動若沒有明確釘選 namespace/epoch，直接拒絕服務。"""
    key = Ed25519PrivateKey.generate()
    for invalid_scope in ("", "../restored", "bad namespace"):
        with pytest.raises(RestoreAnchorError, match="publisher_config_invalid"):
            PostgresAnchorPublisher(
                "postgresql://unused/not-used", expected_login="fence_publisher",
                trusted_namespace="deployed", trusted_epoch=invalid_scope,
                publisher_public_key=_public(key),
            )
        with pytest.raises(RestoreAnchorError, match="head_config_invalid"):
            PostgresAnchorHeadReader(
                "postgresql://unused/not-used", expected_login="fence_reader",
                trusted_namespace=invalid_scope, trusted_epoch="deployed",
                head_private_key=key,
            )
