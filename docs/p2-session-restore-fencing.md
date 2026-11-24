# Mirage Session epoch: single-host disaster-restore retirement

**Status:** proposed native safety guard for Mirage Owner review. This does
not enable DECEIVE and must not trigger database migrations or change staging.

The ordinary Session epoch implementation is monotonic per trusted Session ID,
with a row-locked session_heads entry. An incident restore from a stale backup
may roll that head and its Generation/Emergency/Send Authorization controls
backward. Operators may then retire **all restored Session IDs** by setting
session_heads.session_epoch to the PostgreSQL BIGINT maximum
(9223372036854775807) while the restored database is OFFLINE.

Before this change, a new signed binding claiming exactly that BIGINT value
could be accepted by PostgresSessionWorlds.resolve() and create a new
Generation. A retired Session ID must instead **fail closed**, regardless of
whether its presented epoch was older than or equal to the reserved value.
The runtime reserves this value in _binding_params and rejects a head
already at this value inside the same transaction's FOR UPDATE row lock.

This is **not** ordinary Emergency Revocation. The normal Protocol Freeze
still permits already-committed SEND_AUTHORIZED to progress within its
transmission_deadline. Incident restoration instead occurs with old workers
stopped and all production deception disabled: unstarted legacy admissions
must be quarantined before any replacement workers can connect.
Previously SEND_STARTED content may already have reached ASGI; its outcome
must not be silently rewritten as safe or completed.

The Session retirement guard does **not** restore post-backup trusted-key
revocations, JWS replay entries, profile emergency tombstones or the
independent original AttackAssessment ledger. A recovery must separately
quarantine those stores, rotate deployment/signer identity and obtain owner
approval before accepting new trusted deception traffic.

Verification:
- Native no-DB test: test_session_worlds.py::test_reserved_recovery_epoch_is_always_refused_without_database.
- 外部判定服務 isolated PostgreSQL acceptance: 7/7 World/Session/Admission tests
  including a real T0 backup, T1 emergency + epoch advance + start_send, T2
  offline restore, and forged reserved-epoch rejection.
- All code and patch for review remain in Draft PRs. Never apply the
  test-only quarantine SQL to a live/staging database.
