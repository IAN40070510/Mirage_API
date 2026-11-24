# BD-11 — Deadline decision (owner adopted, 2026-11-21)

> 本文件以 Mirage 原生授權契約為維護範圍。歷史跨專案整合證據已移交保存，原生安全要求與驗收狀態維持原紀錄。

**Decision: Option A — authoritative deadline check time controls eligibility; SEND_AUTHORIZED COMMIT controls authorization effect.**

This decision belongs to Mirage Protocol Freeze v1 and does not authorize enabling trusted send.

## Normative behavior

1. After acquiring the protected authorization locks, the Authorizer MUST evaluate the deadline using authoritative PostgreSQL time (`clock_timestamp()`), not an application-supplied clock or an earlier transaction-start timestamp.
2. If the deadline has passed **at that locked check**, authorization MUST fail closed. For an unexpired deadline, the transaction may COMMIT after the deadline; successful COMMIT is the authorization linearization point, not a retroactive deadline evaluation.
3. If the transaction aborts, there is no authorization. If the COMMIT outcome is unknown, the caller MUST reconcile durable operation identity and authorization state before retrying; it MUST NOT assume rollback or create another authorization.
4. `StartSend` independently enforces its execution deadline, owner identity, single-use and authorized immutable Snapshot execution eligibility. A valid authorization does **not** grant unlimited time to start transport.
5. `StartSend` does not re-evaluate Policy/Emergency to revoke an already committed Freeze v1 authorization. This decision does not weaken separate execution-eligibility checks or the Restore Quarantine and Purge Fence.
6. Every deadline race test MUST include a clock crossing between the protected check and COMMIT, a deadline already expired at the protected check, and an unknown COMMIT acknowledgement.
7. Until protected Authorizer implementation and PostgreSQL integration tests establish these semantics, BD-11 is **DECIDED**, not **IMPLEMENTED** or **ACCEPTED**.

## Illustrative race

- Deadline: `12:00:00`
- Locked PostgreSQL check: `11:59:59` (eligible)
- Successful COMMIT: `12:00:01` (authorization takes effect)
- `StartSend` at `12:00:02`: independently rejected if its execution deadline has elapsed.

**MIR-SEC-WORLD-001 OPEN · G3/G6 NOT RUN · Mirage release NO-GO · Production trusted send OFF.**
