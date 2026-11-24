# Independent Fence PostgreSQL lock contention probe — 2026-11-21

## Scope

Isolated container `mir-sec-world001-fence-pg`, independent volume `mir-sec-world001-fence-data`; no production/staging resources modified. This is a **database-level row-lock contention probe**, not an end-to-end Send/Purge/Restore acceptance test.

## Procedure and observed result

1. Insert disposable namespace `lab-lock-test` with `RELEASED` (lab-only fixture; not a verified production release).
2. Session A: `BEGIN; SELECT state FROM restore_quarantine_fences WHERE namespace='lab-lock-test' FOR UPDATE; SELECT pg_sleep(4); COMMIT;`
3. Start session B one second later: `BEGIN; UPDATE restore_quarantine_fences SET state='QUARANTINED', revision=revision+1, verifier_version=NULL, verified_at=NULL WHERE namespace='lab-lock-test'; COMMIT;`
4. Session B completed after **4 seconds measured wall time**, indicating it waited for the row lock held by A. Final readback: `QUARANTINED|1`.

**Result:** independent Fence DB row locking serialized these two database sessions. This does **not** prove that the application sends hold the lock or that a crashed process reconciles a World DB commit.

## Outstanding gates

- Route all trusted Send/StartSend/Purge/Restore paths through the independent Fence; enforce no bypass and least-privilege credentials.
- Prove full transaction lifetime, lock loss, stale state, restore races, and concurrent snapshot purge using real application paths.
- Durable operation identity and reconciliation of ambiguous cross-DB COMMIT/ACK.
- Full independent verifier and evidence-based BD-05 release.
- A lab-only RELEASED fixture must never be treated as an approved restore-release event.

**MIR-SEC-WORLD-001 OPEN / 外部端權限驗收 NO-GO / trusted send OFF.**
