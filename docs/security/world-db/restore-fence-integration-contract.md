# Restore Fence integration contract — incomplete implementation

The lab branch now contains `migrations/018_restore_quarantine_fence.sql`, `restore_fence.py`, and `restore_quarantine.py`. These are **isolated building blocks**, not an end-to-end trusted release path.

## Mandatory transaction ordering

1. Restore controller: deny transport externally before restore, lock the namespace fence, enter a strictly newer restore epoch, COMMIT quarantine before loading restored World DB. **The fence must survive a World DB backup restore**; storing the only fence inside the restored database is unsafe. The current migration is a schema prototype, not the final independent deployment.
2. Verifier: run under independent OS/SCRAM credentials, read an independently authenticated Anchor head, reconcile durable publication intents and ambiguous COMMIT/ACK outcomes, and verify all revocation, replay, Grant, Snapshot and Purge evidence. Hold the fence lock or revalidate its revision and the independently observed Anchor head at the release linearization point.
3. Release: only an independently validated complete evidence bundle may invoke the conditional release transition. The current `release_if_reconciled` helper checks revision and outstanding intent rows **but does not validate the complete evidence bundle**. Never expose it to Runtime or treat its success as production authorization.
4. Send/StartSend and Purge: acquire the same namespace fence row lock in the **same PostgreSQL transaction** as their protected transition, and reject if not released. Lock order must be specified and exercised with real concurrent PostgreSQL sessions; no read-then-send outside the fence.
5. Unknown COMMIT/ACK: reconcile by stable publication ID before publishing again. `PENDING` or `PUBLISHED` is unresolved until independently verified and marked `RECONCILED`.
6. A prior PASS, release certificate or operator override cannot replace verification. The earlier experimental operator-certificate helper is not BD-05 policy.

## Required acceptance before G5

- Real PostgreSQL rollback/restore with fence state independently preserved; no old release resurrected.
- Verifier identity isolation, protected DB roles, Anchor outside backup scope and publisher key isolation.
- Restore/StartSend/Purge race, revision ABA, lock ordering and deadlock handling.
- Crash after DB COMMIT before Anchor publication; lost publication ACK; duplicate publication ID.
- Anchor unavailable, tampered, stale, or advanced during verification; quarantine persists.
- Revocation, Replay Tombstone, one-time Grant, immutable Snapshot and Purge Fence reconciliation.
- Proof that a successful release never authorizes transport by itself.

**Status: BD-05 ADOPTED; fence schema/helper unit tests PASS (7); independent verifier, durable transaction reconciliation, production integration and G5 acceptance NOT COMPLETE. MIR-SEC-WORLD-001 OPEN / P2 NO-GO / trusted send OFF.**
