# Restore Anchor Option B — approved security contract (2026-11-21)

Status: **OWNER APPROVED / IMPLEMENTATION NOT COMPLETE / G5 NOT RUN**.

## Trust boundary

The Restore Anchor MUST be outside the World DB backup and restore domain. Its credentials, write authority, backup and retention policy MUST be independent from World DB Runtime, Verifier and Authorizer credentials. An isolated same-host laboratory store may validate the protocol but does not establish resistance to host-root compromise, host snapshot rollback, or a malicious Docker administrator.

## Required invariants

1. World DB rollback MUST NOT make a previously revoked key, consumed replay JTI, non-retryable operation or purged authorized Snapshot eligible again.
2. Anchor checkpoints MUST bind authority namespace, epoch, monotonically increasing sequence, previous checkpoint digest, World DB evidence digest, protocol version and publication identifier. Hashes alone do not establish freshness: the verifier MUST consult the independent authoritative latest checkpoint.
3. An anchor record MUST NOT be overwritten, deleted, or replaced by Runtime credentials. Only a dedicated checkpoint publisher may append; quarantine release requires a separately authorized operator certificate.
4. Checkpoint publication and World DB COMMIT are not one atomic transaction. Both crash windows MUST have explicit durable intent, reconciliation and fail-closed behavior; an ACK loss MUST NOT be treated as rollback.
5. Restore starts in quarantine. It remains quarantined on missing, stale, conflicting, unavailable or unverifiable anchor evidence, and on unknown commit/publication outcomes. Reconciliation alone MUST NOT authorize a new HTTP transport attempt.
6. Snapshot purge MUST persist the non-retryable fence before deleting bytes and must not race with an active sender without a retention or controlled-abort protocol.
7. Release requires proof of contiguous coverage from the restored checkpoint to the independent latest checkpoint, including revocations, replay tombstones, bindings, send attempts and purge fences. Missing evidence means NO-GO.
8. The Release Fuse and production trusted send remain OFF throughout this work.

## Mandatory acceptance cases (not yet passed)

- RESTORE-ANCHOR-01: rollback World DB while Anchor retains later revocation/JTI/purge checkpoint => quarantine.
- RESTORE-ANCHOR-02: missing, stale, tampered, overwritten or inaccessible Anchor => fail closed.
- RESTORE-ANCHOR-03: crash before/after World DB COMMIT and before/after Anchor publication, including lost ACK => deterministic reconciliation without duplicate authorization.
- RESTORE-ANCHOR-04: Runtime SCRAM identity cannot append, update, delete, truncate, switch role or read publisher secrets.
- RESTORE-ANCHOR-05: verified contiguous coverage and operator release certificate required to exit quarantine.
- RESTORE-ANCHOR-06: restore during concurrent StartSend, active sender and Snapshot purge => no second transport or resurrection.

## Deployment guardrails

Use only the dedicated `mir-sec-world001-lab` resources for implementation and tests. Do not attach the existing staging networks, restart the seven existing containers, reuse production secrets, merge the Draft PR, or enable trusted send.

Decision: **Option B approved**. Implementation: **IN PROGRESS**. G5: **NOT RUN**. MIR-SEC-WORLD-001: **OPEN**. 外部端權限驗收: **NO-GO**.
