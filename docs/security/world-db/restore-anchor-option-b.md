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

## 2026-11-24 one-time Oracle Arm64 lab preflight — bounded PASS, G5 OPEN

On `msdss-oracle-arm64-test`, authenticated Gateway sudo access inspected two **already
existing** `postgres:17.6-alpine` containers:
`mir-sec-world001-pg` (World Lab, separate `mir-sec-world001-pgdata` volume,
`mir_sec_owner` login) and `mir-sec-world001-fence-pg` (Fence Lab, separate
`mir-sec-world001-fence-data` volume, `fence_admin` login). Both use the dedicated
Lab Docker network, not a staging network. This proves distinct PostgreSQL
instances, physical data volumes and admin logins, **not** credential invisibility
to a malicious host root or a deployed independent checkpoint authority.

A temporary `mir_g5_oneoff_20261124` schema was created in each **Lab database
only**. Test records advanced World and independent Fence to sequence 2, with
SHA-256 digests and a previous-record hash. The test then removed sequence 2
**only from the temporary World probe table**, simulating a rollback to sequence 1.
Fence still reported sequence 2, its one-step hash chain verified, and an external
comparison failed closed:

```text
G5_ONEOFF WORLD_HEAD=1 FENCE_HEAD=2 QUARANTINE_REQUIRED=YES
```

Gateway evidence: cross-DB comparison job `job_01M85VFNS30025JTG3PT9CA5RQ`
(exit 0).
One-time schemas were then deleted from both Lab databases and verified absent:
Fence cleanup job `job_01M85VGH3S001KMJ813MW7NCYQ`, World cleanup job
`job_01M85VG8CP00DHMPWRFWD81SN9`. No existing app tables, containers,
Docker volumes or staging/production resources were modified or removed.

**Acceptance boundary:** this is a physical-isolation and rollback-*simulation*
preflight only, not `RESTORE-ANCHOR-01` through `06` acceptance. No actual World
DB backup/restore, durable publication protocol with external highest-head
anti-replay trust, independent publisher ACL, checkpoint coverage proof,
crash-window reconciliation, release certificate, active Sender or Purge race
was exercised. The lab comparison must not be treated as an implemented runtime
quarantine guard, a production Anchor, or authorization to lift the Release Fuse.

## Deployment guardrails

Use only the dedicated `mir-sec-world001-lab` resources for implementation and tests. Do not attach the existing staging networks, restart the seven existing containers, reuse production secrets, merge the Draft PR, or enable trusted send.

Decision: **Option B approved**. Implementation: **IN PROGRESS**. G5: **NOT RUN**. MIR-SEC-WORLD-001: **OPEN**. MSDSS P2: **NO-GO**.
