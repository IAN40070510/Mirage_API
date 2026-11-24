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

## 2026-11-24 cryptographic anchor verifier increment — local unit PASS, G5 OPEN

`src/deception/world/restore_anchor.py` adds a fail-closed, **verification-only**
Ed25519 contract with separate pinned Publisher and Head Authority public keys.
The Head Authority must sign fresh 32-byte challenges together with the
independent **latest** namespace/epoch/sequence/digest **before and after** chain
verification; an advancing Head invalidates the comparison. The verifier checks every
checkpoint signature, previous-checkpoint hash, exact event sequence coverage,
unique publication identity, COMMITTED-only state, and the restored World's
digest against its historical checkpoint. An older restored DB receives
`RESTORE_BEHIND`; matching the latest Head receives `HEAD_MATCHED`, but
**neither result permits release** (`release_authorized=False`). Read failure,
missing link, stale/tampered signature, nonce mismatch, PREPARED publication,
or untrusted Head fails closed.

`tests/test_restore_anchor.py` provides nine isolated cryptographic contract
tests (including mismatch, rollback, outage, tampering, replay and coverage
gaps). Local command `PYTHONPATH=src python -m unittest discover -s tests -p
test_restore_anchor.py -v`: **9 passed**, no physical DB/restore/container
involved; GitHub isolated contract CI is configured to retain JUnit separately.
This is **only a code-level subcomponent** and must not be counted as
`RESTORE-ANCHOR-01` through `06` or `RESTORE-RELEASE-01` through `07`.

At fixed code SHA `4be39923bbffb76ded388035cd250517ff732e57`,
[PostgreSQL contract CI 45325688577](https://github.com/IAN40070510/Mirage_API/actions/runs/45325688577)
reported 154 protected PG passes, 5 mTLS passes and **9 separate anchor
cryptography passes**. [Python CI 45325688529](https://github.com/IAN40070510/Mirage_API/actions/runs/45325688529)
reported `1436 passed / 21 skipped / 2 warnings`;
[container CI 45325688534](https://github.com/IAN40070510/Mirage_API/actions/runs/45325688534)
was successful. The skipped cases remain skipped.

To make this enforceable, a subsequent isolated implementation must supply
an independently credentialed durable Publisher and fresh monotonic Head Reader,
with an auditable append-only event ledger that proves completeness (not just
contiguous declared event numbers). It must bind exact restore-epoch/World DB
state, perform two-domain COMMIT/ACK reconciliation and atomic BD-05 quarantine
transitions, and serialize Sender/Purge. The Reader/Head expected epoch and
public keys cannot be supplied by the restored World DB or untrusted Runtime.
No production or staging service is connected to this helper.

## 2026-11-24 actual pg_dump/pg_restore against separate lab Fence — bounded PASS

An additional **host-only disposable test** on `msdss-oracle-arm64-test`
used the existing `mir-sec-world001-pg` World Lab and the separate
`mir-sec-world001-fence-pg` PostgreSQL 17.6 Fence Lab (distinct containers,
data volumes, and administrator logins). It never touched a staging or
production database. Two uniquely named empty World test databases and a
single dedicated Fence schema were created after verifying none existed.

1. In World source test DB, commit event 1 (`REPLAY_CONSUMED`); persist an
   independently calculated SHA-256 state digest in Fence checkpoint 1.
   Jobs `job_01M85WR4RC0020QMDBAJ4GXN43` and
   `job_01M85WRHM700JQ4B44CEX43VW7`.
2. Take a **real PostgreSQL custom-format `pg_dump`** before event 2:
   `job_01M85WSAXP00YZAAVFZDWKA7QB` exited 0; archive SHA-256
   `979bada0cd18b7ec89d9c475c3c3bc9c1ab33f055b330257632812d5a77a68bb`
   from `job_01M85WSNVD00HDBF6WVA7RG75T`.
3. Commit event 2 (`SNAPSHOT_PURGE_FENCE`) **after backup** and append
   Fence checkpoint 2 linked to checkpoint 1. Jobs
   `job_01M85WT4NR00Q59E1H5JRAVVFW` and
   `job_01M85WTH6B009H9MN3PEDXSZ5V`.
4. Run actual `pg_restore --exit-on-error` into a **different empty World
   test database**, job `job_01M85WTW0D00D7K8B84YECRGP3` exit 0.
   Source was sequence 2 / digest `35002ada60aa676b...`, restored was
   sequence 1 / digest `451f92386c058839...`, independently stored
   Fence Head was sequence 2. Fence checkpoint count and SHA-256 previous
   links verified `2|2|t|t`: source/restore/Fence query jobs
   `job_01M85WWE3S00ECZGFH34KH702A`,
   `job_01M85WW3S300FG1FXBH5E1DRGT`,
   `job_01M85WVSDJ006Z2C75SW3G05WS`,
   `job_01M85WVF2Y00RM0V91H3YKV5QC`.
   Comparison result: **`G5_LAB_PGDUMP_RESTORE QUARANTINE_REQUIRED=YES`**.
5. Drop **only** the two one-off databases, one Fence schema, and its archive;
   jobs `job_01M85WX3HX00F3TH0N27RKWYM4`,
   `job_01M85WY0XX00664D6JR1SCBS72`,
   `job_01M85WXPW200G8AP6VMEAJE93W`,
   `job_01M85WXC9E00NPRH55G31WSH8A` all succeeded.
   Independent post-cleanup checks found `0` matching databases,
   `0` matching Fence schemas and no archive: jobs
   `job_01M85WYCYE00DG0P41GKCE1RWX`,
   `job_01M85WYXGG002MRYVMCS3FPRBV`,
   `job_01M85WYN6C00ZTFSE8D0DZFGBP`.

This is stronger than deleting a probe table to simulate rollback: the
restored World contents were actually produced by PostgreSQL backup/restore.
**It is nevertheless a disposable ledger probe**, not a full application
World DB restore or production Anchor. The host SQL probe uses hash chaining,
not the new signed-checkpoint Reader; it has no complete Publisher/Head
credential isolation proof, no signed monotonic freshness protocol, no
real business effects, no crash-window/unknown-ACK reconciliation, and no
BD-05 automated Quarantine transition or Sender/Purge concurrency test.
`RESTORE-ANCHOR-01` through `06` and G5 overall remain **OPEN/NOT_RUN**.

## Deployment guardrails

Use only the dedicated `mir-sec-world001-lab` resources for implementation and tests. Do not attach the existing staging networks, restart the seven existing containers, reuse production secrets, merge the Draft PR, or enable trusted send.

Decision: **Option B approved**. Implementation: **IN PROGRESS**. G5: **NOT RUN**. MIR-SEC-WORLD-001: **OPEN**. MSDSS P2: **NO-GO**.
