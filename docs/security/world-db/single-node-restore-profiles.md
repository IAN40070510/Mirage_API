# Mirage single-node deployment and optional external Restore Fence — D-74

> Owner product direction: **ACCEPTED 2026-11-25**. Implementation: **PARTIAL — deployment profile configuration preflight only**. Acceptance: **NOT RUN for full feature/security gates**. Release: **NO-GO**; Trusted Send and DECEIVE remain **OFF**.

## Product and threat-model boundary

Mirage is designed for **one deployable host**. Its API, World PostgreSQL, Verifier, Authorizer, Executor, Validator, immutable Authorized Snapshot and Sender must remain fully functional without installing an **external** Restore Fence, once their own independent role, transaction, transport and release tests pass. Separate containers, processes, identities and database roles can share that one host.

The external Fence is an **optional, explicitly selected high-assurance recovery profile**, not an ordinary API startup dependency. A second self-managed VM is not inherently required: an independently administered service outside the World backup/restore domain may supply its authority. Two PostgreSQL containers on the same host are only an isolation lab, not evidence of host-wide anti-rollback.

**Unavoidable limit:** without authority that survives a complete host/disk/VM snapshot rollback, Mirage cannot prove that a consumed replay JTI, revoked credential, external effect key or purged Snapshot did not resurrect when the *entire host* goes back in time. Ordinary single-node functionality is not equivalent to that additional security guarantee. The standard profile must never advertise cross-host/whole-host rollback resistance.

## Explicit deployment profiles (initial configuration preflight implemented; protected transport still sealed)

| Property | `standard_single_node` | `external_fence` |
| --- | --- | --- |
| Hosts required for Mirage service | One | One Mirage host plus independent authority/recovery domain |
| Business APIs and trusted responses after required release gates | Full | Full |
| Ingress Receipt, replay, Grant, immutable Snapshot, Send Lease, Purge and ACL | Mandatory | Mandatory |
| Independent monotonic signed highest Head | Not claimed or required at normal startup | Mandatory; Option B governs it |
| Host-wide snapshot rollback protection | **Not guaranteed; explicitly disclosed** | Must pass all independent Fence/BD-05 tests |
| Unknown send/COMMIT, detected restore and local integrity failures | Fail closed; never blindly replay | Fail closed and reconcile with Fence |
| On configured external authority outage | Not applicable | **Remain quarantined; no silent profile downgrade** |

Profile selection must be explicit, versioned, auditable and startup-verified. `src/deception/security/restore_profile.py` now implements the **configuration-parse subset** at the formal `trusted_http.from_environment()` entrypoint. It validates exact version `1`, rejects unknown modes, requires complete external configuration and different 32-byte Ed25519 public-key pins, and rejects a standard-mode declaration if any `MIRAGE_FENCE_*` setting remains. The formal Trusted HTTP sender Release Fuse remains hard closed. This parsing alone does **not** persist a deployment mode pin, contact the Fence, prove an independent recovery domain, support mode migration, or make Trusted Send operational.

The initial configuration names are:

```dotenv
# Full normal functionality is the intended eventual release target, not currently enabled.
MIRAGE_RESTORE_PROFILE=standard_single_node
MIRAGE_RESTORE_PROFILE_VERSION=1
```

`standard_single_node` requires **no** `MIRAGE_FENCE_*` fields or Fence installation. For the optional mode, set `MIRAGE_RESTORE_PROFILE=external_fence` and provide `MIRAGE_FENCE_AUTHORITY_DSN`, `MIRAGE_FENCE_NAMESPACE`, `MIRAGE_FENCE_EPOCH`, `MIRAGE_FENCE_PUBLISHER_PUBLIC_KEY_FILE`, and `MIRAGE_FENCE_HEAD_PUBLIC_KEY_FILE`. The public-key files currently use lowercase 64-hex-character representations of distinct Ed25519 public keys; their contents, not paths, are digested in the in-memory profile. Keep the DSN and any credentials outside documentation, command logs and images. No external adapter is enabled from these settings yet.

**Known-restore local guard candidate (not release-accepted):** Migration
`030_local_known_restore_quarantine.sql` and `PostgresKnownRestoreRecorder` record
append-only restore-event IDs in the World PostgreSQL. An advisory transaction lock
serializes new Sender Lease creation against event insertion; once an event is
committed, later new leases are denied. The schema/table must exist and the Sender
must have SELECT or starting a lease fails closed. The Recorder only needs
INSERT, and an isolated PostgreSQL SCRAM role test denies its SELECT privilege,
the Sender's INSERT privilege and cross-role SET ROLE. This is a narrowly scoped
single-node mechanism, **not** an external Fence or whole-host rollback detector.
Migration `031_known_restore_lease_db_fence.sql` additionally guards direct
Lease INSERT at PostgreSQL trigger level, so an older Sender that omits the new
Python check cannot commit a fresh Lease after a known event. This mixed-binary
subcase requires independent PostgreSQL CI and does not cover already-started
network sends or unprotected legacy egress paths.
Migration `032_known_restore_trigger_privilege_isolation.sql` pins that no-argument
trigger to a fixed trusted schema under a SECURITY DEFINER function. Thus an old
Sender login need not receive SELECT on the newly introduced event table, but a
spoofed same-name TEMP table cannot hide an actual event. This requires real
least-privilege login, positive legacy SQL and adversarial TEMP-shadow tests.
The deployer must suspend ingress before restore and persist the marker **after**
restoring the database, before reopening Sender; restoring an older DB image after
the marker could erase it. A separate opt-in `restore_bootstrap.py` entrypoint now
verifies this **manual** post-restore marker step under two distinct least-privilege
logins, but there is still no verified **production** release path, startup
orchestrator, or protection against already-started network sends; SINGLE-NODE-03
remains OPEN.

Missing external DSN/secret must not prevent standard single-node **configuration parsing**; configured external mode cannot downgrade to standard because an external field is missing or corrupt. **Remaining security blocker:** a deliberately changed environment that removes *all* external settings is not detectable from an environment-only declaration. An authoritative, durable mode pin outside the World restore domain, guarded transitions, liveness/freshness verification and persistent quarantine are still required before claiming full `SINGLE-NODE-05` or any external assurance. A configured external profile whose authority becomes unavailable MUST remain quarantined, without silent downgrade.

## Standard single-node security acceptance — all mandatory

- **SINGLE-NODE-01:** Install/start all required Mirage business and protected services with no external Fence DSN, keys, network or tables. Confirm full native HTTP 2xx/4xx, World commits and candidate-to-authorized-response flow; no legacy unprotected bypass.
- **SINGLE-NODE-02:** Real PostgreSQL SCRAM/ACL, independent logical roles, protected Receipt, Grant/Binding, immutable Snapshot, single-use StartSend and actual ASGI first-byte/partial/unknown transport; prove unauthorized writes and duplicates are rejected.
- **SINGLE-NODE-03:** Candidate GC, Snapshot Purge, active Send Lease, local crash/restart, World DB rollback/unknown commit, and idempotent reconciliation. A known or detected restore must enter a persistent deny state before further protected sends until the *single-node recovery policy* has verified integrity; absence of external evidence cannot be called a cross-host proof.
- **SINGLE-NODE-04:** No external Fence installed: full normal API and trusted response flows pass their own gates; deployment reports `whole_host_rollback_guarantee=false`. No claim that an undetected full-VM snapshot rollback is detectable.
- **SINGLE-NODE-05:** Explicit external mode with wrong/missing credentials or broken network cannot automatically start as standard mode; a profile change needs an auditable authorized transition, no active send lease, and consistent state. **Partial code/test candidate:** fail-closed syntax, field and key checks; not yet durable pin, live Fence or controlled transitions.
- **SINGLE-NODE-06:** G3b/G4/G6 full native regression, mixed binaries, rollback, concurrency, performance, release fuse and Owner acceptance for an exact SHA/environment. Optionality does not bypass any other security gate.

### 2026-11-25 isolated standard-profile evidence — not a release signature

On the dedicated ARM64 `161.33.154.211` **disposable test PostgreSQL**, exact
SHA `7ada6fd539075c74ad4660919b0a2a5bc5852acc`, Gateway job
`job_01M893DRJW00Z7GF0MPMZR6H75` executed
`tests/test_protected_send.py`, `tests/test_restore_profile.py` and
`tests/test_world_acl_preflight.py`: **53 passed, 0 failed**; JUnit:
`/tmp/mirage-g3b-g6-20261125.AsFBoE/g5-standard-roles-exact-7ada6fd.xml`.
Cases include actual PostgreSQL SCRAM privilege denial, known-restore
quarantine and idempotence, older Sender SQL INSERT trigger protection,
adversarial TEMP shadow, unknown COMMIT ACK, active Send Lease versus Purge,
concurrent StartSend, pinned ASGI partial delivery, and explicit standard versus
external-profile parse rejection. No external Fence service was installed.
The exact same SHA's 7 TLS native gateway suite
`job_01M8939FXM001KK15ZBTSGNCTK` passed **30 tests** covering at least
one Client-native response per 20 registered routes across Inventory,
Synthetic Cart/Order and Medusa; its JUnit is
`/tmp/mirage-g3b-g6-20261125.AsFBoE/g3b-all20-exact-7ada6fd.xml`.

| Gate | Isolated evidence status | Still required for formal acceptance |
| --- | --- | --- |
| SINGLE-NODE-01 | **PARTIAL PASS** — 20 routes have specified Client HTTP/PG subcases with no external Fence | Complete 2xx/4xx matrix and actual formal single-node startup/services without lab-only components |
| SINGLE-NODE-02 | **PARTIAL PASS** — true SCRAM negative ACL, unique Send Lease, ASGI partial/unknown cases and four-service CI | All seven deployed services with independent physical logins, secret mounts, strict ingress network and client transport |
| SINGLE-NODE-03 | **PARTIAL PASS** — local restore marker, immutable DB trigger, mixed legacy Sender SQL and Send/Purge serialization | Real restored-system bootstrap/DB rollback and snapshot reconciliation/GC under release policy; no blind rearming |
| SINGLE-NODE-04 | **PARTIAL PASS** — profile parser accepts no-Fence mode and live isolated native paths function without it | Formal production-like all-service boot, full feature matrix and explicit `whole_host_rollback_guarantee=false` deployment report |
| SINGLE-NODE-05 | **PARTIAL PASS** — invalid/missing external settings fail closed in syntax/identity tests | Durable external-mode pin, authorized transition, fresh live authority/quarantine and downgrade resistance |
| SINGLE-NODE-06 | **PARTIAL PASS** — 30 true seven-TLS tests and separate G6 outage/ACK/timeout subcases | Full matrix: mixed binaries, true network loss, concurrency, performance, rollback recovery and Owner exact-SHA GO |

**None of these six rows is an unconditional final PASS.** In particular,
local PostgreSQL tests cannot prove an undetected whole-host snapshot rollback,
and an accepted standard profile must explicitly disclose that limitation.
The production release fuse, Trusted Send and DECEIVE remain OFF.

### 2026-11-25 G5 actual PostgreSQL restore experiment — bounded evidence

On dedicated disposable ARM64 PostgreSQL 17.6, the opt-in
`tests/test_g5_real_restore.py` performed an actual `pg_dump -Fc` of an
isolated migrated source schema and `pg_restore` into a **separately named,
random temporary database in the same disposable PostgreSQL cluster**. The
backup was taken before a known-restore marker existed; the restored copy
therefore contained a protected `SEND_AUTHORIZED` Receipt but **no marker**.
Before any restored Sender startup or permitted traffic, the experiment
persisted the marker twice (idempotently), then verified the new Sender
issued **zero** Send Leases and an older Sender's direct SQL was denied by
the database's known-restore trigger. Four independent runs passed:
`job_01M89BEPRS009SYR2E1N2CV6Y6` (one) and
`job_01M89BFA0W00APSBDM74NY4RYF` (three); JUnit files
`g5-real-pgdump-restore-experiment.xml` and
`g5-real-pgdump-restore-repeat-2.xml` through `-4.xml`, under
`/tmp/mirage-g3b-g6-20261125.AsFBoE/`. Cleanup inspection reported
**zero** generated `mirage_g5_restore_%` databases remaining.

This proves only the **controlled, manually sequenced, same-host restored-DB
quarantine subcase**. The marker is not magically included in an older backup;
real restore orchestration must guarantee quiesced ingress, marker durability
and Sender isolation *before* traffic. This experiment did **not** test VM
rollback, boot/restart orchestration, full GC/Purge reconciliation, host-wide
snapshot detection, a separate failure domain or a production restore.
`SINGLE-NODE-03`, the full G5 gate and final release remain **OPEN/NO-GO**.

**2026-11-26 incremental restored-DB GC/Purge subcase:** the same opt-in
PG17.6 `pg_dump -Fc` / `pg_restore` test now continues *after* the known-restore
quarantine to query Sender's read-only reconciliation: a restored
`SEND_AUTHORIZED` record with no visible Lease is **not** permission to retry.
It then installs a real `protected_authorized_snapshot_purge_fences` row with
one UUIDv4 GC operation, proves exact-ID replay is idempotent, rejects a
different GC ID, preserves the immutable pinned Envelope bytes and original
Authorization, and verifies **zero new Send Leases**. Disposable ARM64 lab
job `job_01M8ABADVY00ZQPFE8B0W2237Q` passed one actual restored-DB case;
temporary restored DB count **0**. This is an **isolated quarantine/Purge
subcase only**, not GC byte deletion, concurrent distributed purge, a real
crash/restart, the production retention policy or a formal G5 release PASS.

The G5 Sender also now exposes **read-only, counter-only**
`summarize_known_restore_quarantine()` for an isolated physical Sender login.
It requires at least one immutable Restore marker, then uses a **single SQL
snapshot** to classify pinned Authorizations without Lease, started/unknown
sends, terminal sends, existing Leases, GC/Purge Fences and unclassified states.
This result has no rearm operation and always reports `retry_permitted=false`;
an empty Lease count after DB rollback never proves that no external bytes were
sent. PostgreSQL experiment `job_01M8ABGMAR00N443VFMRZGZZKS` passed **2**
real cases (unmarked DB rejected; previous started/unknown Lease classified;
real restored/Purged DB classified) with **zero** generated databases left.
Production recovery review, error-handling, retention and authoritative release
governance are still **NOT ACCEPTED**.

### Subsequent G5 post-restore bootstrap candidate — not an acceptance signature

`src/deception/security/restore_bootstrap.py` adds an explicit operator-controlled
`python -m deception.security.restore_bootstrap` command for the same normal
single-node profile. It demands **both** ingress-stopped and restore-complete
confirmations, a stable UUIDv4 event, two different physical `NOINHERIT` PostgreSQL
logins pointing at exactly the same database/schema, and separate secret mounts.
The Recorder must have only Marker `INSERT`; a readback Sender must have only
Marker `SELECT`, with no role memberships, `CREATE`, `UPDATE` or `DELETE`.
The CLI marks under the existing exclusive transaction lock and **reads the exact
event back using the independent Sender login**; a repeated ID is idempotent.
Invalid/missing confirmation, credential/target mismatch, unexpectedly elevated
ACLs and role memberships all reject before insertion. Secrets are read from
bounded, non-symlink regular files and never printed in CLI output.

The new isolated PG17 `pg_dump -Fc`/`pg_restore` subcase also invokes the actual
bootstrap CLI, checks deliberate role-ACL and membership attacks, and verifies
that ordinary and legacy Sender remain quarantined after bootstrapping. The
**pre-commit** ARM64 jobs `job_01M89CEBNQ00FMS45JHAH0P0WY` (1 pass),
`job_01M89CGEPX00X3SY807Y01DRF1` (53 pass combined regression) and
`job_01M89CJ65400KV54JB1A9MP0W7` (5 pass including negatives) used disposable
DBs and left zero `mirage_g5_restore_%` databases. Their exact-commit
success is recorded in PR #34 at `73a84461` (58 actual ARM64 tests, four CI
workflows successful, Python full suite 1559 passed/15 skipped). Ordinary CI
deliberately skips the destructive real-Restore case without opt-in.

The subsequent boot guard candidate optionally reads a host-side expected
UUIDv4 file **outside the restored World DB**, and `create_sender_service`
requires the **matching persisted event through its own physical Sender login
before constructing even its sealed mTLS app**. A restored older DB with the
host-side file still present, missing/wrong marker, unreadable/invalid host
file or DB outage all fail closed at startup. Real PG17 `pg_restore` negative
and positive tests use the same disposable roles; this remains an opt-in
boot guard, **not an enforced or authoritative host-side witness**: removing
the configuration or rolling back the whole VM may remove both sides.
**No software guard verifies that ingress was truly stopped**, nor is there a
production restart orchestrator, persistent mode pin, GC/Purge reconciliation
or approved release mechanism. Thus `SINGLE-NODE-03` remains PARTIAL and
the release remains NO-GO.

## Optional external Fence acceptance — mandatory only if enabled or claimed

- **FENCE-OPTION-01:** Independent authority and storage/backup/restore domain; pin namespace, epoch, real SCRAM logins and Ed25519 identity. Same-host Docker lab is insufficient for whole-host rollback claim.
- **FENCE-OPTION-02:** True `pg_dump/pg_restore` and separate-host/failure-domain rollback: Fence highest Head remains fresh and detects restored World behind; outage/forgery/epoch retirement block release.
- **FENCE-OPTION-03:** Durable World Intent, DB-first/Anchor-first ambiguity, both commit-ACK losses, publisher reconciliation, immutable evidence and exact coverage of revocation/replay/binding/sends/purge; unresolved state remains quarantined.
- **FENCE-OPTION-04:** BD-05 atomic machine-verified Quarantine release bound to exact World snapshot and latest Fence Head, under concurrent Send/Purge/Restore; no human bypass and no new Send authorization created by release.

Existing `RESTORE-ANCHOR-*`, `RESTORE-RELEASE-*` and external `WORLD-RESTORE-PUBLISH/FENCE-*` cases remain required for **the enabled external profile**. Their historical `NOT_RUN`, `OPEN` or partial CI results must not be relabeled PASS. The 2026-11-25 isolated single-node subcases above are now executed, but the **full** SINGLE-NODE-01～06 acceptance remains OPEN.

## Release governance and migration

1. The Owner's single-host/full-feature direction changes product scope, **not** the meaning of Option B's high-assurance guarantees. Earlier absolute external-Fence prerequisites are superseded **only for `standard_single_node`**.
2. A future release must identify its selected profile, exact SHA, configuration, DB schema/roles, native 2xx/4xx and Send evidence, all applicable security test results, residual risks and a separately recorded Owner GO/NO-GO decision.
3. Until the normal sender and permission boundary are genuinely implemented and accepted, **both profiles remain NO-GO and Trusted Send OFF**. This document creates no override flag, backdoor, new external dependency or permission to merge a Draft PR.
4. `standard_single_node` cannot advertise external/host-wide anti-rollback. The Owner must explicitly acknowledge that missing guarantee in the final release record; merely accepting this product direction is not a final residual-risk/release signature.
5. Restoring an ordinary backup and restoring an entire VM are different threats. A full-VM rollback without an external witness cannot be conclusively detected; do not promise a security check that is mathematically unavailable.

Related decisions: [D-74](decisions-log.md), [Option B](restore-anchor-option-b.md), [BD-05](bd-05-restore-quarantine-release.md), [verification plan](verification-plan.md), [Owner acceptance](solo-developer-security-acceptance-v1.md).
