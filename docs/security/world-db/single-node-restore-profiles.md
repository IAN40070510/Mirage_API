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
The deployer must suspend ingress before restore and persist the marker **after**
restoring the database, before reopening Sender; restoring an older DB image after
the marker could erase it. There is no verified release path, startup orchestrator,
or protection against already-started network sends yet, so SINGLE-NODE-03 remains OPEN.

Missing external DSN/secret must not prevent standard single-node **configuration parsing**; configured external mode cannot downgrade to standard because an external field is missing or corrupt. **Remaining security blocker:** a deliberately changed environment that removes *all* external settings is not detectable from an environment-only declaration. An authoritative, durable mode pin outside the World restore domain, guarded transitions, liveness/freshness verification and persistent quarantine are still required before claiming full `SINGLE-NODE-05` or any external assurance. A configured external profile whose authority becomes unavailable MUST remain quarantined, without silent downgrade.

## Standard single-node security acceptance — all mandatory

- **SINGLE-NODE-01:** Install/start all required Mirage business and protected services with no external Fence DSN, keys, network or tables. Confirm full native HTTP 2xx/4xx, World commits and candidate-to-authorized-response flow; no legacy unprotected bypass.
- **SINGLE-NODE-02:** Real PostgreSQL SCRAM/ACL, independent logical roles, protected Receipt, Grant/Binding, immutable Snapshot, single-use StartSend and actual ASGI first-byte/partial/unknown transport; prove unauthorized writes and duplicates are rejected.
- **SINGLE-NODE-03:** Candidate GC, Snapshot Purge, active Send Lease, local crash/restart, World DB rollback/unknown commit, and idempotent reconciliation. A known or detected restore must enter a persistent deny state before further protected sends until the *single-node recovery policy* has verified integrity; absence of external evidence cannot be called a cross-host proof.
- **SINGLE-NODE-04:** No external Fence installed: full normal API and trusted response flows pass their own gates; deployment reports `whole_host_rollback_guarantee=false`. No claim that an undetected full-VM snapshot rollback is detectable.
- **SINGLE-NODE-05:** Explicit external mode with wrong/missing credentials or broken network cannot automatically start as standard mode; a profile change needs an auditable authorized transition, no active send lease, and consistent state. **Partial code/test candidate:** fail-closed syntax, field and key checks; not yet durable pin, live Fence or controlled transitions.
- **SINGLE-NODE-06:** G3b/G4/G6 full native regression, mixed binaries, rollback, concurrency, performance, release fuse and Owner acceptance for an exact SHA/environment. Optionality does not bypass any other security gate.

## Optional external Fence acceptance — mandatory only if enabled or claimed

- **FENCE-OPTION-01:** Independent authority and storage/backup/restore domain; pin namespace, epoch, real SCRAM logins and Ed25519 identity. Same-host Docker lab is insufficient for whole-host rollback claim.
- **FENCE-OPTION-02:** True `pg_dump/pg_restore` and separate-host/failure-domain rollback: Fence highest Head remains fresh and detects restored World behind; outage/forgery/epoch retirement block release.
- **FENCE-OPTION-03:** Durable World Intent, DB-first/Anchor-first ambiguity, both commit-ACK losses, publisher reconciliation, immutable evidence and exact coverage of revocation/replay/binding/sends/purge; unresolved state remains quarantined.
- **FENCE-OPTION-04:** BD-05 atomic machine-verified Quarantine release bound to exact World snapshot and latest Fence Head, under concurrent Send/Purge/Restore; no human bypass and no new Send authorization created by release.

Existing `RESTORE-ANCHOR-*`, `RESTORE-RELEASE-*` and external `WORLD-RESTORE-PUBLISH/FENCE-*` cases remain required for **the enabled external profile**. Their historical `NOT_RUN`, `OPEN` or partial CI results must not be relabeled PASS. Single-node tests are newly introduced and are also `NOT_RUN` until executed against native code.

## Release governance and migration

1. The Owner's single-host/full-feature direction changes product scope, **not** the meaning of Option B's high-assurance guarantees. Earlier absolute external-Fence prerequisites are superseded **only for `standard_single_node`**.
2. A future release must identify its selected profile, exact SHA, configuration, DB schema/roles, native 2xx/4xx and Send evidence, all applicable security test results, residual risks and a separately recorded Owner GO/NO-GO decision.
3. Until the normal sender and permission boundary are genuinely implemented and accepted, **both profiles remain NO-GO and Trusted Send OFF**. This document creates no override flag, backdoor, new external dependency or permission to merge a Draft PR.
4. `standard_single_node` cannot advertise external/host-wide anti-rollback. The Owner must explicitly acknowledge that missing guarantee in the final release record; merely accepting this product direction is not a final residual-risk/release signature.
5. Restoring an ordinary backup and restoring an entire VM are different threats. A full-VM rollback without an external witness cannot be conclusively detected; do not promise a security check that is mathematically unavailable.

Related decisions: [D-74](decisions-log.md), [Option B](restore-anchor-option-b.md), [BD-05](bd-05-restore-quarantine-release.md), [verification plan](verification-plan.md), [Owner acceptance](solo-developer-security-acceptance-v1.md).
