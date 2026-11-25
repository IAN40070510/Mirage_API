# BD-05 — Restore Quarantine release policy

**Owner decision adopted 2026-11-21: automatic evidence verification first; anomalies remain quarantined; humans repair evidence and systems, never override the evidence gate.**

> **2026-11-25 D-74 applicability:** BD-05 is the automatic evidence-based **external Fence** release policy **when enhanced recovery protection is configured**. It is not a mandatory external-service dependency for ordinary full-feature single-node startup. Standard mode remains obligated to stop protected sends on a known/detected restore, fail closed on ambiguous local effects and disclose that whole-host snapshot rollback is not provably detectable. This re-scoping is **not** an implementation or release approval. See [single-node deployment profiles](single-node-restore-profiles.md).

This supersedes the previously proposed mandatory two-person approval and the experimental single-operator release certificate as release requirements. The experimental `restore_quarantine.py` certificate helper on the separate lab branch is **not an authorized production release policy**.

## External-Fence release requirements (all mandatory if external profile is selected)

1. On any World DB restore, enter persistent, default-deny Restore Quarantine **before** allowing any trusted transport, authorization, or protected state transition.
2. A separately credentialed verifier checks the independent Restore Anchor's authenticated namespace, epoch, latest monotonic sequence, world-state digest and uninterrupted publication history.
3. Reconcile all durable publication intents, ambiguous COMMIT/ACK outcomes, revocation records, replay tombstones, one-time Grant bindings, immutable Authorized Snapshots and Purge Fences. Any missing, contradictory, unverifiable, stale or unavailable evidence blocks release.
4. Release must be an atomic, conditional transition bound to the **exact verified restore epoch, Anchor head and World DB state**. Concurrent writes, restores, sends, purges or Anchor advances must invalidate the release proof or serialize behind the release fence.
5. Record an immutable, auditable machine-verification decision containing evidence identifiers, verifier version, observed head, timestamp, and explicit PASS/FAIL. A prior PASS cannot be replayed for a different state.
6. Only if **every** check passes and the verifier is healthy may the system automatically remove the quarantine fence. Release does not create or renew send authorization and does not override `StartSend` execution checks.
7. On failure, remain quarantined. Operators may repair/reconcile/retry validation, but cannot sign a bypass or force release with missing evidence.
8. No production automatic release until independent storage/identity isolation, durable reconciliation, concurrency and fault-injection acceptance tests, and owner/security/release signoffs are complete.

## External-Fence profile acceptance tests

- RESTORE-RELEASE-01: clean complete evidence permits automatic release with no human approval.
- RESTORE-RELEASE-02: missing/stale/tampered/outage Anchor blocks release.
- RESTORE-RELEASE-03: unresolved COMMIT/ACK or publication intent blocks release.
- RESTORE-RELEASE-04: replay tombstone, revocation, Grant or Purge Fence inconsistency blocks release.
- RESTORE-RELEASE-05: concurrent restore/send/purge or advancing Anchor cannot reuse a stale PASS.
- RESTORE-RELEASE-06: operator credentials cannot override failed verification.
- RESTORE-RELEASE-07: release cannot itself authorize or start a send.

**Decision status: ADOPTED, implementation NOT COMPLETE, acceptance NOT RUN. MIR-SEC-WORLD-001 OPEN; Mirage release NO-GO; production trusted send OFF.**
