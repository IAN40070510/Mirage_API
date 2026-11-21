# Independent Fence PostgreSQL — isolated Oracle lab deployment (2026-11-21)

## Verified environment

- Container: `mir-sec-world001-fence-pg`, image `postgres:17.6-alpine`, separate from `mir-sec-world001-pg`.
- Data volume: `mir-sec-world001-fence-data`, independently named and mounted at `/var/lib/postgresql/data`; **not included in World DB container volume**.
- Network: `mir-sec-world001-lab-net`, no host-published PostgreSQL port (`5432/tcp: null`).
- DB: `restore_fence`; migration `018_restore_quarantine_fence.sql` applied successfully; two tables confirmed.
- Seeded test namespace `lab-world` with state `QUARANTINED`, epoch 1 and an unresolved `PENDING` publication intent. SQL insert/readback passed. No release was performed.
- First container start failed because `--cap-drop ALL` blocked the PostgreSQL image's permission setup and user switch. Removed **only** this new isolated lab container and recreated it using the same isolated volume; subsequent migration succeeded.
- No existing production or staging containers were changed. Container is a **same-host** lab and is not resistant to host root/Docker daemon compromise or same-host disaster.

## Non-negotiable integration gaps

1. The runtime does **not yet** enforce `protected_world_operation` on every `StartSend`, Send and Purge path. There is no global deny gate yet; production trusted send remains OFF.
2. Restore tooling does **not yet** guarantee committed quarantine before every restore. A separate, non-restored fence volume is necessary but not sufficient.
3. The independent verifier is not deployed with distinct least-privilege credentials and full revocation/replay/grant/snapshot/purge reconciliation.
4. Cross-DB COMMIT and ACK outcomes are not atomic. Durable operation IDs, fencing epochs, reconciliation and failure-injection tests are mandatory.
5. `restore_fence.py` and `independent_fence_gate.py` are prototypes. In particular, a released fence read must be paired with a durable send/purge operation protocol that survives loss of the independent lock after a process crash.

**Status: independent isolated PostgreSQL lab storage DEPLOYED; end-to-end enforcement and security acceptance NOT COMPLETE. MIR-SEC-WORLD-001 OPEN, P2 NO-GO, trusted send OFF.**
