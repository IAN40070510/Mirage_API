# MIR-SEC-WORLD-001 — Full-business protected executor decision

**Decision (2026-11-22): ADOPT full business capability.** Preserve inventory, cart, orders and Medusa synthetic API operations, including successful and legitimate failure responses. This does **not** authorize production Trusted Send, branch merge, or deployment.

**Transport decision (2026-11-22): ADOPT independent mTLS trusted services.** HTTP Runtime must not share Verifier／Executor／Validator／Authorizer DB credentials. Service certificates and private keys belong to separate deployment secrets and dedicated trust roots. An authenticated mTLS channel alone does **not** prove the original HTTP request or authorize arbitrary RPC operations. The first implementation remains `sealed` (only mTLS readiness + fixed 503 for business requests); see [Protected RPC](../../protected-rpc.md). The protocol cannot be opened until trusted HTTP operation identity and Receipt/Handler binding are complete and independently tested.

## Security invariants

1. An untrusted HTTP Runtime never receives the Executor, Ingress Verifier, Candidate Validator or Authorizer database credentials; role inheritance and direct DML on protected state/proof tables are prohibited. Privileged service calls must be authenticated, policy-scoped and independently authorized. A mere `expected_login` argument is **not** a secure remote service boundary.
2. Every World write and its provenance record commit in the **same database transaction**, with a fixed server-side business handler. No promotion may accept legacy `world_operations` or `read_admissions` merely because their values or hashes match.
3. A signed ingress receipt must bind verified environment, deployment, session, epoch, access mode, resource, request fingerprint and non-reusable operation identity. All current session/generation/revocation checks are performed under appropriate database locks and authoritative database time.
4. **Derived cart creation is a separate primitive**, not an ordinary mutation. The creator's ingress Receipt authorizes a single protected `create_cart` operation that allocates and records a derived cart session, world and resource mapping **atomically**, with a one-time `creator_receipt_id -> derived_scope -> resource_id` lineage. The new scope is not asserted to be the creator's session; its identity must be minted exclusively by the protected Executor. Retry requires the same immutable identity, payload digest and previously recorded result; unknown commit does not grant permission to allocate a second cart.
5. Normal 400/409 responses are valid API outputs, but do not get treated as arbitrary `SecurityErrorSource` proofs. A protected rejection record must bind a whitelisted error template, exact operation/status, request/receipt, candidate hash, business result or validation decision and contract revision. A failed business mutation must not be presented as a committed mutation.
6. Keep exact existing cart/inventory/order response schemas, deterministic idempotency, operation-result retrieval, synthetic isolation, and Medusa adapter behavior. For each endpoint separately prove 2xx, 4xx, retry, replay, cross-session and unknown-COMMIT behavior.
7. No service is considered integrated until `trusted_http.create_app` and all concrete handlers actually invoke the protected path. Legacy Runtime APIs may remain for isolated tests but their output **cannot obtain protected Grant/Send**.
8. G4 creates an immutable authorized HTTP snapshot plus single-use send lease and pin; G5 closes the independent Fence/Restore/Purge race through a verified monotonic authority held across the real ASGI send, with an explicit partial/unknown transmission outcome. Do not claim that already-sent bytes can be rolled back.

## Implementation order

- **G3a — provenance (implemented as isolated candidate):** protected read/commit source, separate PostgreSQL login, one-to-one Receipt/Promotion/Grant. Continue with dedicated role and provenance CI.
- **G3b — complete business parity (OPEN):** protected session resolve and cart creation, immutable creator→derived lineage, trusted 400/409 proof, fixed-handler wiring for inventory, cart and Medusa paths, complete endpoint compatibility and concurrency tests.
- **G4 — send authority (OPEN):** authorized immutable snapshot, pin and single-use lease, safe HTTP start/body control, timeout and crash reconciliation.
- **G5 — independent restore fence (OPEN):** separate-database quarantine epoch and evidence-backed release, send/restore and purge/send races, unknown COMMIT/ACK fault injection.
- **G6 — rollout review (OPEN):** verifiable role/network/secret isolation, CI and HTTP performance evidence, owner/security acceptance. No automatic release from a passing unit-test count.

## Go/no-go gates

| Gate | Required proof | Current status |
| --- | --- | --- |
| G3a | isolated PostgreSQL read/commit provenance and role tests | Partial PASS; see `grant-binding-implementation-status.md` for exact SHA |
| G3b | derived cart lineage and legitimate 400/409 source proofs, all HTTP endpoint parity | PARTIAL: isolated Verifier→Executor mTLS and scoped Medusa 400/404; see implementation record; all-route parity OPEN |
| G4 | immutable bytes and lease used by first ASGI byte | PARTIAL: isolated primitive only; real Sender mTLS OPEN |
| G5 | independent fence authority and fault injection | NOT IMPLEMENTED |
| Production | complete G0–G6, security owner approval | NO-GO |

**Safety state:** `MIR-SEC-WORLD-001=OPEN`, `MSDSS P2=NO-GO`, production Trusted Send OFF, existing release fuse intact, main and staging untouched.
