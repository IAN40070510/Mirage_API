# Fenced StartSend integration — isolated lab evidence

Status: PARTIAL / NO-GO. Not a production approval or G5 PASS.

Opt-in trusted_http.create_app(fence_dsn, fence_namespace) uses FencedAdmissionControl.
StartSend persists an independent PENDING intent before the World DB transition.
Both parameters are required; unequal DSN strings do not prove different DB identity.

## Isolated test evidence

Ephemeral msdss-mirage:p2-7-acceptance Docker container, source mounted read-only.
pytest installed inside disposable container only, not on host or production.
Command: python -m pytest tests/test_trusted_ingress.py tests/test_renderer_admission.py tests/test_fenced_admission_control.py -q --disable-warnings --maxfail=1 -p no:cacheprovider
Observed: 24 passed, 1 skipped. No live two-DB HTTP integration exercised.

## Open security blockers

1. Fence optional; direct PostgresAdmissionControl.start_send remains accessible.
2. Independent Fence lock ends BEFORE ASGI response bytes; restore/send race remains.
3. Claim and Authorize in prepare() are not fenced; BD-11 is not fully enforced.
4. No independently verified World DB operation-id evidence or automatic reconciliation.
5. Purge/Restore and crash/unknown-COMMIT fault injection not completed.
6. Same-host Docker isolation does not protect against host root compromise.

Trusted send OFF; MIR-SEC-WORLD-001 OPEN; MSDSS P2 NO-GO.
