-- G3b：原生 Medusa 400／404 只能由隔離 Executor 以原始 HTTP Proof 產生。
-- 404 必須另外綁定同一 Receipt 的受保護世界 Read Source；一般 Runtime 無寫權。
CREATE TABLE protected_medusa_rejection_sources (
    receipt_id UUID PRIMARY KEY REFERENCES ingress_receipts(receipt_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    environment_id TEXT NOT NULL,
    deployment_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    world_generation_id TEXT NOT NULL,
    request_fingerprint CHAR(64) NOT NULL CHECK (request_fingerprint ~ '^[0-9a-f]{64}$'),
    operation_id TEXT NOT NULL,
    status_code INTEGER NOT NULL CHECK (status_code IN (400, 404)),
    reason_code TEXT NOT NULL CHECK (reason_code IN (
        'native_bad_key', 'native_bad_item_body', 'native_variant_absent')),
    template_id TEXT NOT NULL CHECK (template_id IN ('native-cart-invalid', 'native-cart-rejected')),
    contract_revision TEXT NOT NULL CHECK (contract_revision = 'medusa-cart-1'),
    envelope_hash CHAR(64) NOT NULL CHECK (envelope_hash ~ '^[0-9a-f]{64}$'),
    read_admission_id TEXT NOT NULL REFERENCES read_admissions(read_admission_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    CHECK ((status_code = 404 AND reason_code = 'native_variant_absent'
            AND template_id = 'native-cart-rejected')
        OR (status_code = 400 AND reason_code IN ('native_bad_key', 'native_bad_item_body')
            AND template_id = 'native-cart-invalid')),
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

CREATE TRIGGER protected_medusa_rejection_immutable BEFORE UPDATE OR DELETE
ON protected_medusa_rejection_sources FOR EACH ROW EXECUTE FUNCTION reject_protected_mutation();
REVOKE ALL ON TABLE protected_medusa_rejection_sources FROM PUBLIC;
