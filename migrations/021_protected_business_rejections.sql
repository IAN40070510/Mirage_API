-- G3b：僅認可同一 Executor 交易內真正被固定 Handler 拒絕的業務操作。
-- 不將任意 Runtime SecurityErrorSource 或失敗訊息補簽成受保護來源。
CREATE TABLE protected_world_rejection_sources (
    commit_attempt_id UUID PRIMARY KEY REFERENCES world_operations(commit_attempt_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    receipt_id UUID NOT NULL UNIQUE REFERENCES ingress_receipts(receipt_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    environment_id TEXT NOT NULL,
    deployment_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    world_generation_id TEXT NOT NULL,
    request_fingerprint CHAR(64) NOT NULL CHECK (request_fingerprint ~ '^[0-9a-f]{64}$'),
    operation TEXT NOT NULL,
    result_digest CHAR(64) NOT NULL CHECK (result_digest ~ '^[0-9a-f]{64}$'),
    template_id TEXT NOT NULL,
    contract_revision TEXT NOT NULL,
    envelope_hash CHAR(64) NOT NULL CHECK (envelope_hash ~ '^[0-9a-f]{64}$'),
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

CREATE TRIGGER protected_world_rejection_immutable BEFORE UPDATE OR DELETE
ON protected_world_rejection_sources FOR EACH ROW EXECUTE FUNCTION reject_protected_mutation();
REVOKE ALL ON TABLE protected_world_rejection_sources FROM PUBLIC;
