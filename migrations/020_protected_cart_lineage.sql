-- G3b：購物車衍生 Session 必須由已驗證 creator Receipt 一次性建立。
-- 舊 guest_cart_creations 不自動補簽，只有 Executor 同交易寫入來源鏈才可信。
CREATE TABLE protected_cart_creations (
    receipt_id UUID PRIMARY KEY REFERENCES ingress_receipts(receipt_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    environment_id TEXT NOT NULL,
    deployment_id TEXT NOT NULL,
    creator_session_id TEXT NOT NULL,
    creator_epoch BIGINT NOT NULL,
    idempotency_key UUID NOT NULL,
    commit_attempt_id UUID NOT NULL UNIQUE,
    request_fingerprint CHAR(64) NOT NULL CHECK (request_fingerprint ~ '^[0-9a-f]{64}$'),
    operation_digest CHAR(64) NOT NULL CHECK (operation_digest ~ '^[0-9a-f]{64}$'),
    derived_session_id TEXT NOT NULL,
    derived_world_generation_id TEXT NOT NULL,
    resource_id TEXT NOT NULL UNIQUE REFERENCES synthetic_resources(resource_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY(environment_id,deployment_id,creator_session_id,creator_epoch,idempotency_key)
        REFERENCES guest_cart_creations(environment_id,deployment_id,creator_session_id,creator_epoch,idempotency_key)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    UNIQUE(environment_id,deployment_id,creator_session_id,creator_epoch,idempotency_key)
);

CREATE TRIGGER protected_cart_creation_immutable BEFORE UPDATE OR DELETE
ON protected_cart_creations FOR EACH ROW EXECUTE FUNCTION reject_protected_mutation();
REVOKE ALL ON TABLE protected_cart_creations FROM PUBLIC;
