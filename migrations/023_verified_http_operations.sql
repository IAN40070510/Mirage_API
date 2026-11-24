-- G3b：只有獨立 Verifier 在 Replay/Receipt 同交易中生成的固定 Operation 可被信任。
-- 舊 Receipt 不自動補簽；Runtime 不能只靠 matching fingerprint 填入這張表。
CREATE TABLE protected_http_operation_bindings (
    receipt_id UUID PRIMARY KEY REFERENCES ingress_receipts(receipt_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    platform TEXT NOT NULL CHECK (length(platform) BETWEEN 1 AND 128),
    operation_id TEXT NOT NULL CHECK (length(operation_id) BETWEEN 1 AND 128),
    method TEXT NOT NULL CHECK (method ~ '^[A-Z]+$'),
    path_template TEXT NOT NULL CHECK (length(path_template) BETWEEN 1 AND 256),
    request_fingerprint CHAR(64) NOT NULL CHECK (request_fingerprint ~ '^[0-9a-f]{64}$'),
    request_body_sha256 CHAR(64) NOT NULL CHECK (request_body_sha256 ~ '^[0-9a-f]{64}$'),
    verified_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

CREATE TRIGGER protected_http_operation_binding_immutable BEFORE UPDATE OR DELETE
ON protected_http_operation_bindings FOR EACH ROW EXECUTE FUNCTION reject_protected_mutation();
REVOKE ALL ON TABLE protected_http_operation_bindings FROM PUBLIC;
