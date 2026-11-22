-- G4 第一階段：SEND_AUTHORIZED 與不可變 HTTP Envelope 在同一交易提交。
-- 本表只是 pin/snapshot 證據，尚不授權任何 ASGI byte；Send Lease 與 Fence 另行驗收。
CREATE TABLE protected_authorized_http_snapshots (
    admission_id TEXT PRIMARY KEY REFERENCES response_admissions(admission_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    operation_id UUID NOT NULL UNIQUE REFERENCES protected_grant_bindings(operation_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    receipt_id UUID NOT NULL UNIQUE REFERENCES ingress_receipts(receipt_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    environment_id TEXT NOT NULL,
    deployment_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    world_generation_id TEXT NOT NULL,
    candidate_ref TEXT NOT NULL,
    candidate_version BIGINT NOT NULL CHECK (candidate_version = 1),
    request_fingerprint CHAR(64) NOT NULL CHECK (request_fingerprint ~ '^[0-9a-f]{64}$'),
    candidate_hash CHAR(64) NOT NULL CHECK (candidate_hash ~ '^[0-9a-f]{64}$'),
    envelope_bytes BYTEA NOT NULL,
    send_owner TEXT NOT NULL CHECK (length(send_owner) BETWEEN 1 AND 128),
    transmission_deadline BIGINT NOT NULL,
    authorized_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY(environment_id,deployment_id,session_id,world_generation_id,candidate_ref,candidate_version)
        REFERENCES protected_candidate_promotions(environment_id,deployment_id,session_id,
                                                   world_generation_id,candidate_ref,candidate_version)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    CHECK (candidate_hash = encode(sha256(envelope_bytes),'hex'))
);

CREATE TRIGGER protected_authorized_http_snapshot_immutable BEFORE UPDATE OR DELETE
ON protected_authorized_http_snapshots FOR EACH ROW EXECUTE FUNCTION reject_protected_mutation();
REVOKE ALL ON TABLE protected_authorized_http_snapshots FROM PUBLIC;
