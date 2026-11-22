-- G4：SEND_AUTHORIZED 後只允許單次 StartSend，精確綁定不可變 HTTP Snapshot。
-- Sender 為獨立實體登入；此 migration 不授權 Runtime 操作或啟用正式傳送。
CREATE TABLE protected_send_leases (
    admission_id TEXT PRIMARY KEY REFERENCES protected_authorized_http_snapshots(admission_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    lease_id UUID NOT NULL UNIQUE,
    receipt_id UUID NOT NULL REFERENCES ingress_receipts(receipt_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    send_owner TEXT NOT NULL CHECK (length(send_owner) BETWEEN 1 AND 128),
    request_fingerprint CHAR(64) NOT NULL CHECK (request_fingerprint ~ '^[0-9a-f]{64}$'),
    candidate_hash CHAR(64) NOT NULL CHECK (candidate_hash ~ '^[0-9a-f]{64}$'),
    transmission_deadline BIGINT NOT NULL,
    started_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

CREATE TRIGGER protected_send_lease_immutable BEFORE UPDATE OR DELETE
ON protected_send_leases FOR EACH ROW EXECUTE FUNCTION reject_protected_mutation();
REVOKE ALL ON TABLE protected_send_leases FROM PUBLIC;
