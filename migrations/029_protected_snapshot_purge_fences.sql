-- G4 局部安全增量：保留已授權 Snapshot／其 Bytes，另行不可逆地封閉執行資格。
-- 這不是外部 Object GC，也不代表 G5 Restore Fence 已驗收。嚴禁賦權 Runtime。
CREATE TABLE protected_authorized_snapshot_purge_fences (
    admission_id TEXT PRIMARY KEY REFERENCES protected_authorized_http_snapshots(admission_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    gc_operation_id UUID NOT NULL UNIQUE,
    purge_reason TEXT NOT NULL CHECK (purge_reason IN (
        'retention_expired', 'snapshot_corrupt')),
    fenced_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

-- 和 Sender 一樣先鎖 Admission；同筆交易完成 Fence INSERT 才生效。
-- Sender 取得鎖後另發 SQL 讀取 Fence，避免 READ COMMITTED 舊 snapshot 競態。
CREATE FUNCTION guard_authorized_snapshot_purge_insert() RETURNS TRIGGER AS $$
DECLARE
    current_state TEXT;
BEGIN
    SELECT state INTO current_state FROM response_admissions
        WHERE admission_id = NEW.admission_id FOR UPDATE;
    IF current_state IS NULL THEN
        RAISE EXCEPTION 'protected_snapshot_purge_admission_missing' USING ERRCODE = '42501';
    END IF;
    IF current_state = 'SEND_STARTED' OR EXISTS (
        SELECT 1 FROM protected_send_leases WHERE admission_id = NEW.admission_id
    ) THEN
        RAISE EXCEPTION 'protected_snapshot_purge_active_or_unknown_send'
            USING ERRCODE = '42501';
    END IF;
    IF current_state NOT IN (
        'SEND_AUTHORIZED', 'EXPIRED', 'SEND_COMPLETED',
        'SEND_FAILED', 'SEND_PARTIAL_FAILURE'
    ) THEN
        RAISE EXCEPTION 'protected_snapshot_purge_state_unapproved' USING ERRCODE = '42501';
    END IF;
    NEW.fenced_at := clock_timestamp();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER protected_snapshot_purge_guard BEFORE INSERT
ON protected_authorized_snapshot_purge_fences
FOR EACH ROW EXECUTE FUNCTION guard_authorized_snapshot_purge_insert();

CREATE TRIGGER protected_snapshot_purge_immutable BEFORE UPDATE OR DELETE
ON protected_authorized_snapshot_purge_fences
FOR EACH ROW EXECUTE FUNCTION reject_protected_mutation();

REVOKE ALL ON TABLE protected_authorized_snapshot_purge_fences FROM PUBLIC;
REVOKE ALL ON FUNCTION guard_authorized_snapshot_purge_insert() FROM PUBLIC;
