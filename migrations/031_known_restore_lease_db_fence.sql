-- D-74 / G6 mixed binary: 即使舊 Sender 不知道本機 Restore 表，DB 仍拒絕 Lease。
-- 不改既有 migration checksum；此 Trigger 固定 current_schema() 而非 caller path。
CREATE FUNCTION protected_deny_lease_during_known_restore()
RETURNS trigger
LANGUAGE plpgsql VOLATILE PARALLEL UNSAFE
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    -- 與可信 Recorder 的排他交易鎖互斥；接著另發查詢取新快照。
    PERFORM pg_advisory_xact_lock_shared(1296650823, 1380275028);
    IF EXISTS (SELECT 1 FROM protected_local_restore_events LIMIT 1) THEN
        RAISE EXCEPTION 'known restore quarantine active' USING ERRCODE = '42501';
    END IF;
    RETURN NEW;
END;
$$;

DO $$
DECLARE trusted_schema NAME := current_schema();
BEGIN
    EXECUTE format('ALTER FUNCTION %I.protected_deny_lease_during_known_restore() '
                   'SET search_path = pg_catalog, %I, pg_temp', trusted_schema, trusted_schema);
END;
$$;

CREATE TRIGGER protected_send_leases_known_restore_gate
BEFORE INSERT ON protected_send_leases
FOR EACH ROW EXECUTE FUNCTION protected_deny_lease_during_known_restore();

REVOKE ALL ON FUNCTION protected_deny_lease_during_known_restore() FROM PUBLIC;
