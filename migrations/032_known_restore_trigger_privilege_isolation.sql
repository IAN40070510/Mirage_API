-- D-74 / G6 rolling upgrade: 舊 Sender 無需讀取新增事件表，DB Trigger 仍可檢查。
-- 唯一的 SECURITY DEFINER 函式是無參數的 Trigger，沒有可由 Caller 組裝的 SQL。
-- 重新明確 Pin search_path：pg_temp 最後，防止同名 TEMP 表遮蔽正式事件。
DO $$
DECLARE trusted_schema NAME := current_schema();
BEGIN
    EXECUTE format('ALTER FUNCTION %I.protected_deny_lease_during_known_restore() '
                   'SECURITY DEFINER', trusted_schema);
    EXECUTE format('ALTER FUNCTION %I.protected_deny_lease_during_known_restore() '
                   'SET search_path = pg_catalog, %I, pg_temp', trusted_schema, trusted_schema);
    EXECUTE format('REVOKE ALL ON FUNCTION %I.protected_deny_lease_during_known_restore() '
                   'FROM PUBLIC', trusted_schema);
END;
$$;
