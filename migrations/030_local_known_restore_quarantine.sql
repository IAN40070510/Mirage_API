-- D-74 / SINGLE-NODE-03: 已知 Restore 事件是不可變本機隔離證據。
-- 本表只代表明確收到的 Restore 通知，不聲稱能偵測整台主機快照回滾。
-- 實體 Recorder 需獨立 INSERT Login；Sender 僅需 SELECT，Runtime 無權操作。
CREATE TABLE protected_local_restore_events (
    restore_event_id UUID PRIMARY KEY,
    observed_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CHECK (restore_event_id <> '00000000-0000-0000-0000-000000000000'::uuid)
);

CREATE TRIGGER protected_local_restore_events_immutable
BEFORE UPDATE OR DELETE ON protected_local_restore_events
FOR EACH ROW EXECUTE FUNCTION reject_protected_mutation();

REVOKE ALL ON TABLE protected_local_restore_events FROM PUBLIC;
