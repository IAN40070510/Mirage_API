-- Cart 資源身份建立後不可重綁。受限 Executor 對 SELECT ... FOR SHARE
-- 必須具有至少一欄 UPDATE privilege；實際 UPDATE 一律由 Trigger 拒絕。
-- 此 migration 不向任何 Role 授權 UPDATE，僅收緊資料本身的不可變性。
DROP TRIGGER IF EXISTS synthetic_resource_immutable ON synthetic_resources;
CREATE TRIGGER synthetic_resource_immutable BEFORE UPDATE OR DELETE
ON synthetic_resources FOR EACH ROW EXECUTE FUNCTION reject_protected_mutation();

REVOKE ALL ON TABLE synthetic_resources FROM PUBLIC;
