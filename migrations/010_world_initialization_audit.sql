-- 初始化稽核只記世界身份、版本與 hash，不複製商品內容或憑證。
-- 舊世界不補造歷史事件；此 migration 安裝後的新建立才留下原子證據。
CREATE TABLE IF NOT EXISTS world_initializations (
    environment_id TEXT NOT NULL,
    deployment_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    world_generation_id TEXT NOT NULL,
    state_version BIGINT NOT NULL,
    state_hash CHAR(64) NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY(environment_id,deployment_id,session_id,world_generation_id)
);

CREATE OR REPLACE FUNCTION record_world_initialization() RETURNS TRIGGER
LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO world_initializations
        (environment_id,deployment_id,session_id,world_generation_id,state_version,state_hash)
    VALUES (NEW.environment_id,NEW.deployment_id,NEW.session_id,NEW.world_generation_id,
            NEW.version,NEW.state_hash);
    RETURN NEW;
END;
$$;
COMMENT ON FUNCTION record_world_initialization() IS
    '與新世界快照同交易保存初始化摘要；不產生業務變更、不保存狀態本文，稽核失敗時建立回滾。';

DROP TRIGGER IF EXISTS world_initialization_audit ON world_snapshots;
CREATE TRIGGER world_initialization_audit AFTER INSERT ON world_snapshots
FOR EACH ROW EXECUTE FUNCTION record_world_initialization();
