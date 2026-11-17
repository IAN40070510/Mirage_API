-- Profile 撤銷墓碑獨立於契約；保留紀錄以阻止未來契約或啟動程序復活同一 Profile。
CREATE TABLE IF NOT EXISTS projection_profile_revocations (
    compatibility_profile_sha256 CHAR(64) PRIMARY KEY CHECK (compatibility_profile_sha256 ~ '^[0-9a-f]{64}$'),
    registry_revision BIGINT NOT NULL CHECK (registry_revision >= 1),
    emergency BOOLEAN NOT NULL DEFAULT FALSE
);
