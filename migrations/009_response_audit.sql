CREATE TABLE IF NOT EXISTS response_audit (
    admission_id TEXT NOT NULL REFERENCES response_admissions(admission_id),
    sequence SMALLINT NOT NULL,
    event_name TEXT NOT NULL,
    final_response_hash CHAR(64) NOT NULL,
    outcome TEXT,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY(admission_id,sequence)
);
