ALTER TABLE generation_controls
    ADD COLUMN IF NOT EXISTS emergency_revision BIGINT CHECK (emergency_revision > 0);
