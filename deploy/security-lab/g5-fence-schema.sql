-- G5 isolated Fence DB only. Never apply this DDL to the World DB.
-- A separate database owner must provision publisher/head-reader login ACLs.
CREATE SCHEMA mirage_restore_fence;

CREATE TABLE mirage_restore_fence.checkpoints (
    namespace text NOT NULL,
    epoch text NOT NULL,
    sequence bigint NOT NULL CHECK (sequence BETWEEN 1 AND 10000),
    previous_digest char(64) NOT NULL,
    world_digest char(64) NOT NULL,
    events_digest char(64) NOT NULL,
    first_event bigint NOT NULL CHECK (first_event >= 1),
    last_event bigint NOT NULL CHECK (last_event >= first_event - 1),
    publication_id text NOT NULL,
    status text NOT NULL CHECK (status = 'COMMITTED'),
    signature bytea NOT NULL CHECK (octet_length(signature) = 64),
    checkpoint_digest char(64) NOT NULL,
    PRIMARY KEY (namespace, epoch, sequence),
    UNIQUE (namespace, epoch, publication_id)
);

CREATE TABLE mirage_restore_fence.heads (
    namespace text NOT NULL,
    epoch text NOT NULL,
    sequence bigint NOT NULL CHECK (sequence BETWEEN 1 AND 10000),
    checkpoint_digest char(64) NOT NULL,
    PRIMARY KEY (namespace, epoch)
);

CREATE FUNCTION mirage_restore_fence.reject_checkpoint_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'restore_anchor_append_only' USING ERRCODE = '42501';
END
$$;

CREATE TRIGGER checkpoints_immutable
BEFORE UPDATE OR DELETE OR TRUNCATE ON mirage_restore_fence.checkpoints
FOR EACH STATEMENT EXECUTE FUNCTION mirage_restore_fence.reject_checkpoint_mutation();

CREATE FUNCTION mirage_restore_fence.protect_head()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'UPDATE' THEN
        IF NEW.namespace <> OLD.namespace OR NEW.epoch <> OLD.epoch
           OR NEW.sequence <> OLD.sequence + 1 THEN
            RAISE EXCEPTION 'restore_anchor_head_not_monotonic' USING ERRCODE = '42501';
        END IF;
    ELSE
        RAISE EXCEPTION 'restore_anchor_head_immutable' USING ERRCODE = '42501';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER head_monotonic
BEFORE UPDATE OR DELETE ON mirage_restore_fence.heads
FOR EACH ROW EXECUTE FUNCTION mirage_restore_fence.protect_head();

CREATE TRIGGER head_no_truncate
BEFORE TRUNCATE ON mirage_restore_fence.heads
FOR EACH STATEMENT EXECUTE FUNCTION mirage_restore_fence.reject_checkpoint_mutation();

REVOKE ALL ON SCHEMA mirage_restore_fence FROM PUBLIC;
