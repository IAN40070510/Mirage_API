-- P2 original assessment ledger: explicitly provision; no runtime auto-migration.
-- Use isolated EXECUTE-only service roles, not direct table privileges.
-- Never manually reset consumed_at. Keep tombstones for a reviewed retention window.
-- DBA MUST apply this standalone file as one transaction (psql -1 -f ...).
-- Ordinary Mirage World migration runner applies 001-016 separately and
-- intentionally does NOT discover this dedicated original_assessment subdir.
-- Never add explicit BEGIN/COMMIT here: a transaction-owning caller may wrap it.
-- A nested COMMIT can break the migration runner's atomicity.
-- The single-transaction requirement prevents temporary PUBLIC EXECUTE.
DO $$
BEGIN
    IF current_schema() <> 'public' THEN
        RAISE EXCEPTION 'original_assessment_requires_dedicated_public_schema';
    END IF;
END
$$;

CREATE TABLE public.msdss_original_assessments (
    assessment_id text PRIMARY KEY,
    environment_id text NOT NULL,
    deployment_id text NOT NULL,
    request_id text NOT NULL,
    digest char(64) NOT NULL CHECK (digest ~ '^[0-9a-f]{64}$'),
    original_json text NOT NULL CHECK (octet_length(original_json) <= 8192),
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (environment_id, deployment_id, request_id),
    CHECK (length(assessment_id) BETWEEN 1 AND 128),
    CHECK (length(environment_id) BETWEEN 1 AND 64),
    CHECK (length(deployment_id) BETWEEN 1 AND 64)
);
CREATE INDEX msdss_original_assessments_expiry ON msdss_original_assessments (expires_at);

-- Do not issue INSERT/SELECT/UPDATE grants on this table to either service.
-- Only a dedicated NOLOGIN DDL/function owner should have underlying table rights.
-- Service users receive EXECUTE only on the appropriate SECURITY DEFINER function.

-- SECURITY DEFINER functions isolate database privileges: callers MUST NOT
-- have direct SELECT/INSERT/UPDATE/DELETE on the immutable/tombstone table.
-- Function owner must be an isolated schema owner, not an HTTP service role.
CREATE FUNCTION public.msdss_publish_original_assessment(
    p_assessment_id text, p_environment_id text, p_deployment_id text,
    p_request_id text, p_digest text, p_original_json text,
    p_expires_at timestamptz, p_observed_at timestamptz
) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
    v_now timestamptz;
    inserted_id text;
BEGIN
    v_now := clock_timestamp();
    IF p_expires_at IS NULL OR p_observed_at IS NULL
       OR p_expires_at <= v_now
       OR p_expires_at > v_now + INTERVAL '60 seconds'
       OR p_observed_at > v_now + INTERVAL '30 seconds'
       OR p_observed_at >= p_expires_at
       OR octet_length(p_original_json) > 8192 THEN
        RETURN FALSE;
    END IF;
    INSERT INTO public.msdss_original_assessments
        (assessment_id, environment_id, deployment_id, request_id,
         digest, original_json, expires_at)
    VALUES (p_assessment_id,p_environment_id,p_deployment_id,p_request_id,
            p_digest,p_original_json,p_expires_at)
    ON CONFLICT DO NOTHING RETURNING assessment_id INTO inserted_id;
    RETURN inserted_id IS NOT NULL;
END
$$;

CREATE FUNCTION public.msdss_take_original_assessment(
    p_assessment_id text, p_environment_id text, p_deployment_id text
) RETURNS TABLE (original_json text, digest text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
BEGIN
    RETURN QUERY
    UPDATE public.msdss_original_assessments AS item
       SET consumed_at = clock_timestamp()
     WHERE item.assessment_id = p_assessment_id
       AND item.environment_id = p_environment_id
       AND item.deployment_id = p_deployment_id
       AND item.consumed_at IS NULL
       AND item.expires_at > clock_timestamp()
    RETURNING item.original_json, item.digest::text;
END
$$;

-- PostgreSQL grants EXECUTE to PUBLIC on new functions by default: REVOKE!
REVOKE ALL ON FUNCTION public.msdss_publish_original_assessment(
    text,text,text,text,text,text,timestamptz,timestamptz) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.msdss_take_original_assessment(text,text,text) FROM PUBLIC;
REVOKE ALL ON TABLE public.msdss_original_assessments FROM PUBLIC;

-- PUBLIC must not be allowed to create shadow objects in this isolated schema.
-- This migration targets a dedicated original-assessment database, never staging.
REVOKE CREATE ON SCHEMA public FROM PUBLIC;

-- Atomic DDL publication is the DBA runner's responsibility (-1 / external
-- transaction). Never publish SECURITY DEFINER functions before REVOKEs commit.

-- DBA provisioning, example only; do NOT auto-create roles in migration:
-- GRANT USAGE ON SCHEMA public TO role_gateway_original_writer, role_mirage_original_reader;
-- GRANT EXECUTE ON FUNCTION public.msdss_publish_original_assessment(
--   text,text,text,text,text,text,timestamptz,timestamptz) TO role_gateway_original_writer;
-- GRANT EXECUTE ON FUNCTION public.msdss_take_original_assessment(
--   text,text,text) TO role_mirage_original_reader;
-- No direct table access for either role; only isolated DDL owner may inspect.
