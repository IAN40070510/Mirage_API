CREATE TABLE IF NOT EXISTS ingress_refusal_audit (
    event_id UUID PRIMARY KEY,
    environment_id TEXT NOT NULL CHECK (length(environment_id) > 0),
    deployment_id TEXT NOT NULL CHECK (length(deployment_id) > 0),
    stage TEXT NOT NULL CHECK (stage IN (
        'trusted_ingress','resource_binding','world_resolve','read_admission','response_pipeline'
    )),
    reason TEXT NOT NULL CHECK (reason IN (
        'unavailable','read_only_policy','authorization_expired','resource_scope_mismatch'
    )),
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
