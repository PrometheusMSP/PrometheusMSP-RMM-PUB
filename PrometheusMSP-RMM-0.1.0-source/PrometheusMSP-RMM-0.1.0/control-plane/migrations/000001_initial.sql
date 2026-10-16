CREATE TABLE tenants (
    id uuid PRIMARY KEY,
    name text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE enrollment_tokens (
    token_hash bytea PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    expires_at timestamptz NOT NULL,
    used_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE devices (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    name text NOT NULL,
    platform text NOT NULL,
    agent_version text NOT NULL,
    labels jsonb NOT NULL DEFAULT '{}',
    created_at timestamptz NOT NULL,
    last_seen_at timestamptz,
    UNIQUE (tenant_id, id)
);
CREATE INDEX devices_tenant_idx ON devices(tenant_id, id);

CREATE TABLE heartbeats (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id uuid NOT NULL,
    device_id uuid NOT NULL,
    observed_at timestamptz NOT NULL,
    payload jsonb NOT NULL,
    FOREIGN KEY (tenant_id, device_id) REFERENCES devices(tenant_id, id)
);
CREATE INDEX heartbeats_device_time_idx ON heartbeats(tenant_id, device_id, observed_at DESC);

CREATE TABLE inventories (
    tenant_id uuid NOT NULL,
    device_id uuid NOT NULL,
    collected_at timestamptz NOT NULL,
    payload jsonb NOT NULL,
    PRIMARY KEY (tenant_id, device_id),
    FOREIGN KEY (tenant_id, device_id) REFERENCES devices(tenant_id, id)
);

CREATE TABLE events (
    id text NOT NULL,
    tenant_id uuid NOT NULL,
    device_id uuid NOT NULL,
    occurred_at timestamptz NOT NULL,
    source text NOT NULL,
    severity text NOT NULL,
    payload jsonb NOT NULL,
    PRIMARY KEY (tenant_id, device_id, id),
    FOREIGN KEY (tenant_id, device_id) REFERENCES devices(tenant_id, id)
);
CREATE INDEX events_tenant_time_idx ON events(tenant_id, occurred_at DESC);

CREATE TABLE event_checkpoints (
    tenant_id uuid NOT NULL,
    device_id uuid NOT NULL,
    checkpoint text NOT NULL,
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, device_id),
    FOREIGN KEY (tenant_id, device_id) REFERENCES devices(tenant_id, id)
);

CREATE TABLE jobs (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    device_id uuid NOT NULL,
    issued_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    nonce text NOT NULL UNIQUE,
    action text NOT NULL,
    parameters jsonb NOT NULL,
    risk text NOT NULL,
    requested_by text NOT NULL,
    approved_by text,
    signature text,
    status text NOT NULL CHECK(status IN ('pending','approved','dispatched','completed','cancelled')),
    dispatched_at timestamptz,
    completed_at timestamptz,
    result jsonb,
    FOREIGN KEY (tenant_id, device_id) REFERENCES devices(tenant_id, id)
);
CREATE INDEX jobs_dispatch_idx ON jobs(tenant_id, device_id, status, issued_at);

CREATE TABLE audit_events (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    actor text NOT NULL,
    action text NOT NULL,
    target_type text NOT NULL,
    target_id text NOT NULL,
    occurred_at timestamptz NOT NULL,
    correlation_id text NOT NULL,
    details jsonb NOT NULL DEFAULT '{}'
);
CREATE INDEX audit_tenant_time_idx ON audit_events(tenant_id, occurred_at DESC);
