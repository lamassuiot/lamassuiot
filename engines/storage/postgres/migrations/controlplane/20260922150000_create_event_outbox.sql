-- +goose Up
CREATE TABLE event_outbox (
    event_id text PRIMARY KEY,
    tenant_id text NOT NULL,
    organization_id text NOT NULL,
    correlation_id text NOT NULL,
    type text NOT NULL,
    version text NOT NULL,
    payload jsonb NOT NULL,
    status text NOT NULL DEFAULT 'PENDING',
    attempts integer NOT NULL DEFAULT 0,
    available_at timestamptz NOT NULL DEFAULT now(),
    last_error text,
    created_at timestamptz NOT NULL DEFAULT now(),
    published_at timestamptz
);
CREATE INDEX event_outbox_pending_idx ON event_outbox (tenant_id, status, available_at, created_at);

-- +goose Down
DROP TABLE event_outbox;