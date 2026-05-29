-- +goose Up
-- +goose StatementBegin
CREATE TABLE stored_events (
    id          text        NOT NULL,
    event_type  text        NOT NULL,
    event       jsonb       NOT NULL,
    received_at timestamptz NOT NULL,
    expires_at  timestamptz NOT NULL,
    CONSTRAINT stored_events_pkey PRIMARY KEY (id)
);

CREATE INDEX idx_stored_events_event_type  ON stored_events(event_type);
CREATE INDEX idx_stored_events_received_at ON stored_events(received_at);
CREATE INDEX idx_stored_events_expires_at  ON stored_events(expires_at);

CREATE TABLE event_retention_settings (
    id              int         NOT NULL,
    audit_event_ttl text        NOT NULL DEFAULT '8760h',
    updated_at      timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT event_retention_settings_pkey PRIMARY KEY (id),
    CONSTRAINT only_one_row CHECK (id = 1)
);

INSERT INTO event_retention_settings (id, audit_event_ttl)
VALUES (1, '8760h');
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE stored_events;
DROP TABLE event_retention_settings;
-- +goose StatementEnd
