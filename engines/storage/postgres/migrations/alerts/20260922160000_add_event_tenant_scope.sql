-- +goose Up
-- +goose StatementBegin
ALTER TABLE events ADD COLUMN tenant_id text;
UPDATE events SET tenant_id = '00000000-0000-0000-0000-000000000002' WHERE tenant_id IS NULL;
ALTER TABLE events ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE events DROP CONSTRAINT events_pkey;
ALTER TABLE events ADD CONSTRAINT events_pkey PRIMARY KEY (tenant_id, event_type);
CREATE INDEX events_tenant_id_idx ON events (tenant_id);
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE events TO lamassu_app;
ALTER TABLE events ENABLE ROW LEVEL SECURITY;
ALTER TABLE events FORCE ROW LEVEL SECURITY;
CREATE POLICY events_tenant_isolation ON events
    FOR ALL TO lamassu_app
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP POLICY IF EXISTS events_tenant_isolation ON events;
ALTER TABLE events DISABLE ROW LEVEL SECURITY;
ALTER TABLE events NO FORCE ROW LEVEL SECURITY;
REVOKE SELECT, INSERT, UPDATE, DELETE ON TABLE events FROM lamassu_app;
DROP INDEX IF EXISTS events_tenant_id_idx;
ALTER TABLE events DROP CONSTRAINT IF EXISTS events_pkey;
ALTER TABLE events ADD CONSTRAINT events_pkey PRIMARY KEY (event_type);
ALTER TABLE events DROP COLUMN tenant_id;
-- +goose StatementEnd
