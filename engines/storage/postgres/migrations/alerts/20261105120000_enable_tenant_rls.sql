-- +goose Up
-- +goose StatementBegin
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'lamassu_app') THEN
        CREATE ROLE lamassu_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
    END IF;
END
$$;
GRANT USAGE ON SCHEMA alerts TO lamassu_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE subscriptions, events TO lamassu_app;

ALTER TABLE subscriptions ENABLE ROW LEVEL SECURITY;
CREATE POLICY subscriptions_tenant_isolation ON subscriptions
    FOR ALL TO lamassu_app
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

ALTER TABLE events ENABLE ROW LEVEL SECURITY;
CREATE POLICY events_tenant_isolation ON events
    FOR ALL TO lamassu_app
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP POLICY IF EXISTS events_tenant_isolation ON events;
ALTER TABLE events DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS subscriptions_tenant_isolation ON subscriptions;
ALTER TABLE subscriptions DISABLE ROW LEVEL SECURITY;

REVOKE SELECT, INSERT, UPDATE, DELETE ON TABLE subscriptions, events FROM lamassu_app;
REVOKE USAGE ON SCHEMA alerts FROM lamassu_app;
-- +goose StatementEnd