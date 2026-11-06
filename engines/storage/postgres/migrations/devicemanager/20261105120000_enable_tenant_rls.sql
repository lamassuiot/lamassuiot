-- +goose Up
-- +goose StatementBegin
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'lamassu_app') THEN
        CREATE ROLE lamassu_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
    END IF;
END
$$;
GRANT USAGE ON SCHEMA devicemanager TO lamassu_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE devices, device_groups, device_events TO lamassu_app;

ALTER TABLE devices ENABLE ROW LEVEL SECURITY;
CREATE POLICY devices_tenant_isolation ON devices
    FOR ALL TO lamassu_app
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

ALTER TABLE device_groups ENABLE ROW LEVEL SECURITY;
CREATE POLICY device_groups_tenant_isolation ON device_groups
    FOR ALL TO lamassu_app
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

ALTER TABLE device_events ENABLE ROW LEVEL SECURITY;
CREATE POLICY device_events_tenant_isolation ON device_events
    FOR ALL TO lamassu_app
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP POLICY IF EXISTS device_events_tenant_isolation ON device_events;
ALTER TABLE device_events DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS device_groups_tenant_isolation ON device_groups;
ALTER TABLE device_groups DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS devices_tenant_isolation ON devices;
ALTER TABLE devices DISABLE ROW LEVEL SECURITY;

REVOKE SELECT, INSERT, UPDATE, DELETE ON TABLE devices, device_groups, device_events FROM lamassu_app;
REVOKE USAGE ON SCHEMA devicemanager FROM lamassu_app;
-- +goose StatementEnd