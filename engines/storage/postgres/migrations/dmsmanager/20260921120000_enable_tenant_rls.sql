-- +goose Up
-- +goose StatementBegin
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'lamassu_app') THEN
        CREATE ROLE lamassu_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
    END IF;
END
$$;
-- +goose StatementEnd

GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE dms TO lamassu_app;
ALTER TABLE dms ENABLE ROW LEVEL SECURITY;
ALTER TABLE dms FORCE ROW LEVEL SECURITY;
CREATE POLICY dms_tenant_isolation ON dms
    FOR ALL TO lamassu_app
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

-- +goose Down
DROP POLICY IF EXISTS dms_tenant_isolation ON dms;
ALTER TABLE dms DISABLE ROW LEVEL SECURITY;
ALTER TABLE dms NO FORCE ROW LEVEL SECURITY;
REVOKE SELECT, INSERT, UPDATE, DELETE ON TABLE dms FROM lamassu_app;