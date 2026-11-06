-- +goose Up
-- +goose StatementBegin
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'lamassu_app') THEN
        CREATE ROLE lamassu_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
    END IF;
END
$$;
GRANT USAGE ON SCHEMA va TO lamassu_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE va_role TO lamassu_app;
ALTER TABLE va_role ENABLE ROW LEVEL SECURITY;
CREATE POLICY va_role_tenant_isolation ON va_role
    FOR ALL TO lamassu_app
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP POLICY IF EXISTS va_role_tenant_isolation ON va_role;
ALTER TABLE va_role DISABLE ROW LEVEL SECURITY;
REVOKE SELECT, INSERT, UPDATE, DELETE ON TABLE va_role FROM lamassu_app;
REVOKE USAGE ON SCHEMA va FROM lamassu_app;
-- +goose StatementEnd