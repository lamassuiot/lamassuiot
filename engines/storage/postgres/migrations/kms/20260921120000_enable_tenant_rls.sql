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

GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE kms_keys TO lamassu_app;
ALTER TABLE kms_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE kms_keys FORCE ROW LEVEL SECURITY;
CREATE POLICY kms_keys_tenant_isolation ON kms_keys
    FOR ALL TO lamassu_app
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

-- +goose Down
DROP POLICY IF EXISTS kms_keys_tenant_isolation ON kms_keys;
ALTER TABLE kms_keys DISABLE ROW LEVEL SECURITY;
ALTER TABLE kms_keys NO FORCE ROW LEVEL SECURITY;
REVOKE SELECT, INSERT, UPDATE, DELETE ON TABLE kms_keys FROM lamassu_app;