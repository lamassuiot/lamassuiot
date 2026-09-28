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

GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE ca_certificates, certificates, issuance_profiles TO lamassu_app;

ALTER TABLE ca_certificates ENABLE ROW LEVEL SECURITY;
ALTER TABLE ca_certificates FORCE ROW LEVEL SECURITY;
CREATE POLICY ca_certificates_tenant_isolation ON ca_certificates
    FOR ALL TO lamassu_app
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

ALTER TABLE certificates ENABLE ROW LEVEL SECURITY;
ALTER TABLE certificates FORCE ROW LEVEL SECURITY;
CREATE POLICY certificates_tenant_isolation ON certificates
    FOR ALL TO lamassu_app
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

ALTER TABLE issuance_profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE issuance_profiles FORCE ROW LEVEL SECURITY;
CREATE POLICY issuance_profiles_tenant_isolation ON issuance_profiles
    FOR ALL TO lamassu_app
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

-- +goose Down
DROP POLICY IF EXISTS issuance_profiles_tenant_isolation ON issuance_profiles;
ALTER TABLE issuance_profiles DISABLE ROW LEVEL SECURITY;
ALTER TABLE issuance_profiles NO FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS certificates_tenant_isolation ON certificates;
ALTER TABLE certificates DISABLE ROW LEVEL SECURITY;
ALTER TABLE certificates NO FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS ca_certificates_tenant_isolation ON ca_certificates;
ALTER TABLE ca_certificates DISABLE ROW LEVEL SECURITY;
ALTER TABLE ca_certificates NO FORCE ROW LEVEL SECURITY;
REVOKE SELECT, INSERT, UPDATE, DELETE ON TABLE ca_certificates, certificates, issuance_profiles FROM lamassu_app;