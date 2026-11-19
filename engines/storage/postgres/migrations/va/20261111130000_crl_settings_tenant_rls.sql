-- +goose Up
-- +goose StatementBegin
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE crl_settings TO lamassu_app;
ALTER TABLE crl_settings ENABLE ROW LEVEL SECURITY;
CREATE POLICY crl_settings_tenant_isolation ON crl_settings
    FOR ALL TO lamassu_app
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP POLICY IF EXISTS crl_settings_tenant_isolation ON crl_settings;
ALTER TABLE crl_settings DISABLE ROW LEVEL SECURITY;
REVOKE SELECT, INSERT, UPDATE, DELETE ON TABLE crl_settings FROM lamassu_app;
-- +goose StatementEnd
