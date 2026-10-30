-- +goose Up
-- +goose StatementBegin
ALTER TABLE ca_certificates ADD COLUMN tenant_id text;
ALTER TABLE certificates ADD COLUMN tenant_id text;
ALTER TABLE issuance_profiles ADD COLUMN tenant_id text;

UPDATE ca_certificates SET tenant_id = '00000000-0000-0000-0000-000000000002' WHERE tenant_id IS NULL;
UPDATE certificates SET tenant_id = '00000000-0000-0000-0000-000000000002' WHERE tenant_id IS NULL;
UPDATE issuance_profiles SET tenant_id = '00000000-0000-0000-0000-000000000002' WHERE tenant_id IS NULL;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE issuance_profiles DROP COLUMN tenant_id;
ALTER TABLE certificates DROP COLUMN tenant_id;
ALTER TABLE ca_certificates DROP COLUMN tenant_id;
-- +goose StatementEnd