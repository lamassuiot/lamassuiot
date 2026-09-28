-- +goose Up
-- +goose StatementBegin
ALTER TABLE devices ADD COLUMN tenant_id text;
ALTER TABLE device_groups ADD COLUMN tenant_id text;

UPDATE devices SET tenant_id = '00000000-0000-0000-0000-000000000002' WHERE tenant_id IS NULL;
UPDATE device_groups SET tenant_id = '00000000-0000-0000-0000-000000000002' WHERE tenant_id IS NULL;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE device_groups DROP COLUMN tenant_id;
ALTER TABLE devices DROP COLUMN tenant_id;
-- +goose StatementEnd