-- +goose Up
-- +goose StatementBegin
ALTER TABLE dms ADD COLUMN tenant_id text;

UPDATE dms SET tenant_id = '00000000-0000-0000-0000-000000000002' WHERE tenant_id IS NULL;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE dms DROP COLUMN tenant_id;
-- +goose StatementEnd