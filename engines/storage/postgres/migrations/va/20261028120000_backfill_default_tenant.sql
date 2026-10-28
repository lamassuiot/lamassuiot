-- +goose Up
-- +goose StatementBegin
ALTER TABLE va_role ADD COLUMN tenant_id text;

UPDATE va_role SET tenant_id = '00000000-0000-0000-0000-000000000002' WHERE tenant_id IS NULL;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE va_role DROP COLUMN tenant_id;
-- +goose StatementEnd