-- +goose Up
-- +goose StatementBegin
ALTER TABLE subscriptions ADD COLUMN tenant_id text;

UPDATE subscriptions SET tenant_id = '00000000-0000-0000-0000-000000000002' WHERE tenant_id IS NULL;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE subscriptions DROP COLUMN tenant_id;
-- +goose StatementEnd