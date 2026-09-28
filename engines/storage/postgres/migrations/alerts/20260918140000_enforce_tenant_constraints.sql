-- +goose Up
-- +goose StatementBegin
ALTER TABLE subscriptions ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE subscriptions ADD CONSTRAINT subscriptions_tenant_id_key UNIQUE (tenant_id, id);
CREATE INDEX subscriptions_tenant_id_idx ON subscriptions (tenant_id);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS subscriptions_tenant_id_idx;
ALTER TABLE subscriptions DROP CONSTRAINT IF EXISTS subscriptions_tenant_id_key;
ALTER TABLE subscriptions ALTER COLUMN tenant_id DROP NOT NULL;
-- +goose StatementEnd