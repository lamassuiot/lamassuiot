-- +goose Up
-- +goose StatementBegin
ALTER TABLE kms_keys ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE kms_keys ADD CONSTRAINT kms_keys_tenant_id_key UNIQUE (tenant_id, key_id);
CREATE INDEX kms_keys_tenant_id_idx ON kms_keys (tenant_id);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS kms_keys_tenant_id_idx;
ALTER TABLE kms_keys DROP CONSTRAINT IF EXISTS kms_keys_tenant_id_key;
ALTER TABLE kms_keys ALTER COLUMN tenant_id DROP NOT NULL;
-- +goose StatementEnd