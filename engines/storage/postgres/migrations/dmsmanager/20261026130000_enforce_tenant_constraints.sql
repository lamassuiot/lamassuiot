-- +goose Up
-- +goose StatementBegin
ALTER TABLE dms ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE dms ADD CONSTRAINT dms_tenant_id_key UNIQUE (tenant_id, id);
CREATE INDEX dms_tenant_id_idx ON dms (tenant_id);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS dms_tenant_id_idx;
ALTER TABLE dms DROP CONSTRAINT IF EXISTS dms_tenant_id_key;
ALTER TABLE dms ALTER COLUMN tenant_id DROP NOT NULL;
-- +goose StatementEnd