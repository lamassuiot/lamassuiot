-- +goose Up
-- +goose StatementBegin
UPDATE va_role
SET tenant_id = '00000000-0000-0000-0000-000000000002'
WHERE tenant_id IS NULL;

ALTER TABLE va_role ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE va_role ADD CONSTRAINT va_role_tenant_ski_key UNIQUE (tenant_id, ca_ski);
CREATE INDEX va_role_tenant_id_idx ON va_role (tenant_id);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS va_role_tenant_id_idx;
ALTER TABLE va_role DROP CONSTRAINT IF EXISTS va_role_tenant_ski_key;
ALTER TABLE va_role ALTER COLUMN tenant_id DROP NOT NULL;
-- +goose StatementEnd