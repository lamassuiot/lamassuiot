-- +goose Up
-- +goose StatementBegin
ALTER TABLE va_role ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE va_role DROP CONSTRAINT ca_ski_pkey;
ALTER TABLE va_role ADD CONSTRAINT va_role_pkey PRIMARY KEY (tenant_id, ca_ski);
CREATE INDEX va_role_tenant_id_idx ON va_role (tenant_id);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS va_role_tenant_id_idx;
ALTER TABLE va_role DROP CONSTRAINT va_role_pkey;
ALTER TABLE va_role ADD CONSTRAINT ca_ski_pkey PRIMARY KEY (ca_ski);
ALTER TABLE va_role ALTER COLUMN tenant_id DROP NOT NULL;
-- +goose StatementEnd