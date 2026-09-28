-- +goose Up
-- +goose StatementBegin
ALTER TABLE va_role DROP CONSTRAINT ca_ski_pkey;
ALTER TABLE va_role ADD CONSTRAINT va_role_pkey PRIMARY KEY (tenant_id, ca_ski);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE va_role DROP CONSTRAINT va_role_pkey;
ALTER TABLE va_role ADD CONSTRAINT ca_ski_pkey PRIMARY KEY (ca_ski);
-- +goose StatementEnd
