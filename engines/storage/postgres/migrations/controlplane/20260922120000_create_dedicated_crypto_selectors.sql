-- +goose Up
-- +goose StatementBegin
CREATE TABLE dedicated_crypto_selectors (
    tenant_id text NOT NULL,
    ca_id text NOT NULL,
    engine_id text NOT NULL,
    key_id text NOT NULL,
    version bigint NOT NULL DEFAULT 1,
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT dedicated_crypto_selectors_pkey PRIMARY KEY (tenant_id),
    CONSTRAINT dedicated_crypto_selectors_tenant_fk FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    CONSTRAINT dedicated_crypto_selectors_version_check CHECK (version > 0)
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE dedicated_crypto_selectors;
-- +goose StatementEnd
