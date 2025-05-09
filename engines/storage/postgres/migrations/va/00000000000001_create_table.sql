-- +goose Up
-- +goose StatementBegin
CREATE TABLE va_role (
	ca_ski TEXT,
	crl_refresh_interval TEXT,
	crl_validity TEXT,
	crl_subject_key_id_signer TEXT,
	crl_regenerate_on_revoke BOOLEAN,
	latest_crl_version NUMERIC,
	latest_crl_valid_from TIMESTAMPTZ,
	latest_crl_valid_until TIMESTAMPTZ,
	CONSTRAINT ca_ski_pkey PRIMARY KEY (ca_ski)
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE va_role;
-- +goose StatementEnd
