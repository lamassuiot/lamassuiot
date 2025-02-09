-- +goose Up
-- +goose StatementBegin
CREATE TABLE va_role (
	caid TEXT,
	crl_refresh_interval TEXT,
	crl_validity TEXT,
	crl_key_id_singer TEXT,
	crl_regenerate_on_revoke BOOLEAN,
	latest_crl_version NUMERIC,
	latest_crl_valid_from TIMESTAMPTZ,
	latest_crl_valid_until TIMESTAMPTZ,
	CONSTRAINT caid_pkey PRIMARY KEY (caid)
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE va_role;
-- +goose StatementEnd
