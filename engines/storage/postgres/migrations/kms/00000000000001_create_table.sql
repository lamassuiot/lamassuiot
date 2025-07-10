-- +goose Up
-- +goose StatementBegin
CREATE TABLE kms_keys (
	id text NOT NULL,
    name text NOT NULL,
    algorithm text NOT NULL,
    size int8 NOT NULL,
    public_key text NOT NULL,
    status text NOT NULL,
    creation_ts timestamptz NULL,
	CONSTRAINT keys_pkey PRIMARY KEY (id)
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE kms_keys;
-- +goose StatementEnd