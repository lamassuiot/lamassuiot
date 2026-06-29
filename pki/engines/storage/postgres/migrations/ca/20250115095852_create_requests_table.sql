-- +goose Up
-- +goose StatementBegin
-- public.ca_certificates definition

-- this is the schema used by LAMASSU 3.2

CREATE TABLE ca_certificate_requests (
	id text NOT NULL,
    key_id text NOT NULL,
    engine_id text NULL,
	metadata text NULL,
	issuer_meta_serial_number text NULL,
	issuer_meta_id text NULL,
	issuer_meta_level int8 NULL,
    subject_common_name text NULL,
	subject_organization text NULL,
	subject_organization_unit text NULL,
	subject_country text NULL,
	subject_state text NULL,
	subject_locality text NULL,
    creation_ts timestamptz NULL,
	"level" int8 NULL,
    key_meta_type text NULL,
	key_meta_bits int8 NULL,
	key_meta_strength text NULL,
	status text NULL,
	fingerprint text NULL,
	csr text NULL,
	CONSTRAINT certificate_requests_pkey PRIMARY KEY (id)
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE ca_certificate_requests;
-- +goose StatementEnd
