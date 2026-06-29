-- +goose Up
-- +goose StatementBegin
-- public.ca_certificates definition

-- this is the schema used by LAMASSU 3.2

CREATE TABLE ca_certificates (
	serial_number text NOT NULL,
	metadata text NULL,
	issuer_meta_serial_number text NULL,
	issuer_meta_id text NULL,
	issuer_meta_level int8 NULL,
	status text NULL,
	certificate text NULL,
	key_strength_meta_type int8 NULL,
	key_strength_meta_bits int8 NULL,
	key_strength_meta_strength text NULL,
	subject_common_name text NULL,
	subject_organization text NULL,
	subject_organization_unit text NULL,
	subject_country text NULL,
	subject_state text NULL,
	subject_locality text NULL,
	valid_from timestamptz NULL,
	valid_to timestamptz NULL,
	revocation_timestamp timestamptz NULL,
	revocation_reason int8 NULL,
	"type" text NULL,
	engine_id text NULL,
	id text NOT NULL,
	issuance_expiration_ref text NULL,
	creation_ts timestamptz NULL,
	"level" int8 NULL,
	CONSTRAINT ca_certificates_pkey PRIMARY KEY (serial_number, id)
);

CREATE TABLE certificates (
	serial_number text NOT NULL,
	metadata text NULL,
	issuer_meta_serial_number text NULL,
	issuer_meta_id text NULL,
	issuer_meta_level int8 NULL,
	status text NULL,
	certificate text NULL,
	key_strength_meta_type int8 NULL,
	key_strength_meta_bits int8 NULL,
	key_strength_meta_strength text NULL,
	subject_common_name text NULL,
	subject_organization text NULL,
	subject_organization_unit text NULL,
	subject_country text NULL,
	subject_state text NULL,
	subject_locality text NULL,
	valid_from timestamptz NULL,
	valid_to timestamptz NULL,
	revocation_timestamp timestamptz NULL,
	revocation_reason int8 NULL,
	"type" text NULL,
	engine_id text NULL,
	CONSTRAINT certificates_pkey PRIMARY KEY (serial_number)
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE ca_certificates;
DROP TABLE certificates;
-- +goose StatementEnd
