-- +goose Up
-- +goose StatementBegin
-- public.issuance_profiles definition

CREATE TABLE issuance_profiles (
	id text NOT NULL,
   name text NOT NULL,
   description text,
   validity_type TEXT NOT NULL,
   validity_time TIMESTAMPTZ NULL,
   validity_duration TEXT NULL,
   sign_as_ca boolean NOT NULL DEFAULT false,
   honor_key_usage boolean NOT NULL DEFAULT true,
   key_usage text[] NOT NULL DEFAULT '{}',
   honor_extended_key_usage boolean NOT NULL DEFAULT true,
   extended_key_usage text[] NOT NULL DEFAULT '{}',
   honor_subject boolean NOT NULL DEFAULT true,
   subject_common_name text NOT NULL DEFAULT '',
   subject_organization text DEFAULT '',
   subject_organization_unit text DEFAULT '',
   subject_country text DEFAULT '',
   subject_state text DEFAULT '',
   subject_locality text DEFAULT '',
   honor_extensions boolean NOT NULL DEFAULT true,
   allow_rsa_keys boolean NOT NULL DEFAULT true,
   allow_ecdsa_keys boolean NOT NULL DEFAULT true,
	CONSTRAINT issuance_profiles_pkey PRIMARY KEY (id)
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE issuance_profiles;
-- +goose StatementEnd
