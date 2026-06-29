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
   key_usage text NOT NULL DEFAULT '{}',
   honor_extended_key_usages boolean NOT NULL DEFAULT true,
   extended_key_usages text NOT NULL DEFAULT '{}',
   honor_subject boolean NOT NULL DEFAULT true,
   subject_common_name text NOT NULL DEFAULT '',
   subject_organization text DEFAULT '',
   subject_organization_unit text DEFAULT '',
   subject_country text DEFAULT '',
   subject_state text DEFAULT '',
   subject_locality text DEFAULT '',
   honor_extensions boolean NOT NULL DEFAULT true,
   crypto_enforcement_enabled boolean NOT NULL DEFAULT false,
   crypto_enforcement_allow_rsa_keys boolean NOT NULL DEFAULT true,
   crypto_enforcement_allowed_rsa_key_sizes text DEFAULT '{}',
   crypto_enforcement_allow_ecdsa_keys boolean NOT NULL DEFAULT true,
   crypto_enforcement_allowed_ecdsa_key_sizes text DEFAULT '{}',

	CONSTRAINT issuance_profiles_pkey PRIMARY KEY (id)
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE issuance_profiles;
-- +goose StatementEnd