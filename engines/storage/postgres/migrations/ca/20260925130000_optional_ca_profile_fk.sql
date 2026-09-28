-- +goose Up
-- +goose StatementBegin
-- A CA may have no issuance profile (e.g. a CA imported without its key),
-- stored as an empty profile_id. The composite FK must only apply when a
-- profile is set, so it references NULLIF(profile_id, '') instead.
ALTER TABLE ca_certificates DROP CONSTRAINT IF EXISTS ca_certificates_tenant_profile_fk;
ALTER TABLE ca_certificates ADD COLUMN profile_ref text GENERATED ALWAYS AS (NULLIF(profile_id, '')) STORED;
ALTER TABLE ca_certificates ADD CONSTRAINT ca_certificates_tenant_profile_fk
	FOREIGN KEY (tenant_id, profile_ref) REFERENCES issuance_profiles (tenant_id, id);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE ca_certificates DROP CONSTRAINT IF EXISTS ca_certificates_tenant_profile_fk;
ALTER TABLE ca_certificates DROP COLUMN IF EXISTS profile_ref;
ALTER TABLE ca_certificates ADD CONSTRAINT ca_certificates_tenant_profile_fk
	FOREIGN KEY (tenant_id, profile_id) REFERENCES issuance_profiles (tenant_id, id);
-- +goose StatementEnd
