-- +goose Up
-- +goose StatementBegin
ALTER TABLE certificates ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE ca_certificates ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE issuance_profiles ALTER COLUMN tenant_id SET NOT NULL;

ALTER TABLE certificates ADD CONSTRAINT certificates_tenant_serial_key UNIQUE (tenant_id, serial_number);
ALTER TABLE ca_certificates ADD CONSTRAINT ca_certificates_tenant_id_key UNIQUE (tenant_id, id);
ALTER TABLE issuance_profiles ADD CONSTRAINT issuance_profiles_tenant_id_key UNIQUE (tenant_id, id);
ALTER TABLE ca_certificates ADD CONSTRAINT ca_certificates_tenant_certificate_fk
	FOREIGN KEY (tenant_id, serial_number) REFERENCES certificates (tenant_id, serial_number);
ALTER TABLE ca_certificates ADD COLUMN profile_ref text GENERATED ALWAYS AS (NULLIF(profile_id, '')) STORED;
ALTER TABLE ca_certificates ADD CONSTRAINT ca_certificates_tenant_profile_fk
	FOREIGN KEY (tenant_id, profile_ref) REFERENCES issuance_profiles (tenant_id, id);

CREATE INDEX certificates_tenant_id_idx ON certificates (tenant_id);
CREATE INDEX ca_certificates_tenant_id_idx ON ca_certificates (tenant_id);
CREATE INDEX issuance_profiles_tenant_id_idx ON issuance_profiles (tenant_id);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS issuance_profiles_tenant_id_idx;
DROP INDEX IF EXISTS ca_certificates_tenant_id_idx;
DROP INDEX IF EXISTS certificates_tenant_id_idx;
ALTER TABLE ca_certificates DROP CONSTRAINT IF EXISTS ca_certificates_tenant_profile_fk;
ALTER TABLE ca_certificates DROP COLUMN IF EXISTS profile_ref;
ALTER TABLE ca_certificates DROP CONSTRAINT IF EXISTS ca_certificates_tenant_certificate_fk;
ALTER TABLE issuance_profiles DROP CONSTRAINT IF EXISTS issuance_profiles_tenant_id_key;
ALTER TABLE ca_certificates DROP CONSTRAINT IF EXISTS ca_certificates_tenant_id_key;
ALTER TABLE certificates DROP CONSTRAINT IF EXISTS certificates_tenant_serial_key;
ALTER TABLE issuance_profiles ALTER COLUMN tenant_id DROP NOT NULL;
ALTER TABLE ca_certificates ALTER COLUMN tenant_id DROP NOT NULL;
ALTER TABLE certificates ALTER COLUMN tenant_id DROP NOT NULL;
-- +goose StatementEnd