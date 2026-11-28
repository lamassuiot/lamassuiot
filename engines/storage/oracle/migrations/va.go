package migrations

// ValidationAuthority creates the CRL settings of the CAs after their signer
// certificates and KMS keys. It mirrors the PostgreSQL crl_settings table
// (va/20261111120000_crl_settings.sql) for new installations: there are no
// va_role rows to migrate.
//
// CRL versions use decimal text because Oracle NUMBER cannot represent all
// values of the arbitrary-precision BigInt exposed by the API. The column
// supports up to 4000 ASCII characters; numeric sorting needs a custom query.
//
// Oracle has no ON UPDATE CASCADE: renaming a KMS key updates signer_key_id
// itself, which is why lamassu_crl_signer_key_fk is DEFERRABLE.
func ValidationAuthority() Migration {
	return Migration{Version: 4, Name: "validation authority", Statements: []string{
		`CREATE TABLE crl_settings (
			ca_id VARCHAR2(512 CHAR) NOT NULL,
			legacy_ski VARCHAR2(512 CHAR),
			signer_serial_number VARCHAR2(512 CHAR),
			signer_engine_id VARCHAR2(512 CHAR),
			signer_key_id VARCHAR2(512 CHAR),
			validity VARCHAR2(255 CHAR),
			refresh_interval VARCHAR2(255 CHAR),
			regenerate_on_revoke NUMBER(1) CHECK (regenerate_on_revoke IN (0,1)),
			status VARCHAR2(16 CHAR) NOT NULL,
			latest_crl_version VARCHAR2(4000 CHAR) CHECK (REGEXP_LIKE(latest_crl_version, '^-?[0-9]+$', 'c')),
			latest_crl_valid_from TIMESTAMP WITH TIME ZONE,
			latest_crl_valid_until TIMESTAMP WITH TIME ZONE,
			CONSTRAINT lamassu_crl_settings_pk PRIMARY KEY (ca_id),
			CONSTRAINT lamassu_crl_legacy_ski_uq UNIQUE (legacy_ski),
			CONSTRAINT lamassu_crl_signer_by_status CHECK (
				(status = 'ACTIVE' AND signer_serial_number IS NOT NULL AND signer_engine_id IS NOT NULL AND signer_key_id IS NOT NULL)
				OR (status = 'FINAL' AND signer_serial_number IS NOT NULL AND signer_engine_id IS NULL AND signer_key_id IS NULL)
				OR (status = 'ARCHIVED' AND signer_serial_number IS NULL AND signer_engine_id IS NULL AND signer_key_id IS NULL)),
			CONSTRAINT lamassu_crl_signer_cert_fk FOREIGN KEY (signer_serial_number) REFERENCES certificates (serial_number),
			CONSTRAINT lamassu_crl_signer_key_fk FOREIGN KEY (signer_key_id, signer_engine_id)
				REFERENCES kms_keys (key_id, engine_id) DEFERRABLE INITIALLY IMMEDIATE
		)`,
		`CREATE INDEX lamassu_crl_signer_cert_idx ON crl_settings (signer_serial_number)`,
		`CREATE INDEX lamassu_crl_signer_key_idx ON crl_settings (signer_engine_id, signer_key_id)`,
	}}
}
