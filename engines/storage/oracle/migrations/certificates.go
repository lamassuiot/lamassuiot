package migrations

// CertificateFoundation extends KMSFoundation with certificates, CA records
// and the view used to read key availability. Other domains remain pending.
func CertificateFoundation() Migration {
	return Migration{
		Version: 2,
		Name:    "certificates foundation",
		Statements: []string{
			`CREATE TABLE certificates (
				serial_number VARCHAR2(512 CHAR) NOT NULL,
				subject_key_id VARCHAR2(512 CHAR),
				authority_key_id VARCHAR2(512 CHAR),
				metadata JSON,
				status VARCHAR2(255 CHAR),
				certificate CLOB,
				key_meta_type VARCHAR2(255 CHAR),
				key_meta_bits NUMBER(19),
				key_meta_strength VARCHAR2(255 CHAR),
				subject_common_name VARCHAR2(1000 CHAR),
				subject_organization VARCHAR2(1000 CHAR),
				subject_organization_unit VARCHAR2(1000 CHAR),
				subject_country VARCHAR2(1000 CHAR),
				subject_state VARCHAR2(1000 CHAR),
				subject_locality VARCHAR2(1000 CHAR),
				issuer_common_name VARCHAR2(1000 CHAR),
				issuer_organization VARCHAR2(1000 CHAR),
				issuer_organization_unit VARCHAR2(1000 CHAR),
				issuer_country VARCHAR2(1000 CHAR),
				issuer_state VARCHAR2(1000 CHAR),
				issuer_locality VARCHAR2(1000 CHAR),
				valid_from TIMESTAMP WITH TIME ZONE,
				valid_to TIMESTAMP WITH TIME ZONE,
				revocation_timestamp TIMESTAMP WITH TIME ZONE,
				revocation_reason VARCHAR2(255 CHAR),
				"TYPE" VARCHAR2(255 CHAR),
				engine_id VARCHAR2(512 CHAR),
				key_id VARCHAR2(512 CHAR),
				issuer_meta_serial_number VARCHAR2(512 CHAR),
				issuer_meta_id VARCHAR2(512 CHAR),
				issuer_meta_level NUMBER(19),
				extensions_key_usage JSON,
				extensions_extended_key_usage JSON,
				is_ca NUMBER(1) CHECK (is_ca IN (0, 1)),
				CONSTRAINT lamassu_cert_pk PRIMARY KEY (serial_number),
				CONSTRAINT lamassu_cert_key_engine_ck CHECK (key_id IS NULL OR engine_id IS NOT NULL),
				CONSTRAINT lamassu_cert_key_fk FOREIGN KEY (key_id, engine_id)
					REFERENCES kms_keys (key_id, engine_id) DEFERRABLE INITIALLY IMMEDIATE
			)`,
			`CREATE INDEX lamassu_cert_key_idx ON certificates (engine_id, key_id)`,
			`CREATE INDEX lamassu_cert_issuer_idx ON certificates (issuer_meta_id)`,
			`CREATE VIEW certificates_view AS SELECT c.*, COALESCE(k.has_private_key, 0) AS has_private_key
				FROM certificates c LEFT JOIN kms_keys k ON k.engine_id = c.engine_id AND k.key_id = c.key_id`,
			`CREATE TABLE ca_certificates (
				serial_number VARCHAR2(512 CHAR) NOT NULL,
				id VARCHAR2(512 CHAR) NOT NULL,
				metadata JSON,
				creation_ts TIMESTAMP WITH TIME ZONE,
				"LEVEL" NUMBER(19),
				profile_id VARCHAR2(512 CHAR),
				CONSTRAINT lamassu_ca_pk PRIMARY KEY (serial_number, id),
				CONSTRAINT lamassu_ca_id_unique UNIQUE (id),
				CONSTRAINT lamassu_ca_cert_fk FOREIGN KEY (serial_number) REFERENCES certificates (serial_number) ON DELETE CASCADE
			)`,
		},
	}
}
