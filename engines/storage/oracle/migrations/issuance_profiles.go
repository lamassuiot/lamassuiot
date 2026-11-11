package migrations

// IssuanceProfiles adds certificate issuance profiles to the Oracle baseline.
func IssuanceProfiles() Migration {
	return Migration{Version: 3, Name: "issuance profiles", Statements: []string{
		`CREATE TABLE issuance_profiles (
			id VARCHAR2(512 CHAR) NOT NULL,
			name VARCHAR2(1000 CHAR) NOT NULL,
			description CLOB,
			validity_type VARCHAR2(255 CHAR) NOT NULL,
			validity_time TIMESTAMP WITH TIME ZONE,
			validity_duration VARCHAR2(255 CHAR),
			sign_as_ca NUMBER(1) NOT NULL CHECK (sign_as_ca IN (0,1)),
			honor_key_usage NUMBER(1) NOT NULL CHECK (honor_key_usage IN (0,1)),
			key_usage JSON,
			honor_extended_key_usages NUMBER(1) NOT NULL CHECK (honor_extended_key_usages IN (0,1)),
			extended_key_usages JSON,
			honor_subject NUMBER(1) NOT NULL CHECK (honor_subject IN (0,1)),
			subject_common_name VARCHAR2(1000 CHAR),
			subject_organization VARCHAR2(1000 CHAR),
			subject_organization_unit VARCHAR2(1000 CHAR),
			subject_country VARCHAR2(1000 CHAR),
			subject_state VARCHAR2(1000 CHAR),
			subject_locality VARCHAR2(1000 CHAR),
			honor_extensions NUMBER(1) NOT NULL CHECK (honor_extensions IN (0,1)),
			crypto_enforcement_enabled NUMBER(1) NOT NULL CHECK (crypto_enforcement_enabled IN (0,1)),
			crypto_enforcement_allow_rsa_keys NUMBER(1) NOT NULL CHECK (crypto_enforcement_allow_rsa_keys IN (0,1)),
			crypto_enforcement_allowed_rsa_key_sizes JSON,
			crypto_enforcement_allow_ecdsa_keys NUMBER(1) NOT NULL CHECK (crypto_enforcement_allow_ecdsa_keys IN (0,1)),
			crypto_enforcement_allowed_ecdsa_key_sizes JSON,
			CONSTRAINT lamassu_profile_pk PRIMARY KEY (id)
		)`,
	}}
}
