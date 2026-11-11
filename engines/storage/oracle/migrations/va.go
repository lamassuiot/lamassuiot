package migrations

// ValidationAuthority creates VA roles after their signer certificates.
// CRL versions use decimal text because Oracle NUMBER cannot represent all
// values of the arbitrary-precision BigInt exposed by the API. The column
// supports up to 4000 ASCII characters; numeric sorting needs a custom query.
func ValidationAuthority() Migration {
	return Migration{Version: 4, Name: "validation authority", Statements: []string{
		`CREATE TABLE va_role (
			ca_ski VARCHAR2(512 CHAR) NOT NULL,
			crl_refresh_interval VARCHAR2(255 CHAR),
			crl_validity VARCHAR2(255 CHAR),
			crl_signer_certificate_serial_number VARCHAR2(512 CHAR) NOT NULL,
			crl_regenerate_on_revoke NUMBER(1) CHECK (crl_regenerate_on_revoke IN (0,1)),
			latest_crl_version VARCHAR2(4000 CHAR) CHECK (REGEXP_LIKE(latest_crl_version, '^-?[0-9]+$', 'c')),
			latest_crl_valid_from TIMESTAMP WITH TIME ZONE,
			latest_crl_valid_until TIMESTAMP WITH TIME ZONE,
			CONSTRAINT lamassu_va_pk PRIMARY KEY (ca_ski),
			CONSTRAINT lamassu_va_signer_fk FOREIGN KEY (crl_signer_certificate_serial_number) REFERENCES certificates(serial_number)
		)`,
		`CREATE INDEX lamassu_va_signer_idx ON va_role (crl_signer_certificate_serial_number)`,
	}}
}
