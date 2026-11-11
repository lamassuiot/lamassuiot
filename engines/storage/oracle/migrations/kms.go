package migrations

// KMSFoundation is the first part of the Oracle baseline. It is not a complete
// engine schema: certificate, CA and other domain migrations must be added
// before an installation can be considered ready for service.
func KMSFoundation() Migration {
	return Migration{
		Version: 1,
		Name:    "kms foundation",
		Statements: []string{
			`CREATE TABLE lamassu_locks (lock_id VARCHAR2(64 CHAR) PRIMARY KEY)`,
			`INSERT INTO lamassu_locks (lock_id) VALUES ('kms_rename')`,
			`CREATE TABLE kms_keys (
				key_id VARCHAR2(512 CHAR) NOT NULL,
				engine_id VARCHAR2(512 CHAR) NOT NULL,
				name VARCHAR2(1000 CHAR),
				aliases JSON DEFAULT JSON('[]'),
				has_private_key NUMBER(1) DEFAULT 1 CHECK (has_private_key IN (0, 1)),
				algorithm VARCHAR2(255 CHAR) NOT NULL,
				"SIZE" NUMBER(19) NOT NULL,
				public_key CLOB NOT NULL,
				creation_ts TIMESTAMP WITH TIME ZONE,
				tags JSON DEFAULT JSON('[]'),
				metadata JSON,
				CONSTRAINT lamassu_kms_keys_pk PRIMARY KEY (key_id, engine_id)
			)`,
		},
	}
}
