package migrations

// DMS creates the device-management-system configuration table.
func DMS() Migration {
	return Migration{Version: 5, Name: "dms", Statements: []string{
		`CREATE TABLE dms (
			id VARCHAR2(512 CHAR) NOT NULL,
			name VARCHAR2(1000 CHAR),
			metadata JSON,
			creation_date TIMESTAMP WITH TIME ZONE,
			settings JSON,
			CONSTRAINT lamassu_dms_pk PRIMARY KEY (id)
		)`,
	}}
}
