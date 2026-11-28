package migrations

// Devices creates devices, their event history and hierarchical groups.
func Devices() Migration {
	return Migration{Version: 7, Name: "devices", Statements: []string{
		`INSERT INTO lamassu_locks (lock_id) VALUES ('device_groups')`,
		`CREATE TABLE devices (
			id VARCHAR2(512 CHAR) NOT NULL,
			tags JSON,
			status VARCHAR2(255 CHAR),
			icon CLOB,
			icon_color VARCHAR2(255 CHAR),
			creation_timestamp TIMESTAMP WITH TIME ZONE,
			metadata JSON,
			dms_owner VARCHAR2(512 CHAR),
			identity_slot JSON,
			extra_slots JSON,
			CONSTRAINT lamassu_device_pk PRIMARY KEY (id)
		)`,
		`CREATE INDEX lamassu_device_dms_idx ON devices (dms_owner)`,
		`CREATE TABLE device_events (
			id VARCHAR2(512 CHAR) NOT NULL,
			device_id VARCHAR2(512 CHAR) NOT NULL,
			event_ts TIMESTAMP WITH TIME ZONE NOT NULL,
			event_type VARCHAR2(255 CHAR) NOT NULL,
			description CLOB,
			source VARCHAR2(1000 CHAR),
			structured_fields JSON,
			CONSTRAINT lamassu_device_event_pk PRIMARY KEY (id),
			CONSTRAINT lamassu_device_event_fk FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
		)`,
		`CREATE INDEX lamassu_de_device_time_idx ON device_events (device_id, event_ts DESC)`,
		`CREATE INDEX lamassu_de_event_type_idx ON device_events (event_type)`,
		`CREATE TABLE device_groups (
			id VARCHAR2(36 CHAR) NOT NULL,
			name VARCHAR2(1000 CHAR) NOT NULL,
			description CLOB,
			parent_id VARCHAR2(36 CHAR),
			criteria JSON NOT NULL,
			created_at TIMESTAMP WITH TIME ZONE,
			updated_at TIMESTAMP WITH TIME ZONE,
			CONSTRAINT lamassu_group_pk PRIMARY KEY (id),
			CONSTRAINT lamassu_group_name_uk UNIQUE (name),
			CONSTRAINT lamassu_group_parent_fk FOREIGN KEY (parent_id) REFERENCES device_groups(id) ON DELETE CASCADE
		)`,
		`CREATE INDEX lamassu_group_parent_idx ON device_groups (parent_id)`,
	}}
}
