package migrations

// BinarySortIndexes indexes the keyset columns that the repositories order and
// paginate by as NLSSORT(column, 'NLS_SORT=BINARY'). Without them, ordering by
// that expression cannot use the primary-key indexes, so every page reads and
// sorts all matching rows.
//
// Each index ends with the constant 0. A B-tree index omits rows whose keys are
// all NULL; the non-NULL constant guarantees every row is indexed, so the
// optimizer can always return rows in index order and stop after the page.
// A constant is used instead of the original column to keep the key short:
// with MAX_STRING_SIZE=STANDARD each NLSSORT key is a RAW(2000), and appending
// a VARCHAR2(512 CHAR) would bring the kms_keys index close to the 6398-byte
// key limit of 8 KB blocks.
func BinarySortIndexes() Migration {
	return Migration{Version: 9, Name: "binary sort indexes", Statements: []string{
		`CREATE INDEX lamassu_cert_sort_idx ON certificates (NLSSORT(serial_number, 'NLS_SORT=BINARY'), 0)`,
		`CREATE INDEX lamassu_ca_sort_idx ON ca_certificates (NLSSORT(id, 'NLS_SORT=BINARY'), 0)`,
		`CREATE INDEX lamassu_kms_sort_idx ON kms_keys (NLSSORT(key_id, 'NLS_SORT=BINARY'), NLSSORT(engine_id, 'NLS_SORT=BINARY'), 0)`,
		`CREATE INDEX lamassu_profile_sort_idx ON issuance_profiles (NLSSORT(id, 'NLS_SORT=BINARY'), 0)`,
		`CREATE INDEX lamassu_va_sort_idx ON va_role (NLSSORT(ca_ski, 'NLS_SORT=BINARY'), 0)`,
		`CREATE INDEX lamassu_dms_sort_idx ON dms (NLSSORT(id, 'NLS_SORT=BINARY'), 0)`,
		`CREATE INDEX lamassu_event_sort_idx ON events (NLSSORT(event_type, 'NLS_SORT=BINARY'), 0)`,
		`CREATE INDEX lamassu_sub_sort_idx ON subscriptions (NLSSORT(id, 'NLS_SORT=BINARY'), 0)`,
		`CREATE INDEX lamassu_device_sort_idx ON devices (NLSSORT(id, 'NLS_SORT=BINARY'), 0)`,
		`CREATE INDEX lamassu_de_sort_idx ON device_events (NLSSORT(id, 'NLS_SORT=BINARY'), 0)`,
		`CREATE INDEX lamassu_group_sort_idx ON device_groups (NLSSORT(id, 'NLS_SORT=BINARY'), 0)`,
	}}
}
