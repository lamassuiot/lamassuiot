package migrationstest

import (
	"testing"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/config"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/helpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

var kmsDBName = "kms"

func migrationTest_KMS_00000000000001_create_table(t *testing.T, logger *logrus.Entry, con *gorm.DB) {
	ApplyMigration(t, logger, con, kmsDBName)

	tx := con.Exec(`INSERT INTO kms_keys
		(id, metadata, "name", algorithm, size, public_key, status, creation_ts)
		VALUES('pkcs11:token-id=hsm-offline;id=abc123;type=private', '{}', 'MyKey', 'RSA', 2048, 'pub', 'ACTIVE', '2024-11-25 10:46:28.914');
	`)
	if tx.Error != nil {
		t.Fatalf("failed to insert row: %v", tx.Error)
	}
}

func migrationTest_KMS_20251031174938_key(t *testing.T, logger *logrus.Entry, con *gorm.DB) {
	ApplyMigration(t, logger, con, kmsDBName)

	var engineID, keyID string
	tx := con.Raw("SELECT engine_id, key_id FROM kms_keys").Row().Scan(&engineID, &keyID)
	if tx != nil {
		t.Fatalf("failed to read split columns: %v", tx)
	}

	assert.Equal(t, "hsm-offline", engineID)
	assert.Equal(t, "abc123", keyID)
}

func migrationTest_KMS_20260909084500_kms_key_composite_pk(t *testing.T, logger *logrus.Entry, con *gorm.DB) {
	// Earlier versions accepted an alias equal to another key's key_id. Once key_id wins
	// over an alias, that alias would address the other key, so the migration drops it.
	tx := con.Exec(`INSERT INTO kms_keys
		(key_id, metadata, "name", algorithm, size, public_key, creation_ts, engine_id, aliases)
		VALUES('def456', '{}', 'Other', 'RSA', 2048, 'pub', '2024-11-25 10:46:28.914', 'hsm-offline', '["abc123", "keep-me", "def456"]');
	`)
	if tx.Error != nil {
		t.Fatalf("failed to insert a key with a shadowed alias: %v", tx.Error)
	}

	ApplyMigration(t, logger, con, kmsDBName)

	var aliases string
	tx = con.Raw("SELECT aliases::text FROM kms_keys WHERE key_id = 'def456'").Scan(&aliases)
	if tx.Error != nil {
		t.Fatalf("failed to read aliases: %v", tx.Error)
	}
	assert.JSONEq(t, `["keep-me"]`, aliases, "aliases equal to a key_id must be dropped, the rest kept")

	var abcAliases string
	con.Raw("SELECT aliases::text FROM kms_keys WHERE key_id = 'abc123'").Scan(&abcAliases)
	assert.JSONEq(t, `[]`, abcAliases, "keys without colliding aliases must be left alone")

	var pkCols string
	tx = con.Raw(`
		SELECT string_agg(a.attname, ',' ORDER BY k.ord)
		FROM pg_constraint con
		JOIN pg_class c ON c.oid = con.conrelid
		JOIN unnest(con.conkey) WITH ORDINALITY AS k(attnum, ord) ON true
		JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum = k.attnum
		WHERE c.relname = 'kms_keys' AND con.contype = 'p'`).Scan(&pkCols)
	if tx.Error != nil {
		t.Fatalf("failed to read primary key columns: %v", tx.Error)
	}
	assert.Equal(t, "key_id,engine_id", pkCols)

	var aliasesIndexDef string
	tx = con.Raw("SELECT indexdef FROM pg_indexes WHERE tablename = 'kms_keys' AND indexname = 'kms_keys_aliases_idx'").Scan(&aliasesIndexDef)
	if tx.Error != nil {
		t.Fatalf("failed to read the aliases index: %v", tx.Error)
	}
	assert.Contains(t, aliasesIndexDef, "gin")
	assert.Contains(t, aliasesIndexDef, "jsonb_path_ops")

	// The point of the composite key: the same key_id in two engines, e.g. the private key
	// in an offline HSM and the public key in an online engine.
	insert := con.Exec(`INSERT INTO kms_keys
		(key_id, metadata, "name", algorithm, size, public_key, creation_ts, engine_id, has_private_key)
		VALUES('abc123', '{}', 'MyKey', 'RSA', 2048, 'pub', '2024-11-25 10:46:28.914', 'online-1', false);
	`)
	if insert.Error != nil {
		t.Fatalf("could not store the same key_id in a second engine: %v", insert.Error)
	}

	var engines int64
	con.Raw("SELECT count(*) FROM kms_keys WHERE key_id = 'abc123'").Scan(&engines)
	assert.EqualValues(t, 2, engines)

	// A duplicate within the same engine is still rejected.
	dup := con.Exec(`INSERT INTO kms_keys
		(key_id, metadata, "name", algorithm, size, public_key, creation_ts, engine_id, has_private_key)
		VALUES('abc123', '{}', 'MyKey', 'RSA', 2048, 'pub', '2024-11-25 10:46:28.914', 'online-1', false);
	`)
	assert.Error(t, dup.Error, "the same key_id must not be storable twice in one engine")
}

func migrationTest_KMS_20261027110000_key_bindings(t *testing.T, logger *logrus.Entry, con *gorm.DB) {
	ApplyMigration(t, logger, con, kmsDBName)

	// A key with bindings cannot be deleted.
	require.NoError(t, con.Exec(`INSERT INTO key_bindings (key_id, engine_id, resource_type, resource_id) VALUES ('abc123', 'online-1', 'certificate', 'in-use')`).Error)
	assert.Error(t, con.Exec(`DELETE FROM kms_keys WHERE key_id = 'abc123' AND engine_id = 'online-1'`).Error)
	require.NoError(t, con.Exec(`DELETE FROM key_bindings WHERE resource_id = 'in-use'`).Error)
}

func migrationTest_KMS_20261027110100_move_legacy_key_bindings(t *testing.T, logger *logrus.Entry, con *gorm.DB) {
	insertKey := func(keyID, metadata string) {
		t.Helper()
		require.NoError(t, con.Exec(`INSERT INTO kms_keys
			(key_id, metadata, "name", algorithm, size, public_key, creation_ts, engine_id, has_private_key)
			VALUES(?, ?::jsonb, 'Legacy', 'ECDSA', 256, 'pub', '2026-01-01 00:00:00', 'legacy-engine', true)`, keyID, metadata).Error)
	}
	insertKey("array", `{"owner": "pki", "lamassu.io/kms/binded-resources": [{"resource_type": "certificate", "resource_id": "s1"}, {"resource_type": "certificate", "resource_id": "s2"}]}`)
	insertKey("object", `{"lamassu.io/kms/binded-resources": {"resource_type": "certificate", "resource_id": "s3"}}`)
	insertKey("string", `{"lamassu.io/kms/binded-resources": "[{\"resource_type\": \"certificate\", \"resource_id\": \"s4\"}]"}`)
	insertKey("duplicated", `{"lamassu.io/kms/binded-resources": [{"resource_type": "certificate", "resource_id": "s5"}, {"resource_type": "certificate", "resource_id": "s5"}]}`)
	insertKey("other-type", `{"lamassu.io/kms/binded-resources": [{"resource_type": "device", "resource_id": "d1"}, {"resource_type": "certificate", "resource_id": ""}]}`)
	insertKey("unreadable", `{"lamassu.io/kms/binded-resources": "not bindings"}`)

	ApplyMigration(t, logger, con, kmsDBName)

	bindingsOf := func(keyID string) []string {
		t.Helper()
		var rows []string
		require.NoError(t, con.Raw(`SELECT resource_type || '/' || resource_id FROM key_bindings WHERE key_id = ? AND engine_id = 'legacy-engine' ORDER BY 1`, keyID).Scan(&rows).Error)
		return rows
	}
	metadataOf := func(keyID string) string {
		t.Helper()
		var metadata string
		require.NoError(t, con.Raw(`SELECT metadata::text FROM kms_keys WHERE key_id = ? AND engine_id = 'legacy-engine'`, keyID).Scan(&metadata).Error)
		return metadata
	}

	assert.Equal(t, []string{"certificate/s1", "certificate/s2"}, bindingsOf("array"))
	assert.JSONEq(t, `{"owner": "pki"}`, metadataOf("array"), "the bindings leave the metadata, the rest stays")
	assert.Equal(t, []string{"certificate/s3"}, bindingsOf("object"))
	assert.JSONEq(t, `{}`, metadataOf("object"))
	assert.Equal(t, []string{"certificate/s4"}, bindingsOf("string"))
	assert.Equal(t, []string{"certificate/s5"}, bindingsOf("duplicated"))
	assert.Equal(t, []string{"device/d1"}, bindingsOf("other-type"), "entries without a resource are dropped")
	assert.Empty(t, bindingsOf("unreadable"))
	assert.JSONEq(t, `{"lamassu.io/kms/binded-resources": "not bindings"}`, metadataOf("unreadable"), "unreadable bindings are left as they were")

	RollbackMigration(t, logger, con, kmsDBName, "20261027110100_move_legacy_key_bindings")
	assert.Empty(t, bindingsOf("array"))
	assert.JSONEq(t, `{"owner": "pki", "lamassu.io/kms/binded-resources": [{"resource_type": "certificate", "resource_id": "s1"}, {"resource_type": "certificate", "resource_id": "s2"}]}`, metadataOf("array"))

	// Leave the schema at the latest version for any later migration test.
	ApplyMigration(t, logger, con, kmsDBName)
	assert.Equal(t, []string{"certificate/s1", "certificate/s2"}, bindingsOf("array"))
}

func TestKMSMigrations(t *testing.T) {
	logger := helpers.SetupLogger(config.Info, "test", "test")
	cleanup, con := RunDB(t, logger, kmsDBName)

	defer cleanup()

	migrationTest_KMS_00000000000001_create_table(t, logger, con)
	if t.Failed() {
		t.Fatalf("failed while running migration v00000000000001_create_table")
	}

	migrationTest_KMS_20251031174938_key(t, logger, con)
	if t.Failed() {
		t.Fatalf("failed while running migration v20251031174938_key")
	}

	migrationTest_KMS_20260909084500_kms_key_composite_pk(t, logger, con)
	if t.Failed() {
		t.Fatalf("failed while running migration v20260909084500_kms_key_composite_pk")
	}

	migrationTest_KMS_20261027110000_key_bindings(t, logger, con)
	if t.Failed() {
		t.Fatalf("failed while running migration v20261027110000_key_bindings")
	}

	migrationTest_KMS_20261027110100_move_legacy_key_bindings(t, logger, con)
	if t.Failed() {
		t.Fatalf("failed while running migration v20261027110100_move_legacy_key_bindings")
	}
}
