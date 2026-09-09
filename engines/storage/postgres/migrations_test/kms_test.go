package migrationstest

import (
	"testing"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/stretchr/testify/assert"

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
	ApplyMigration(t, logger, con, kmsDBName)

	var pkCols string
	tx := con.Raw(`
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
}
