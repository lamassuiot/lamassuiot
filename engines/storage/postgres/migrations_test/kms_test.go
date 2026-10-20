package migrationstest

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"testing"
	"time"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/config"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/helpers"
	postgres "github.com/lamassuiot/lamassuiot/v4/engines/storage/postgres"
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

func migrationTest_KMS_20261020100000_reconcile_key_bindings(t *testing.T, logger *logrus.Entry, con *gorm.DB) {
	// The CA schema shares the database. Only the columns the migration reads are created.
	require.NoError(t, con.Exec(`
		CREATE SCHEMA ca;
		CREATE TABLE ca.certificates (serial_number text PRIMARY KEY, certificate text, engine_id text, is_ca boolean);
		CREATE TABLE ca.ca_certificates (id text PRIMARY KEY, serial_number text);
	`).Error)

	newCert := func(cn string) (string, string) {
		cert, _, err := helpers.GenerateSelfSignedCA(x509.RSA, time.Hour, cn)
		require.NoError(t, err)
		spki, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
		require.NoError(t, err)
		digest := sha256.Sum256(spki)
		return base64.StdEncoding.EncodeToString([]byte(helpers.CertificateToPEM(cert))), hex.EncodeToString(digest[:])
	}
	insertCert := func(sn, certificate, engineID string, isCA bool) {
		require.NoError(t, con.Exec(`INSERT INTO ca.certificates VALUES (?, ?, ?, ?)`, sn, certificate, engineID, isCA).Error)
	}
	insertKey := func(keyID, engineID, metadata string) {
		require.NoError(t, con.Exec(`INSERT INTO kms_keys
			(key_id, metadata, "name", algorithm, size, public_key, creation_ts, engine_id, has_private_key)
			VALUES(?, ?::jsonb, 'key', 'RSA', 2048, 'pub', '2024-11-25 10:46:28.914', ?, true)`, keyID, metadata, engineID).Error)
	}
	bindings := func(keyID, engineID string) string {
		var value string
		require.NoError(t, con.Raw(`SELECT COALESCE(metadata->>'lamassu.io/kms/binded-resources', 'absent') FROM kms_keys WHERE key_id = ? AND engine_id = ?`, keyID, engineID).Scan(&value).Error)
		return value
	}

	// A CA and its cross-signed CA share a key; the cross-signed CA was deleted, which left its
	// certificate behind. The key was bound twice to the CA and once to a device.
	caPEM, caKey := newCert("ca")
	insertCert("ca-sn", caPEM, "e1", true)
	require.NoError(t, con.Exec(`INSERT INTO ca.ca_certificates VALUES ('ca-id', 'ca-sn')`).Error)
	insertCert("deleted-cross-sn", caPEM, "e1", true)
	insertKey(caKey, "e1", `{"owner": "x", "lamassu.io/kms/binded-resources": [
		{"resource_type": "certificate", "resource_id": "ca-sn"},
		{"resource_type": "certificate", "resource_id": "ca-sn"},
		{"resource_type": "certificate", "resource_id": "deleted-cross-sn"},
		{"resource_type": "device", "resource_id": "d1"}]}`)
	// The same key in another engine, which no certificate points to.
	insertKey(caKey, "e2", `{}`)

	// A certificate whose key Lamassu generated, never bound.
	leafPEM, leafKey := newCert("leaf")
	insertCert("leaf-sn", leafPEM, "e1", false)
	insertKey(leafKey, "e1", `{}`)

	// A key still bound, as a JSON-encoded string, to a certificate that no longer exists.
	_, staleKey := newCert("stale")
	insertKey(staleKey, "e1", `{"lamassu.io/kms/binded-resources": "[{\"resource_type\":\"certificate\",\"resource_id\":\"gone-sn\"}]"}`)

	// A certificate without a key in the KMS.
	externalPEM, _ := newCert("external")
	insertCert("external-sn", externalPEM, "", false)

	ApplyMigration(t, logger, con, kmsDBName)

	assert.JSONEq(t, `[{"resource_type": "device", "resource_id": "d1"}, {"resource_type": "certificate", "resource_id": "ca-sn"}]`, bindings(caKey, "e1"))
	var owner string
	con.Raw(`SELECT metadata->>'owner' FROM kms_keys WHERE key_id = ? AND engine_id = 'e1'`, caKey).Scan(&owner)
	assert.Equal(t, "x", owner, "other metadata must be kept")
	assert.Equal(t, "absent", bindings(caKey, "e2"))
	assert.JSONEq(t, `[{"resource_type": "certificate", "resource_id": "leaf-sn"}]`, bindings(leafKey, "e1"))
	assert.JSONEq(t, `[]`, bindings(staleKey, "e1"))
}

// On a fresh installation the KMS can be migrated before the CA schema exists.
func TestKMSReconcileKeyBindingsWithoutCASchema(t *testing.T) {
	logger := helpers.SetupLogger(config.Info, "test", "test")
	cleanup, con := RunDB(t, logger, kmsDBName)
	defer cleanup()

	_, err := postgres.NewMigrator(logger, con).Goose.Up(context.Background())
	require.NoError(t, err)
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

	migrationTest_KMS_20261020100000_reconcile_key_bindings(t, logger, con)
	if t.Failed() {
		t.Fatalf("failed while running migration v20261020100000_reconcile_key_bindings")
	}
}
