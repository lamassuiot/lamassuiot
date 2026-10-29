package migrationstest

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	postgres "github.com/lamassuiot/lamassuiot/v4/engines/storage/postgres"
	"strings"
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
	insertKey := func(keyID, metadata string) {
		t.Helper()
		require.NoError(t, con.Exec(`INSERT INTO kms_keys
			(key_id, metadata, "name", algorithm, size, public_key, creation_ts, engine_id, has_private_key)
			VALUES(?, ?::jsonb, 'Legacy', 'ECDSA', 256, 'pub', '2026-01-01 00:00:00', 'legacy-engine', true)`, keyID, metadata).Error)
	}
	const legacyBindings = "lamassu.io/kms/binded-resources"

	// Bindings earlier versions kept in the key metadata, in every format they used.
	insertKey("array", `{"owner": "pki", "`+legacyBindings+`": [{"resource_type": "certificate", "resource_id": "s1"}, {"resource_type": "certificate", "resource_id": "s2"}]}`)
	insertKey("object", `{"`+legacyBindings+`": {"resource_type": "certificate", "resource_id": "s3"}}`)
	insertKey("string", `{"`+legacyBindings+`": "[{\"resource_type\": \"certificate\", \"resource_id\": \"s4\"}]"}`)
	insertKey("duplicated", `{"`+legacyBindings+`": [{"resource_type": "certificate", "resource_id": "s5"}, {"resource_type": "certificate", "resource_id": "s5"}]}`)
	insertKey("other-type", `{"`+legacyBindings+`": [{"resource_type": "device", "resource_id": "d1"}, {"resource_type": "certificate", "resource_id": ""}]}`)
	insertKey("unreadable", `{"`+legacyBindings+`": "not bindings"}`)

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
	assert.JSONEq(t, `{"`+legacyBindings+`": "not bindings"}`, metadataOf("unreadable"), "unreadable bindings are left as they were")

	// A key with bindings cannot be deleted.
	assert.Error(t, con.Exec(`DELETE FROM kms_keys WHERE key_id = 'array' AND engine_id = 'legacy-engine'`).Error)

	RollbackMigration(t, logger, con, kmsDBName, "20261027110000_key_bindings")
	assert.JSONEq(t, `{"owner": "pki", "`+legacyBindings+`": [{"resource_type": "certificate", "resource_id": "s1"}, {"resource_type": "certificate", "resource_id": "s2"}]}`, metadataOf("array"))

	// Leave the schema at the latest version for any later migration test.
	ApplyMigration(t, logger, con, kmsDBName)
	assert.Equal(t, []string{"certificate/s1", "certificate/s2"}, bindingsOf("array"))
}

func migrationTest_KMS_20261027110200_backfill_certificate_key_bindings(t *testing.T, logger *logrus.Entry, con *gorm.DB) {
	const name = "20261027110200_backfill_certificate_key_bindings"
	bindingsOf := func(keyID, engineID string) []string {
		t.Helper()
		rows := []string{}
		require.NoError(t, con.Raw(`SELECT resource_type || '/' || resource_id FROM key_bindings WHERE key_id = ? AND engine_id = ? ORDER BY 1`, keyID, engineID).Scan(&rows).Error)
		return rows
	}

	// A fresh installation, or the KMS migrated first: there are no certificates to bind.
	ApplyMigration(t, logger, con, kmsDBName)
	assert.Equal(t, []string{"certificate/s1", "certificate/s2"}, bindingsOf("array", "legacy-engine"), "nothing changes without the CA schema")
	RollbackMigration(t, logger, con, kmsDBName, name)

	// The CA schema has not been migrated to key_id yet: the migration must not silently skip.
	require.NoError(t, con.Exec(`CREATE SCHEMA ca`).Error)
	require.NoError(t, con.Exec(`CREATE TABLE ca.certificates (serial_number text PRIMARY KEY, certificate text, engine_id text NOT NULL DEFAULT '', is_ca boolean NOT NULL DEFAULT false, metadata jsonb NULL)`).Error)
	require.NoError(t, con.Exec(`CREATE TABLE ca.ca_certificates (serial_number text PRIMARY KEY)`).Error)
	m := postgres.NewMigrator(logger, con)
	var version int64
	for _, src := range m.Goose.ListSources() {
		if strings.Contains(src.Path, name) {
			version = src.Version
		}
	}
	require.NotZero(t, version)
	_, err := m.Goose.ApplyVersion(context.Background(), version, true)
	require.ErrorContains(t, err, "migrate the ca schema first")

	require.NoError(t, con.Exec(`ALTER TABLE ca.certificates ADD COLUMN key_id text NOT NULL DEFAULT ''`).Error)
	insertCert := func(serial, keyID, engineID string, isCA, currentCA bool) {
		t.Helper()
		require.NoError(t, con.Exec(`INSERT INTO ca.certificates (serial_number, key_id, engine_id, is_ca) VALUES (?, ?, ?, ?)`, serial, keyID, engineID, isCA).Error)
		if currentCA {
			require.NoError(t, con.Exec(`INSERT INTO ca.ca_certificates (serial_number) VALUES (?)`, serial).Error)
		}
	}
	insertCert("s1", "array", "legacy-engine", false, false)           // already bound: kept
	insertCert("ca-current", "object", "legacy-engine", true, true)    // current CA certificate: bound
	insertCert("ca-old", "object", "legacy-engine", true, false)       // deleted CA: not bound
	insertCert("ca-previous", "object", "legacy-engine", true, false)  // reissued as ca-current: bound
	insertCert("ca-first", "object", "legacy-engine", true, false)     // reissued as ca-previous: bound
	insertCert("ca-other-key", "string", "legacy-engine", true, false) // reissued from, with another key: not bound
	insertCert("ca-forger", "object", "legacy-engine", true, true)     // current CA certificate: bound
	insertCert("ca-orphan", "object", "legacy-engine", true, false)    // only a forged reissued-from points at it: not bound
	setMetadata := func(serial, key, value string) {
		t.Helper()
		require.NoError(t, con.Exec(`UPDATE ca.certificates SET metadata = COALESCE(metadata, '{}'::jsonb) || jsonb_build_object(?::text, ?::text) WHERE serial_number = ?`,
			key, value, serial).Error)
	}
	reissued := func(previous, current string) {
		t.Helper()
		setMetadata(current, "lamassu.io/ca/reissued-from", previous)
		setMetadata(previous, "lamassu.io/ca/reissued-as", current)
	}
	reissued("ca-previous", "ca-current")
	reissued("ca-first", "ca-previous")
	reissued("ca-other-key", "ca-first")
	setMetadata("ca-forger", "lamassu.io/ca/reissued-from", "ca-orphan")
	insertCert("leaf-new", "abc123", "online-1", false, false)             // never bound before: bound
	insertCert("leaf-no-key", "not-in-kms", "legacy-engine", false, false) // key unknown to the KMS: skipped
	insertCert("s4", "", "legacy-engine", false, false)                    // unreadable certificate: its binding is kept
	insertCert("external", "", "", false, false)                           // key outside the KMS

	// A CA issued by OpenSSL, whose SKI is not the key ID: it is bound by the key_id the CA records.
	opensslCert := base64.StdEncoding.EncodeToString([]byte(opensslCACertPEM))
	opensslBlock, _ := pem.Decode([]byte(opensslCACertPEM))
	opensslX509, err := x509.ParseCertificate(opensslBlock.Bytes)
	require.NoError(t, err)
	opensslSPKI, err := x509.MarshalPKIXPublicKey(opensslX509.PublicKey)
	require.NoError(t, err)
	require.NoError(t, con.Exec(`INSERT INTO kms_keys (key_id, metadata, "name", algorithm, size, public_key, creation_ts, engine_id, has_private_key)
		VALUES (?, '{}'::jsonb, 'OpenSSL CA', 'ECDSA', 256, ?, '2026-01-01 00:00:00', 'legacy-engine', true)`,
		opensslCAKeyID, base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: opensslSPKI}))).Error)
	require.NoError(t, con.Exec(`INSERT INTO ca.certificates (serial_number, certificate, key_id, engine_id, is_ca) VALUES ('openssl-ca', ?, ?, 'legacy-engine', true)`,
		opensslCert, opensslCAKeyID).Error)
	require.NoError(t, con.Exec(`INSERT INTO ca.ca_certificates (serial_number) VALUES ('openssl-ca')`).Error)

	ApplyMigration(t, logger, con, kmsDBName)

	assert.Equal(t, []string{"certificate/s1"}, bindingsOf("array", "legacy-engine"), "s2 is no longer a certificate")
	assert.Equal(t, []string{"certificate/ca-current", "certificate/ca-first", "certificate/ca-forger", "certificate/ca-previous"}, bindingsOf("object", "legacy-engine"),
		"the current certificate of each CA and the ones it reissued, linked both ways")
	assert.Equal(t, []string{"certificate/s4"}, bindingsOf("string", "legacy-engine"))
	assert.Empty(t, bindingsOf("duplicated", "legacy-engine"))
	assert.Equal(t, []string{"device/d1"}, bindingsOf("other-type", "legacy-engine"), "only certificate bindings are rebuilt")
	assert.Equal(t, []string{"certificate/leaf-new"}, bindingsOf("abc123", "online-1"))
	assert.Equal(t, []string{"certificate/openssl-ca"}, bindingsOf(opensslCAKeyID, "legacy-engine"), "bound by key_id, whatever the SKI")

	var keyID string
	require.NoError(t, con.Raw(`SELECT key_id FROM ca.certificates WHERE serial_number = 'openssl-ca'`).Scan(&keyID).Error)
	assert.Equal(t, opensslCAKeyID, keyID, "certificates keep the key_id the CA recorded")
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

	migrationTest_KMS_20261027110200_backfill_certificate_key_bindings(t, logger, con)
	if t.Failed() {
		t.Fatalf("failed while running migration v20261027110200_backfill_certificate_key_bindings")
	}
}
