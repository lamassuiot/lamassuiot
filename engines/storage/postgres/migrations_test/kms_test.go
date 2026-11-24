package migrationstest

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/config"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v4/engines/storage/postgres"
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

func migrationTest_KMS_20261030120100_drop_legacy_key_bindings(t *testing.T, logger *logrus.Entry, con *gorm.DB) {
	// Earlier versions recorded the certificates that use a key in its metadata and never removed them.
	// The certificates reference their key now, so the stale list goes and the rest of the metadata stays.
	tx := con.Exec(`INSERT INTO kms_keys
		(key_id, metadata, "name", algorithm, size, public_key, creation_ts, engine_id, has_private_key)
		VALUES
		('legacy-bound', '{"lamassu.io/kms/binded-resources": [{"resource_type":"certificate","resource_id":"aa"}], "owner": "team-a"}', 'Bound', 'RSA', 2048, 'pub', '2024-11-25 10:46:28.914', 'hsm-offline', true),
		('legacy-plain', '{"owner": "team-b"}', 'Plain', 'RSA', 2048, 'pub', '2024-11-25 10:46:28.914', 'hsm-offline', true);
	`)
	if tx.Error != nil {
		t.Fatalf("failed to insert keys with legacy bindings: %v", tx.Error)
	}

	ApplyMigration(t, logger, con, kmsDBName)

	metadata := func(keyID string) string {
		var value string
		if err := con.Raw(`SELECT metadata::text FROM kms_keys WHERE key_id = ?`, keyID).Scan(&value).Error; err != nil {
			t.Fatalf("failed to read the metadata of %s: %v", keyID, err)
		}
		return value
	}
	assert.JSONEq(t, `{"owner": "team-a"}`, metadata("legacy-bound"), "only the legacy bindings are removed")
	assert.JSONEq(t, `{"owner": "team-b"}`, metadata("legacy-plain"))

	// Rolling back has nothing to restore: the bindings were derived data.
	RollbackMigration(t, logger, con, kmsDBName, "20261030120100_drop_legacy_key_bindings")
	assert.JSONEq(t, `{"owner": "team-a"}`, metadata("legacy-bound"))
}

// kmsKeyFixture returns a fresh public key the way the KMS stores it (the base64 of its PEM encoding)
// and the digest the KMS names that key after.
func kmsKeyFixture(t *testing.T) (publicKey, digest string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	spki, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	require.NoError(t, err)
	digest, err = helpers.PublicKeyDigest(&priv.PublicKey)
	require.NoError(t, err)
	return base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: spki})), digest
}

func insertKMSKey(t *testing.T, con interface {
	Exec(sql string, values ...interface{}) *gorm.DB
}, keyID, engineID, publicKey, aliases string, hasPrivateKey bool) {
	t.Helper()
	require.NoError(t, con.Exec(`INSERT INTO kms_keys
		(key_id, engine_id, metadata, "name", algorithm, size, public_key, creation_ts, aliases, has_private_key)
		VALUES (?, ?, '{}', ?, 'ECDSA', 256, ?, now(), ?::jsonb, ?)`,
		keyID, engineID, "key-"+keyID, publicKey, aliases, hasPrivateKey).Error, "insert key %s", keyID)
}

func migrationTest_KMS_20261124100000_kms_key_identity(t *testing.T, logger *logrus.Entry, con *gorm.DB) {
	// The fixtures of the earlier migrations carry placeholder public keys; the KMS never stores those.
	require.NoError(t, con.Exec(`DELETE FROM kms_keys`).Error)

	publicA := kmsPublicKey(t, opensslCACertPEM)
	publicB, digestB := kmsKeyFixture(t)
	publicC, digestC := kmsKeyFixture(t)
	const skiB, skiC = "b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0", "c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0"

	// A: a key named by its digest, held by two engines (the private key in one, the public key in the other)
	insertKMSKey(t, con, opensslCAKeyID, "e1", publicA, `[]`, true)
	insertKMSKey(t, con, opensslCAKeyID, "e2", publicA, `[]`, false)
	// B: a key of a CA imported before the KMS: the engine holds it under the SKI, nothing else registers it
	// aliases written when nothing kept them from looking like an id or a digest: an identifier of those shapes is no
	// longer looked up as an alias, so they could never be used
	insertKMSKey(t, con, skiB, "e1", publicB, `["keep-me", "0190a6c4-7f3e-7b2a-9c1d-3e5f6a7b8c9d", "`+strings.ToUpper(digestC)+`"]`, true)
	// C: the key of an imported CA registered twice: under its digest by the KMS and under its SKI by the migration tool
	insertKMSKey(t, con, digestC, "e1", publicC, `["real-alias"]`, true)
	insertKMSKey(t, con, skiC, "e1", publicC, `["ghost-alias"]`, true)

	ApplyMigration(t, logger, con, kmsDBName)

	type row struct {
		KeyID, EngineID, ID, Digest, Aliases string
	}
	rows := map[string]row{}
	var all []row
	require.NoError(t, con.Raw(`SELECT key_id AS key_id, engine_id, id::text AS id, digest, aliases::text AS aliases FROM kms_keys`).Scan(&all).Error)
	ids := map[string]bool{}
	for _, r := range all {
		rows[r.KeyID+"@"+r.EngineID] = r
		assert.NotEmpty(t, r.ID, "every key gets an id")
		assert.False(t, ids[r.ID], "ids are unique")
		ids[r.ID] = true
	}

	t.Run("every key gets the digest of its public key", func(t *testing.T) {
		assert.Equal(t, opensslCAKeyID, rows[opensslCAKeyID+"@e1"].Digest)
		assert.Equal(t, opensslCAKeyID, rows[opensslCAKeyID+"@e2"].Digest, "the same key in another engine has the same digest")
		assert.Equal(t, digestB, rows[skiB+"@e1"].Digest, "a key named by its SKI keeps that name and gets its real digest")
		assert.Equal(t, digestC, rows[digestC+"@e1"].Digest)
	})

	t.Run("a key registered twice in an engine keeps the row named by its digest", func(t *testing.T) {
		assert.Len(t, all, 4)
		_, ghostLeft := rows[skiC+"@e1"]
		assert.False(t, ghostLeft, "the row named by the SKI, which no engine holds, is removed")

		var aliases []string
		require.NoError(t, json.Unmarshal([]byte(rows[digestC+"@e1"].Aliases), &aliases))
		assert.ElementsMatch(t, []string{"real-alias", "ghost-alias", skiC}, aliases,
			"the survivor keeps what could address the removed row: its aliases and its old name")
	})

	t.Run("aliases shaped like an id or a digest are dropped, the rest kept", func(t *testing.T) {
		var aliases []string
		require.NoError(t, json.Unmarshal([]byte(rows[skiB+"@e1"].Aliases), &aliases))
		assert.Equal(t, []string{"keep-me"}, aliases)
	})

	t.Run("a key cannot be registered twice in the same engine under different names", func(t *testing.T) {
		err := con.Exec(`INSERT INTO kms_keys (key_id, engine_id, metadata, "name", algorithm, size, public_key, creation_ts, digest)
			VALUES ('another-name', 'e1', '{}', 'dup', 'ECDSA', 256, ?, now(), ?)`, publicB, digestB).Error
		assert.Error(t, err)
	})

	t.Run("the digest must have the shape of a digest", func(t *testing.T) {
		assert.Error(t, con.Exec(`INSERT INTO kms_keys (key_id, engine_id, metadata, "name", algorithm, size, public_key, creation_ts, digest)
			VALUES ('short', 'e3', '{}', 'x', 'ECDSA', 256, 'pk', now(), 'abc')`).Error)
		assert.Error(t, con.Exec(`INSERT INTO kms_keys (key_id, engine_id, metadata, "name", algorithm, size, public_key, creation_ts)
			VALUES ('nodigest', 'e3', '{}', 'x', 'ECDSA', 256, 'pk', now())`).Error, "the digest is required")
	})

	t.Run("a new key gets its id from the database", func(t *testing.T) {
		require.NoError(t, con.Exec(`INSERT INTO kms_keys (key_id, engine_id, metadata, "name", algorithm, size, public_key, creation_ts, digest)
			VALUES ('fresh', 'e3', '{}', 'x', 'ECDSA', 256, 'pk', now(), repeat('a', 64))`).Error)
		var id string
		require.NoError(t, con.Raw(`SELECT id::text FROM kms_keys WHERE key_id = 'fresh'`).Scan(&id).Error)
		assert.Regexp(t, `^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`, id)
	})

	RollbackMigration(t, logger, con, kmsDBName, "20261124100000_kms_key_identity")
	var columns int64
	require.NoError(t, con.Raw(`SELECT count(*) FROM information_schema.columns
		WHERE table_schema = 'kms' AND table_name = 'kms_keys' AND column_name IN ('id', 'digest')`).Scan(&columns).Error)
	assert.Zero(t, columns, "rolling back removes the new columns")
}

// TestKMSKeyIdentityMigrationWithReferences covers installations whose ca and va schemas already reference
// the KMS keys: the row the migration removes may be the one a certificate or a CRL signer points at.
func TestKMSKeyIdentityMigrationWithReferences(t *testing.T) {
	logger := helpers.SetupLogger(config.Info, "test", "test")
	cleanup, con := RunDB(t, logger, kmsDBName)
	defer cleanup()

	ctx := context.Background()
	m := postgres.NewMigrator(logger, con)
	_, err := m.Goose.UpTo(ctx, int64(20261030120100))
	require.NoError(t, err)

	require.NoError(t, con.Exec(`CREATE SCHEMA ca; CREATE SCHEMA va;
		CREATE TABLE ca.certificates (serial_number text PRIMARY KEY, engine_id text, key_id text,
			CONSTRAINT certificates_key_fk FOREIGN KEY (engine_id, key_id) REFERENCES kms.kms_keys (engine_id, key_id)
			ON DELETE RESTRICT ON UPDATE CASCADE);
		CREATE TABLE va.crl_settings (ca_id text PRIMARY KEY, signer_engine_id text, signer_key_id text,
			CONSTRAINT crl_settings_signer_key_fk FOREIGN KEY (signer_engine_id, signer_key_id) REFERENCES kms.kms_keys (engine_id, key_id)
			ON DELETE RESTRICT ON UPDATE CASCADE)`).Error)

	publicC, digestC := kmsKeyFixture(t)
	const skiC = "c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0"
	insertKMSKey(t, con, digestC, "e1", publicC, `[]`, true)
	insertKMSKey(t, con, skiC, "e1", publicC, `[]`, true)
	// the certificate and the CRL signer reference the row the migration removes
	require.NoError(t, con.Exec(`INSERT INTO ca.certificates VALUES ('s1', 'e1', ?), ('s2', 'e1', ?)`, skiC, digestC).Error)
	require.NoError(t, con.Exec(`INSERT INTO va.crl_settings VALUES ('ca1', 'e1', ?)`, skiC).Error)

	_, err = m.Goose.UpTo(ctx, int64(20261124100000))
	require.NoError(t, err)

	var keyID string
	require.NoError(t, con.Raw(`SELECT key_id FROM ca.certificates WHERE serial_number = 's1'`).Scan(&keyID).Error)
	assert.Equal(t, digestC, keyID, "a certificate that referenced the removed row references the survivor")
	require.NoError(t, con.Raw(`SELECT signer_key_id FROM va.crl_settings WHERE ca_id = 'ca1'`).Scan(&keyID).Error)
	assert.Equal(t, digestC, keyID, "so does a CRL signer")
}

// TestKMSKeyIdentityMigrationRefusesAmbiguousDuplicates: when none of the rows holding the same key in an
// engine is named by its digest, the migration cannot tell which one the engine holds.
func TestKMSKeyIdentityMigrationRefusesAmbiguousDuplicates(t *testing.T) {
	logger := helpers.SetupLogger(config.Info, "test", "test")
	cleanup, con := RunDB(t, logger, kmsDBName)
	defer cleanup()

	ctx := context.Background()
	m := postgres.NewMigrator(logger, con)
	_, err := m.Goose.UpTo(ctx, int64(20261030120100))
	require.NoError(t, err)

	publicC, digestC := kmsKeyFixture(t)
	insertKMSKey(t, con, "name-one", "e1", publicC, `[]`, true)
	insertKMSKey(t, con, "name-two", "e1", publicC, `[]`, true)

	_, err = m.Goose.UpTo(ctx, int64(20261124100000))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "same public key")
	assert.Contains(t, err.Error(), digestC)

	var rows int64
	require.NoError(t, con.Raw(`SELECT count(*) FROM kms_keys`).Scan(&rows).Error)
	assert.EqualValues(t, 2, rows, "a refused migration changes nothing")

	// a public key that cannot be read is refused too, rather than given an invented digest
	require.NoError(t, con.Exec(`DELETE FROM kms_keys WHERE key_id = 'name-two'`).Error)
	insertKMSKey(t, con, "garbled", "e2", "not-a-public-key", `[]`, true)
	_, err = m.Goose.UpTo(ctx, int64(20261124100000))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "garbled")
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

	migrationTest_KMS_20261030120100_drop_legacy_key_bindings(t, logger, con)
	if t.Failed() {
		t.Fatalf("failed while running migration v20261030120100_drop_legacy_key_bindings")
	}

	migrationTest_KMS_20261124100000_kms_key_identity(t, logger, con)
	if t.Failed() {
		t.Fatalf("failed while running migration v20261124100000_kms_key_identity")
	}
}
