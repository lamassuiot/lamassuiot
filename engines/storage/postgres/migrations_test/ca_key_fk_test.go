package migrationstest

import (
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/pem"
	"testing"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/config"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v4/engines/storage/postgres"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// kmsPublicKey is how the KMS stores a public key: the base64 of its PEM encoding.
func kmsPublicKey(t *testing.T, certPEM string) string {
	t.Helper()
	block, _ := pem.Decode([]byte(certPEM))
	require.NotNil(t, block)
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	spki, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	require.NoError(t, err)
	return base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: spki}))
}

func TestCertificateKeyForeignKeyMigration(t *testing.T) {
	logger := helpers.SetupLogger(config.Trace, "test", "test")
	cleanup, con := RunDB(t, logger, CADBName)
	defer cleanup()

	ctx := context.Background()
	m := postgres.NewMigrator(logger, con)
	const previous, target = int64(20261027120000), int64(20261030120000)
	_, err := m.Goose.UpTo(ctx, previous)
	require.NoError(t, err)

	insertCertificate := func(serial, certificate, engineID, keyID string) {
		t.Helper()
		require.NoError(t, con.Exec(`INSERT INTO certificates
			(serial_number, metadata, issuer_meta_serial_number, issuer_meta_id, issuer_meta_level, status, certificate, key_meta_type, key_meta_bits, key_meta_strength,
			subject_common_name, subject_organization, subject_organization_unit, subject_country, subject_state, subject_locality,
			valid_from, valid_to, revocation_timestamp, revocation_reason, "type", engine_id, key_id, is_ca)
			VALUES (?, '{}', ?, 'x', 0, 'ACTIVE', ?, 'ECDSA', 256, 'HIGH', 'KeyFK', '', '', '', '', '',
			now(), now() + interval '1 day', '0001-01-01', 'Unspecified', 'MANAGED', ?, ?, false)`,
			serial, serial, certificate, engineID, keyID).Error, "insert certificate %s", serial)
	}
	insertCA := func(id, serial string) {
		t.Helper()
		require.NoError(t, con.Exec(`INSERT INTO ca_certificates (id, serial_number) VALUES (?, ?)`, id, serial).Error, "insert CA %s", id)
	}
	opensslCert := base64.StdEncoding.EncodeToString([]byte(opensslCACertPEM))

	// the digest key_id the previous migration backfills for every certificate of the OpenSSL CA
	insertCertificate("fk-held", opensslCert, "e1", opensslCAKeyID)
	insertCertificate("fk-ski", opensslCert, "e2", opensslCAKeyID)
	insertCertificate("fk-dangling", opensslCert, "e3", opensslCAKeyID)
	insertCertificate("fk-dangling-old", opensslCert, "e3", opensslCAKeyID) // an earlier certificate of the same CA
	insertCertificate("fk-garbage", "not-a-certificate", "e2", "digest-of-nothing")
	insertCertificate("fk-no-engine", opensslCert, "", "")
	insertCertificate("fk-engine-no-key", "not-a-certificate", "e1", "")
	// the certificate of a CA deleted before upgrading: DeleteCA removed its key from the engine and the KMS
	insertCertificate("fk-deleted-ca", opensslCert, "e4", opensslCAKeyID)
	// live CAs whose keys the KMS does not hold yet: only registering them repairs the reference
	insertCA("ca-dangling", "fk-dangling")
	insertCA("ca-garbage", "fk-garbage")

	t.Run("it needs the kms schema", func(t *testing.T) {
		_, err := m.Goose.ApplyVersion(ctx, target, true)
		require.ErrorContains(t, err, "kms schema not found")
	})

	// the table the kms migrations create; the defaults only shorten the fixture inserts below
	require.NoError(t, con.Exec(`CREATE SCHEMA IF NOT EXISTS kms`).Error)
	require.NoError(t, con.Exec(`CREATE TABLE kms.kms_keys (
		key_id text NOT NULL, engine_id text NOT NULL, metadata jsonb NULL,
		name text NOT NULL DEFAULT '', algorithm text NOT NULL DEFAULT '', size int8 NOT NULL DEFAULT 0,
		public_key text NOT NULL, creation_ts timestamptz NULL,
		aliases jsonb DEFAULT '[]'::jsonb, has_private_key boolean DEFAULT true, tags jsonb DEFAULT '[]'::jsonb,
		CONSTRAINT kms_keys_pkey PRIMARY KEY (key_id, engine_id))`).Error)
	keysOf := func(engineID string) int64 {
		t.Helper()
		var n int64
		require.NoError(t, con.Raw(`SELECT COUNT(*) FROM kms.kms_keys WHERE engine_id = ?`, engineID).Scan(&n).Error)
		return n
	}
	publicKey := kmsPublicKey(t, opensslCACertPEM)
	require.NoError(t, con.Exec(`INSERT INTO kms.kms_keys (key_id, engine_id, public_key) VALUES
		(?, 'e1', ?),
		(?, 'e2', ?)`, opensslCAKeyID, publicKey, opensslCASKI, publicKey).Error)

	_, err = m.Goose.ApplyVersion(ctx, target, true)
	require.ErrorContains(t, err, "unresolved certificate key")
	// The failed migration must not erase or partially relink the legacy references.
	var unchanged string
	require.NoError(t, con.Raw(`SELECT key_id FROM certificates WHERE serial_number = 'fk-ski'`).Scan(&unchanged).Error)
	require.Equal(t, opensslCAKeyID, unchanged)
	require.NoError(t, con.Raw(`SELECT key_id FROM certificates WHERE serial_number = 'fk-deleted-ca'`).Scan(&unchanged).Error)
	require.Equal(t, opensslCAKeyID, unchanged)
	require.Zero(t, keysOf("e4"), "a failed migration registers no key")
	require.NoError(t, con.Exec(`INSERT INTO kms.kms_keys (key_id, engine_id, public_key) VALUES
		(?, 'e3', ?), ('digest-of-nothing', 'e2', 'unreadable-public-key')`, opensslCAKeyID, publicKey).Error)
	_, err = m.Goose.ApplyVersion(ctx, target, true)
	require.NoError(t, err)
	var validated bool
	require.NoError(t, con.Raw(`SELECT convalidated FROM pg_constraint WHERE conname = 'certificates_key_fk'`).Scan(&validated).Error)
	require.True(t, validated)

	reference := func(serial string) (engineID, keyID sql.NullString) {
		t.Helper()
		row := con.Raw(`SELECT engine_id, key_id FROM certificates WHERE serial_number = ?`, serial).Row()
		require.NoError(t, row.Scan(&engineID, &keyID))
		return engineID, keyID
	}

	t.Run("a certificate whose key the KMS holds keeps referencing it", func(t *testing.T) {
		engineID, keyID := reference("fk-held")
		assert.Equal(t, "e1", engineID.String)
		assert.Equal(t, opensslCAKeyID, keyID.String)
	})

	t.Run("a certificate whose key the KMS holds under its SKI references that name", func(t *testing.T) {
		_, keyID := reference("fk-ski")
		assert.Equal(t, opensslCASKI, keyID.String)
	})

	t.Run("a repaired legacy reference keeps its key_id and stays updatable", func(t *testing.T) {
		_, keyID := reference("fk-dangling")
		assert.Equal(t, opensslCAKeyID, keyID.String)
		_, keyID = reference("fk-garbage")
		assert.Equal(t, "digest-of-nothing", keyID.String, "an unreadable certificate is skipped, not failed")

		require.NoError(t, con.Exec(`UPDATE certificates SET status = 'REVOKED' WHERE serial_number = 'fk-dangling'`).Error)
	})

	t.Run("the certificate of a deleted CA references a public-only key the KMS now holds", func(t *testing.T) {
		engineID, keyID := reference("fk-deleted-ca")
		assert.Equal(t, "e4", engineID.String)
		assert.Equal(t, opensslCAKeyID, keyID.String, "the reference is left as it was")

		var key struct {
			Name, Algorithm, PublicKey string
			Size                       int
			HasPrivateKey              bool
		}
		require.NoError(t, con.Raw(`SELECT name, algorithm, size, public_key, has_private_key FROM kms.kms_keys
			WHERE engine_id = 'e4' AND key_id = ?`, opensslCAKeyID).Scan(&key).Error)
		assert.False(t, key.HasPrivateKey)
		assert.Equal(t, publicKey, key.PublicKey)
		assert.Equal(t, "ECDSA", key.Algorithm)
		assert.Equal(t, 256, key.Size)
		assert.Equal(t, "KeyFK", key.Name, "named after the certificate's common name")
		assert.Equal(t, int64(1), keysOf("e4"))
	})

	t.Run("a certificate sharing the key of a live CA keeps its reference", func(t *testing.T) {
		_, keyID := reference("fk-dangling-old")
		assert.Equal(t, opensslCAKeyID, keyID.String)
	})

	t.Run("no key is a NULL key_id, and engine_id is left as it was", func(t *testing.T) {
		engineID, keyID := reference("fk-no-engine")
		assert.True(t, engineID.Valid, "engine_id keeps its empty string, so the filters on it keep their meaning")
		assert.Equal(t, "", engineID.String)
		assert.False(t, keyID.Valid)

		engineID, keyID = reference("fk-engine-no-key")
		assert.Equal(t, "e1", engineID.String)
		assert.False(t, keyID.Valid)
	})

	t.Run("the KMS cannot delete a key a certificate references", func(t *testing.T) {
		err := con.Exec(`DELETE FROM kms.kms_keys WHERE key_id = ? AND engine_id = 'e1'`, opensslCAKeyID).Error
		require.ErrorContains(t, err, "certificates_key_fk")
	})

	t.Run("a new certificate must reference a key the KMS holds", func(t *testing.T) {
		err := con.Exec(`INSERT INTO certificates
			(serial_number, metadata, issuer_meta_serial_number, issuer_meta_id, issuer_meta_level, status, certificate, key_meta_type, key_meta_bits, key_meta_strength,
			subject_common_name, subject_organization, subject_organization_unit, subject_country, subject_state, subject_locality,
			valid_from, valid_to, revocation_timestamp, revocation_reason, "type", engine_id, key_id, is_ca)
			VALUES ('fk-new', '{}', 'fk-new', 'x', 0, 'ACTIVE', ?, 'ECDSA', 256, 'HIGH', 'KeyFK', '', '', '', '', '',
			now(), now() + interval '1 day', '0001-01-01', 'Unspecified', 'MANAGED', 'e1', 'missing', false)`, opensslCert).Error
		require.ErrorContains(t, err, "certificates_key_fk")
	})

	t.Run("renaming a key renames the reference", func(t *testing.T) {
		require.NoError(t, con.Exec(`UPDATE kms.kms_keys SET key_id = 'renamed' WHERE key_id = ? AND engine_id = 'e1'`, opensslCAKeyID).Error)
		_, keyID := reference("fk-held")
		assert.Equal(t, "renamed", keyID.String)
		require.NoError(t, con.Exec(`UPDATE kms.kms_keys SET key_id = ? WHERE key_id = 'renamed' AND engine_id = 'e1'`, opensslCAKeyID).Error)
	})

	t.Run("rolling back restores the empty strings and drops the constraint", func(t *testing.T) {
		RollbackMigration(t, logger, con, CADBName, "20261030120000_certificate_key_foreign_key")

		_, keyID := reference("fk-no-engine")
		assert.True(t, keyID.Valid)
		assert.Equal(t, "", keyID.String)

		var constraints int64
		require.NoError(t, con.Raw(`SELECT COUNT(*) FROM pg_constraint WHERE conname IN ('certificates_key_fk', 'certificates_key_engine_required')`).Scan(&constraints).Error)
		assert.Equal(t, int64(0), constraints)

		_, err := m.Goose.ApplyVersion(ctx, target, true)
		require.NoError(t, err, "the migration applies again after a rollback")
	})
}

// An installation which already applied an old NOT VALID certificates_key_fk (a hand-run variant of this
// migration) must be validated, with its orphan references diagnosed, by the same migration.
func TestCertificateLegacyForeignKeyValidation(t *testing.T) {
	logger := helpers.SetupLogger(config.Info, "test", "validation")
	cleanup, con := RunDB(t, logger, CADBName)
	defer cleanup()
	require.NoError(t, con.Exec(`CREATE SCHEMA kms;
 CREATE TABLE kms.kms_keys (key_id text, engine_id text, public_key text, PRIMARY KEY (key_id, engine_id));
 CREATE TABLE certificates (serial_number text PRIMARY KEY, engine_id text, key_id text, certificate text, subject_common_name text);
 CREATE TABLE ca_certificates (id text, serial_number text);
 INSERT INTO certificates VALUES ('orphan', 'engine', 'missing', NULL, 'Orphan');
 INSERT INTO ca_certificates VALUES ('live-ca', 'orphan');
 ALTER TABLE certificates ADD CONSTRAINT certificates_key_fk FOREIGN KEY (engine_id, key_id)
 REFERENCES kms.kms_keys(engine_id, key_id) ON DELETE RESTRICT ON UPDATE CASCADE NOT VALID`).Error)
	m := postgres.NewMigrator(logger, con)
	_, err := m.Goose.ApplyVersion(context.Background(), 20261030120000, true)
	require.ErrorContains(t, err, "unresolved certificate key")
	require.NoError(t, con.Exec(`INSERT INTO kms.kms_keys (key_id, engine_id) VALUES ('missing', 'engine')`).Error)
	_, err = m.Goose.ApplyVersion(context.Background(), 20261030120000, true)
	require.NoError(t, err)
	var validated bool
	require.NoError(t, con.Raw(`SELECT convalidated FROM pg_constraint WHERE conname = 'certificates_key_fk'`).Scan(&validated).Error)
	require.True(t, validated)
	require.Error(t, con.Exec(`INSERT INTO certificates (serial_number, engine_id, key_id) VALUES ('partial', NULL, 'missing')`).Error,
		"a non-null key reference must include its engine; SQL NULL must not bypass the FK")
	require.NoError(t, con.Exec(`INSERT INTO certificates (serial_number, engine_id, key_id) VALUES ('no-key', 'engine', NULL)`).Error)
}
