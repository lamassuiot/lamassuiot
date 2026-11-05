package postgrestest

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/config"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/errs"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	postgres "github.com/lamassuiot/lamassuiot/v4/engines/storage/postgres"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newKMSAndCertStores starts Postgres with the KMS and CA schemas, migrated in the order the CA needs:
// its certificates reference the keys of the KMS.
func newKMSAndCertStores(t *testing.T) (*PostgresSuite, storage.KMSKeysRepo, storage.CertificatesRepo) {
	t.Helper()
	cfg, suite := BeforeSuite([]string{postgres.KMS_SCHEMA, postgres.CA_SCHEMA}, false)
	t.Cleanup(suite.AfterSuite)

	logger := helpers.SetupLogger(config.Info, "PostgreSQL", "Test")
	require.NoError(t, postgres.MigrateDatabase(logger, cfg, postgres.KMS_SCHEMA))
	require.NoError(t, postgres.MigrateDatabase(logger, cfg, postgres.CA_SCHEMA))

	kmsStore, err := postgres.NewKMSPostgresRepository(logger, suite.DB[postgres.KMS_SCHEMA])
	require.NoError(t, err)
	certStore, err := postgres.NewCertificateRepository(logger, suite.DB[postgres.CA_SCHEMA])
	require.NoError(t, err)
	return &suite, kmsStore, certStore
}

func insertTestKey(t *testing.T, store storage.KMSKeysRepo, engineID, keyID string) {
	t.Helper()
	_, err := store.Insert(context.Background(), &models.Key{
		KeyID: keyID, EngineID: engineID, Name: keyID, Algorithm: "ECDSA", Size: 256, PublicKey: "pub-" + keyID,
		HasPrivateKey: true, CreationTS: time.Now().UTC().Truncate(time.Second),
		Aliases: []string{}, Tags: []string{}, Metadata: map[string]any{},
	})
	require.NoError(t, err)
}

func newTestCertificate(t *testing.T, serial int, engineID, keyID string) *models.Certificate {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(int64(serial)), Subject: pkix.Name{CommonName: "leaf"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	require.NoError(t, err)
	parsed, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return &models.Certificate{
		SerialNumber: fmt.Sprintf("%02x", parsed.SerialNumber),
		Certificate:  (*models.X509Certificate)(parsed),
		Status:       models.StatusActive,
		Subject:      models.Subject{CommonName: "leaf"},
		Issuer:       models.Subject{CommonName: "leaf"},
		ValidFrom:    parsed.NotBefore,
		ValidTo:      parsed.NotAfter,
		Metadata:     map[string]any{},
		Extensions:   models.CertificateExtensions{ExtendedKeyUsage: []models.X509ExtKeyUsage{}},
		Type:         models.CertificateTypeManaged,
		EngineID:     engineID,
		KeyID:        keyID,
	}
}

// A certificate references the KMS key it uses through (engine_id, key_id): the database refuses to
// delete a key a certificate still references, and to store a certificate for a key the KMS does not hold.
func TestCertificateKeyForeignKey(t *testing.T) {
	suite, kmsStore, certStore := newKMSAndCertStores(t)
	ctx := context.Background()
	serial := 0
	newCertificate := func(engineID, keyID string) *models.Certificate {
		serial++
		return newTestCertificate(t, serial, engineID, keyID)
	}

	t.Run("a certificate for a key the KMS does not hold is refused", func(t *testing.T) {
		_, err := certStore.Insert(ctx, newCertificate("e1", "nope"))
		require.ErrorIs(t, err, errs.ErrKeyNotFound)
	})

	t.Run("a certificate without a key stores a NULL key_id and keeps its empty engine_id", func(t *testing.T) {
		cert := newCertificate("", "")
		_, err := certStore.Insert(ctx, cert)
		require.NoError(t, err)

		// engine_id stays as it always was, so the string filters on it keep their meaning
		var keyIsNull, engineIsEmpty bool
		row := suite.DB[postgres.CA_SCHEMA].Raw(`SELECT key_id IS NULL, COALESCE(engine_id = '', false) FROM certificates WHERE serial_number = ?`, cert.SerialNumber).Row()
		require.NoError(t, row.Scan(&keyIsNull, &engineIsEmpty))
		assert.True(t, keyIsNull)
		assert.True(t, engineIsEmpty)

		exists, stored, err := certStore.SelectExistsBySerialNumber(ctx, cert.SerialNumber)
		require.NoError(t, err)
		require.True(t, exists)
		assert.Empty(t, stored.EngineID)
		assert.Empty(t, stored.KeyID)
	})

	t.Run("a key a certificate references cannot be deleted", func(t *testing.T) {
		insertTestKey(t, kmsStore, "e1", "referenced")
		cert := newCertificate("e1", "referenced")
		_, err := certStore.Insert(ctx, cert)
		require.NoError(t, err)

		require.ErrorIs(t, kmsStore.Delete(ctx, "referenced", "e1"), errs.ErrKeyInUse)

		require.NoError(t, certStore.Delete(ctx, cert.SerialNumber))
		require.NoError(t, kmsStore.Delete(ctx, "referenced", "e1"))
	})

	t.Run("a certificate with an engine and no key is stored and updatable", func(t *testing.T) {
		cert := newCertificate("e1", "")
		_, err := certStore.Insert(ctx, cert)
		require.NoError(t, err)

		cert.Status = models.StatusRevoked
		_, err = certStore.Update(ctx, cert)
		require.NoError(t, err)
	})
}

// DeleteWith deletes the key row and runs the engine delete in the same transaction, after the row: an
// engine copy is never destroyed for a key a certificate uses.
func TestKMSStoreDeleteWith(t *testing.T) {
	_, kmsStore, certStore := newKMSAndCertStores(t)
	ctx := context.Background()

	t.Run("a key a certificate references keeps its row and its engine copy", func(t *testing.T) {
		insertTestKey(t, kmsStore, "e1", "in-use")
		_, err := certStore.Insert(ctx, newTestCertificate(t, 1, "e1", "in-use"))
		require.NoError(t, err)

		engineDeleted := false
		err = kmsStore.DeleteWith(ctx, "in-use", "e1", func() error { engineDeleted = true; return nil })
		require.ErrorIs(t, err, errs.ErrKeyInUse)
		assert.False(t, engineDeleted, "the engine copy of a key in use must not be touched")

		exists, _, err := kmsStore.SelectExistsByKeyID(ctx, "in-use", "e1")
		require.NoError(t, err)
		assert.True(t, exists)
	})

	t.Run("a failed engine delete keeps the row", func(t *testing.T) {
		insertTestKey(t, kmsStore, "e1", "engine-fails")

		err := kmsStore.DeleteWith(ctx, "engine-fails", "e1", func() error { return errors.New("engine unavailable") })
		require.ErrorContains(t, err, "engine unavailable")

		exists, _, err := kmsStore.SelectExistsByKeyID(ctx, "engine-fails", "e1")
		require.NoError(t, err)
		assert.True(t, exists)
	})

	t.Run("a free key loses its row and its engine copy", func(t *testing.T) {
		insertTestKey(t, kmsStore, "e1", "free")

		engineDeleted := false
		require.NoError(t, kmsStore.DeleteWith(ctx, "free", "e1", func() error { engineDeleted = true; return nil }))
		assert.True(t, engineDeleted)

		exists, _, err := kmsStore.SelectExistsByKeyID(ctx, "free", "e1")
		require.NoError(t, err)
		assert.False(t, exists)
	})

	t.Run("an unknown key is not found and the engine is not touched", func(t *testing.T) {
		engineDeleted := false
		err := kmsStore.DeleteWith(ctx, "ghost", "e1", func() error { engineDeleted = true; return nil })
		require.ErrorIs(t, err, errs.ErrKeyNotFound)
		assert.False(t, engineDeleted)
	})
}
