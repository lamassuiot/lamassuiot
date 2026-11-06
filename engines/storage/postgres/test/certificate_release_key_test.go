package postgrestest

import (
	"context"
	"gorm.io/gorm"
	"testing"
	"time"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/config"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/errs"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	postgres "github.com/lamassuiot/lamassuiot/v4/engines/storage/postgres"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Releasing the certificates of a deleted CA lets the KMS delete the key they no longer use, and only
// the ones given: the certificates of another CA that shares the key keep referencing it.
func TestCertificateStoreReleaseKey(t *testing.T) {
	_, kmsStore, certStore := newKMSAndCertStores(t)
	ctx := context.Background()

	insertTestKey(t, kmsStore, "e1", "shared")
	released := []*models.Certificate{newTestCertificate(t, 1, "e1", "shared"), newTestCertificate(t, 2, "e1", "shared")}
	kept := newTestCertificate(t, 3, "e1", "shared")
	for _, cert := range append(released, kept) {
		_, err := certStore.Insert(ctx, cert)
		require.NoError(t, err)
	}

	require.NoError(t, certStore.ReleaseKey(ctx, []string{released[0].SerialNumber, released[1].SerialNumber}))

	for _, cert := range released {
		_, stored, err := certStore.SelectExistsBySerialNumber(ctx, cert.SerialNumber)
		require.NoError(t, err)
		assert.Empty(t, stored.KeyID)
		assert.Equal(t, "e1", stored.EngineID, "the certificate keeps the engine its key was in")
	}
	_, stored, err := certStore.SelectExistsBySerialNumber(ctx, kept.SerialNumber)
	require.NoError(t, err)
	assert.Equal(t, "shared", stored.KeyID)
	require.ErrorIs(t, kmsStore.Delete(ctx, "shared", "e1"), errs.ErrKeyInUse, "a certificate still references the key")

	require.NoError(t, certStore.ReleaseKey(ctx, []string{kept.SerialNumber}))
	require.NoError(t, kmsStore.Delete(ctx, "shared", "e1"))

	require.NoError(t, certStore.ReleaseKey(ctx, nil), "releasing no certificate does nothing")
}

// CA storage requires an existing certificate and never creates it implicitly.
func TestCAStoreInsertWithMissingCertificateIsRejected(t *testing.T) {
	cfg, suite := BeforeSuite([]string{postgres.KMS_SCHEMA, postgres.CA_SCHEMA}, false)
	defer suite.AfterSuite()

	logger := helpers.SetupLogger(config.Info, "PostgreSQL", "Test")
	require.NoError(t, postgres.MigrateDatabase(logger, cfg, postgres.CA_SCHEMA))
	caStore, err := postgres.NewCAPostgresRepository(logger, suite.DB[postgres.CA_SCHEMA])
	require.NoError(t, err)

	_, err = caStore.Insert(context.Background(), &models.CACertificate{
		ID: "ca-missing-certificate", CertificateSerialNumber: "01", Metadata: map[string]any{}, CreationTS: time.Now(),
		Certificate: *newTestCertificate(t, 1, "e1", "nope"),
	})
	require.ErrorIs(t, err, gorm.ErrForeignKeyViolated)
}
