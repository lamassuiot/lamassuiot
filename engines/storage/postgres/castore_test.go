package postgres

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"testing"
	"time"

	backendservices "github.com/lamassuiot/lamassuiot/v4/backend/pkg/services"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/errs"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/services"
	postgrestest "github.com/lamassuiot/lamassuiot/v4/engines/storage/postgres/test"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

type keylessImportKMS struct {
	services.KMSService
}

func (keylessImportKMS) GetKey(context.Context, services.GetKeyInput) (*models.Key, error) {
	return nil, errs.ErrKeyNotFound
}

// GetKeysByPublicKey is how ImportCA looks for the key of a CA imported without one.
func (keylessImportKMS) GetKeysByPublicKey(context.Context, services.GetKeysByPublicKeyInput) ([]*models.Key, error) {
	return nil, nil
}

func postgresImportInput(t *testing.T, id string, serial int64) services.ImportCAInput {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "root"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		SubjectKeyId: []byte{byte(serial)}, AuthorityKeyId: []byte{byte(serial)},
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return services.ImportCAInput{ID: id, CACertificate: (*models.X509Certificate)(cert)}
}

func TestCAStoreUniqueIDPostgres(t *testing.T) {
	_, suite := postgrestest.BeforeSuite([]string{"ca"}, false)
	t.Cleanup(suite.AfterSuite)
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	log := logrus.NewEntry(logger)
	db := suite.DB["ca"]
	pool, err := db.DB()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, pool.Close()) })
	NewMigrator(log, db).MigrateToLatest()
	repo, err := NewCAPostgresRepository(log, db)
	require.NoError(t, err)
	svc, err := backendservices.NewCAService(backendservices.CAServiceBuilder{CAStorage: repo, KMSService: keylessImportKMS{}, Logger: log})
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	countRows := func(table string, want int64) {
		var count int64
		require.NoError(t, db.Table(table).Count(&count).Error)
		require.Equal(t, want, count, table)
	}

	_, err = svc.ImportCA(ctx, postgresImportInput(t, "shared", 1))
	require.NoError(t, err)
	_, err = svc.ImportCA(ctx, postgresImportInput(t, "other", 2))
	require.NoError(t, err)

	t.Run("import with an existing ID", func(t *testing.T) {
		ca, err := svc.ImportCA(ctx, postgresImportInput(t, "shared", 3))
		require.ErrorIs(t, err, errs.ErrCAAlreadyExists)
		require.Nil(t, ca)
		countRows("ca_certificates", 2)
		countRows("certificates", 2)
	})

	t.Run("duplicates and foreign-key errors", func(t *testing.T) {
		var serial string
		require.NoError(t, db.Raw("SELECT serial_number FROM ca_certificates WHERE id = 'other'").Scan(&serial).Error)
		_, err := repo.Insert(ctx, &models.CACertificate{ID: "shared", CertificateSerialNumber: serial})
		require.ErrorIs(t, err, errs.ErrCAAlreadyExists)
		// A foreign-key violation must not become a duplicate-ID error.
		_, err = repo.Insert(ctx, &models.CACertificate{ID: "missing-cert", CertificateSerialNumber: "missing"})
		require.ErrorIs(t, err, gorm.ErrForeignKeyViolated)
		require.NotErrorIs(t, err, errs.ErrCAAlreadyExists)
	})

	t.Run("concurrent inserts roll back the losing certificate", func(t *testing.T) {
		exists, original, err := repo.SelectExistsByID(ctx, "shared")
		require.NoError(t, err)
		require.True(t, exists)
		start := make(chan struct{})
		results := make(chan error, 2)
		for _, serial := range []string{"aa", "bb"} {
			ca := *original
			ca.ID = "direct-insert"
			ca.CertificateSerialNumber = ""
			ca.Certificate.SerialNumber = serial
			go func() {
				<-start
				_, err := repo.Insert(ctx, &ca)
				results <- err
			}()
		}
		close(start)
		var succeeded, duplicated int
		for range 2 {
			err := <-results
			if err == nil {
				succeeded++
			} else {
				require.ErrorIs(t, err, errs.ErrCAAlreadyExists)
				duplicated++
			}
		}
		require.Equal(t, 1, succeeded)
		require.Equal(t, 1, duplicated)
		countRows("ca_certificates", 3)
		countRows("certificates", 3)
	})
}
