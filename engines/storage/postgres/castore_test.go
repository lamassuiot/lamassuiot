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
	"sync"
	"testing"
	"time"

	backendservices "github.com/lamassuiot/lamassuiot/v4/backend/pkg/services"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/config"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/errs"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/resources"
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

func postgresImportInput(t *testing.T, serial int64) services.ImportCAInput {
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
	return services.ImportCAInput{CACertificate: (*models.X509Certificate)(cert)}
}

func TestCAStoreUniqueIDPostgres(t *testing.T) {
	_, suite := postgrestest.BeforeSuite([]string{"kms", "ca"}, false)
	t.Cleanup(suite.AfterSuite)
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	log := logrus.NewEntry(logger)
	db := suite.DB["ca"]
	pool, err := db.DB()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, pool.Close()) })
	// the CA schema references the KMS one, which is migrated first
	NewMigrator(log, suite.DB["kms"]).MigrateToLatest()
	NewMigrator(log, db).MigrateToLatest()
	repo, err := NewCAPostgresRepository(log, db)
	require.NoError(t, err)
	certRepo, err := NewCertificateRepository(log, db)
	require.NoError(t, err)
	svc, err := backendservices.NewCAService(backendservices.CAServiceBuilder{CAStorage: repo, CertificateStorage: certRepo, KMSService: keylessImportKMS{}, Logger: log})
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	countRows := func(table string, want int64) {
		var count int64
		require.NoError(t, db.Table(table).Count(&count).Error)
		require.Equal(t, want, count, table)
	}

	firstInput := postgresImportInput(t, 1)
	first, err := svc.ImportCA(ctx, firstInput)
	require.NoError(t, err)
	second, err := svc.ImportCA(ctx, postgresImportInput(t, 2))
	require.NoError(t, err)

	require.NotEqual(t, first.ID, second.ID)

	t.Run("import with an existing certificate", func(t *testing.T) {
		ca, err := svc.ImportCA(ctx, firstInput)
		require.ErrorIs(t, err, errs.ErrCAAlreadyExists)
		require.Nil(t, ca)
		countRows("ca_certificates", 2)
		countRows("certificates", 2)
	})

	t.Run("duplicates and foreign-key errors", func(t *testing.T) {
		_, err := repo.Insert(ctx, &models.CACertificate{ID: first.ID, CertificateSerialNumber: second.CertificateSerialNumber})
		require.ErrorIs(t, err, errs.ErrCAAlreadyExists)
		// A foreign-key violation must not become a duplicate-ID error.
		_, err = repo.Insert(ctx, &models.CACertificate{ID: "missing-cert", CertificateSerialNumber: "missing"})
		require.ErrorIs(t, err, gorm.ErrForeignKeyViolated)
		require.NotErrorIs(t, err, errs.ErrCAAlreadyExists)
	})

	t.Run("concurrent CA inserts reference existing certificates", func(t *testing.T) {
		exists, original, err := repo.SelectExistsByID(ctx, first.ID)
		require.NoError(t, err)
		require.True(t, exists)
		start := make(chan struct{})
		results := make(chan error, 2)
		for _, serial := range []string{"aa", "bb"} {
			ca := *original
			ca.ID = "direct-insert"
			ca.Certificate.SerialNumber = serial
			_, err := certRepo.Insert(ctx, &ca.Certificate)
			require.NoError(t, err)
			ca.CertificateSerialNumber = serial
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
		countRows("certificates", 4)
	})
}

func TestCARepositoryTenantScopeWithJoinedQueries(t *testing.T) {
	logger := helpers.SetupLogger(config.Info, "test", "ca-repo-tenant-scope")
	_, suite := postgrestest.BeforeSuite([]string{"kms", "ca"}, false)
	defer suite.AfterSuite()

	db := suite.DB["ca"]
	NewMigrator(logger, suite.DB["kms"]).MigrateToLatest()
	NewMigrator(logger, db).MigrateToLatest()

	repo, err := NewCAPostgresRepository(logger, db)
	require.NoError(t, err)

	ctx := deviceGroupsTenantContext("00000000-0000-0000-0000-00000000000a")
	listRequest := storage.StorageListRequest[models.CACertificate]{}
	queryParams := &resources.QueryParameters{}

	joinedQueries := []struct {
		name string
		run  func() error
	}{
		{
			name: "count with filters",
			run: func() error {
				_, err := repo.CountWithFilters(ctx, queryParams)
				return err
			},
		},
		{
			name: "count by engine",
			run: func() error {
				_, err := repo.CountByEngine(ctx, "engine")
				return err
			},
		},
		{
			name: "count by engine with filters",
			run: func() error {
				_, err := repo.CountByEngineWithFilters(ctx, "engine", queryParams)
				return err
			},
		},
		{
			name: "count by status",
			run: func() error {
				_, err := repo.CountByStatus(ctx, models.StatusActive)
				return err
			},
		},
		{
			name: "select by type",
			run: func() error {
				_, err := repo.SelectByType(ctx, models.CertificateTypeManaged, listRequest)
				return err
			},
		},
		{
			name: "select all",
			run: func() error {
				_, err := repo.SelectAll(ctx, listRequest)
				return err
			},
		},
		{
			name: "select by common name",
			run: func() error {
				_, err := repo.SelectByCommonName(ctx, "common-name", listRequest)
				return err
			},
		},
		{
			name: "select by parent CA",
			run: func() error {
				_, err := repo.SelectByParentCA(ctx, "parent-ca", listRequest)
				return err
			},
		},
		{
			name: "select by subject and subject key ID",
			run: func() error {
				_, err := repo.SelectBySubjectAndSubjectKeyID(ctx, models.Subject{}, "subject-key-id", listRequest)
				return err
			},
		},
		{
			name: "select by issuer and authority key ID",
			run: func() error {
				_, err := repo.SelectByIssuerAndAuthorityKeyID(ctx, models.Subject{}, "authority-key-id", listRequest)
				return err
			},
		},
	}

	for _, query := range joinedQueries {
		t.Run(query.name, func(t *testing.T) {
			require.NoError(t, query.run())
		})
	}
}

func TestCAStoreTenantIsolationPostgres(t *testing.T) {
	_, suite := postgrestest.BeforeSuite([]string{"kms", "ca"}, false)
	defer suite.AfterSuite()

	logger := helpers.SetupLogger(config.Info, "test", "ca-store-tenant-isolation")
	db := suite.DB["ca"]
	NewMigrator(logger, suite.DB["kms"]).MigrateToLatest()
	NewMigrator(logger, db).MigrateToLatest()

	caRepo, err := NewCAPostgresRepository(logger, db)
	require.NoError(t, err)
	certRepo, err := NewCertificateRepository(logger, db)
	require.NoError(t, err)
	svc, err := backendservices.NewCAService(backendservices.CAServiceBuilder{CAStorage: caRepo, CertificateStorage: certRepo, KMSService: keylessImportKMS{}, Logger: logger})
	require.NoError(t, err)

	tenantA := deviceGroupsTenantContext("00000000-0000-0000-0000-00000000000a")
	tenantB := deviceGroupsTenantContext("00000000-0000-0000-0000-00000000000b")

	imported, err := svc.ImportCA(tenantA, postgresImportInput(t, 1))
	require.NoError(t, err)
	caID := imported.ID
	serial := imported.Certificate.SerialNumber

	t.Run("the CA and its certificate take the tenant from the context", func(t *testing.T) {
		var caTenant, certificateTenant string
		require.NoError(t, db.Raw("SELECT tenant_id FROM ca_certificates WHERE id = ?", caID).Scan(&caTenant).Error)
		require.NoError(t, db.Raw("SELECT tenant_id FROM certificates WHERE serial_number = ?", serial).Scan(&certificateTenant).Error)
		require.Equal(t, "00000000-0000-0000-0000-00000000000a", caTenant)
		require.Equal(t, "00000000-0000-0000-0000-00000000000a", certificateTenant)
	})

	t.Run("another tenant cannot read the CA", func(t *testing.T) {
		exists, _, err := caRepo.SelectExistsByID(tenantA, caID)
		require.NoError(t, err)
		require.True(t, exists)

		exists, _, err = caRepo.SelectExistsByID(tenantB, caID)
		require.NoError(t, err)
		require.False(t, exists)
	})

	t.Run("another tenant cannot read its certificate", func(t *testing.T) {
		exists, _, err := certRepo.SelectExistsBySerialNumber(tenantA, serial)
		require.NoError(t, err)
		require.True(t, exists)

		exists, _, err = certRepo.SelectExistsBySerialNumber(tenantB, serial)
		require.NoError(t, err)
		require.False(t, exists)
	})

	t.Run("each tenant counts its own CAs", func(t *testing.T) {
		countA, err := caRepo.Count(tenantA)
		require.NoError(t, err)
		require.Equal(t, 1, countA)

		countB, err := caRepo.Count(tenantB)
		require.NoError(t, err)
		require.Equal(t, 0, countB)
	})

	t.Run("another tenant cannot delete the CA", func(t *testing.T) {
		require.Error(t, caRepo.Delete(tenantB, caID))

		exists, _, err := caRepo.SelectExistsByID(tenantA, caID)
		require.NoError(t, err)
		require.True(t, exists)
	})
}

// Force both imports to observe the certificate as absent before either inserts it.
type simultaneousImportCertificates struct {
	storage.CertificatesRepo
	mu      sync.Mutex
	lookups int
	ready   chan struct{}
}

func (repo *simultaneousImportCertificates) SelectExistsBySerialNumber(ctx context.Context, serial string) (bool, *models.Certificate, error) {
	found, cert, err := repo.CertificatesRepo.SelectExistsBySerialNumber(ctx, serial)
	repo.mu.Lock()
	repo.lookups++
	n := repo.lookups
	if n == 2 {
		close(repo.ready)
	}
	repo.mu.Unlock()
	if n <= 2 {
		select {
		case <-repo.ready:
		case <-ctx.Done():
			return false, nil, ctx.Err()
		}
	}
	return found, cert, err
}

func TestConcurrentCAImportsKeepDuplicateIDError(t *testing.T) {
	_, suite := postgrestest.BeforeSuite([]string{"kms", "ca"}, false)
	t.Cleanup(suite.AfterSuite)
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	log := logrus.NewEntry(logger)
	NewMigrator(log, suite.DB["kms"]).MigrateToLatest()
	NewMigrator(log, suite.DB["ca"]).MigrateToLatest()
	cas, err := NewCAPostgresRepository(log, suite.DB["ca"])
	require.NoError(t, err)
	certs, err := NewCertificateRepository(log, suite.DB["ca"])
	require.NoError(t, err)
	svc, err := backendservices.NewCAService(backendservices.CAServiceBuilder{Logger: log, CAStorage: cas,
		CertificateStorage: &simultaneousImportCertificates{CertificatesRepo: certs, ready: make(chan struct{})}, KMSService: keylessImportKMS{}})
	require.NoError(t, err)
	input := postgresImportInput(t, 9001)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	results := make(chan error, 2)
	for range 2 {
		go func() { _, err := svc.ImportCA(ctx, input); results <- err }()
	}
	var successes, duplicates int
	for range 2 {
		err := <-results
		if err == nil {
			successes++
		} else {
			require.ErrorIs(t, err, errs.ErrCAAlreadyExists)
			duplicates++
		}
	}
	require.Equal(t, 1, successes)
	require.Equal(t, 1, duplicates)
}
