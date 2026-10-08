package postgres

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"sync/atomic"
	"testing"
	"time"

	backendservices "github.com/lamassuiot/lamassuiot/backend/v3/pkg/services"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/errs"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	postgrestest "github.com/lamassuiot/lamassuiot/engines/storage/postgres/v3/test"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

type guardedImportKMS struct {
	services.KMSService
	calls   atomic.Int32
	entered chan struct{}
	release chan struct{}
}

func (kms *guardedImportKMS) GetKey(ctx context.Context, _ services.GetKeyInput) (*models.Key, error) {
	if kms.calls.Add(1) == 1 {
		close(kms.entered)
		select {
		case <-kms.release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return nil, errs.ErrKeyNotFound
}

type failingImportCARepo struct {
	storage.CACertificatesRepo
	err error
}

func (repo failingImportCARepo) WithIDLock(ctx context.Context, id string, fn func(storage.CACertificatesRepo) error) error {
	return repo.CACertificatesRepo.WithIDLock(ctx, id, func(scoped storage.CACertificatesRepo) error {
		return fn(failingImportCARepo{CACertificatesRepo: scoped, err: repo.err})
	})
}

func (repo failingImportCARepo) SelectByIssuerAndAuthorityKeyID(context.Context, models.Subject, string, storage.StorageListRequest[models.CACertificate]) (string, error) {
	return "", repo.err
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

func TestImportCAIDGuardPostgres(t *testing.T) {
	config, suite := postgrestest.BeforeSuite([]string{"ca"}, false)
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

	// Use an independent connection pool, as another service replica would.
	otherDB, err := CreatePostgresDBConnection(log, config, "ca")
	require.NoError(t, err)
	otherPool, err := otherDB.DB()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, otherPool.Close()) })
	otherRepo, err := NewCAPostgresRepository(log, otherDB)
	require.NoError(t, err)
	kms := &guardedImportKMS{entered: make(chan struct{}), release: make(chan struct{})}
	newService := func(repo storage.CACertificatesRepo) services.CAService {
		svc, err := backendservices.NewCAService(backendservices.CAServiceBuilder{CAStorage: repo, KMSService: kms, Logger: log})
		require.NoError(t, err)
		return svc
	}
	svc, otherSvc := newService(repo), newService(otherRepo)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	first, second := postgresImportInput(t, "shared", 1), postgresImportInput(t, "shared", 2)
	winner, loser := make(chan error, 1), make(chan error, 1)
	go func() { _, err := svc.ImportCA(ctx, first); winner <- err }()
	select {
	case <-kms.entered:
	case <-ctx.Done():
		t.Fatal("first import did not reach KMS")
	}
	go func() {
		ca, err := otherSvc.ImportCA(ctx, second)
		if ca != nil {
			loser <- errors.New("duplicate import returned a CA")
			return
		}
		loser <- err
	}()
	// Observe PostgreSQL waiting on the advisory lock before releasing the winner.
	require.Eventually(t, func() bool {
		var waiting int64
		return otherDB.Raw("SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND NOT granted").Scan(&waiting).Error == nil && waiting > 0
	}, 3*time.Second, 10*time.Millisecond)
	close(kms.release)
	require.NoError(t, <-winner)
	require.ErrorIs(t, <-loser, errs.ErrCAAlreadyExists)
	require.EqualValues(t, 1, kms.calls.Load(), "the loser must not reach KMS")
	countRows := func(table string, want int64) {
		var count int64
		require.NoError(t, db.Table(table).Count(&count).Error)
		require.Equal(t, want, count, table)
	}
	countRows("ca_certificates", 1)
	countRows("certificates", 1)

	t.Run("rollback after insert and retry", func(t *testing.T) {
		injected := errors.New("child discovery failed")
		failingSvc := newService(failingImportCARepo{CACertificatesRepo: repo, err: injected})
		input := postgresImportInput(t, "retry", 3)
		ca, err := failingSvc.ImportCA(ctx, input)
		require.ErrorIs(t, err, injected)
		require.Nil(t, ca)
		countRows("ca_certificates", 1)
		countRows("certificates", 1)
		ca, err = svc.ImportCA(ctx, input)
		require.NoError(t, err)
		require.Equal(t, input.ID, ca.ID)
	})

	t.Run("cancel waiting import", func(t *testing.T) {
		require.NoError(t, repo.WithIDLock(ctx, "shared", func(storage.CACertificatesRepo) error {
			waiting, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
			defer cancel()
			calls := kms.calls.Load()
			ca, err := otherSvc.ImportCA(waiting, second)
			require.Error(t, err)
			require.ErrorIs(t, waiting.Err(), context.DeadlineExceeded)
			require.Nil(t, ca)
			require.Equal(t, calls, kms.calls.Load())
			return nil
		}))
	})

	t.Run("duplicates and foreign-key errors", func(t *testing.T) {
		var serial string
		require.NoError(t, db.Raw("SELECT serial_number FROM ca_certificates WHERE id = 'retry'").Scan(&serial).Error)
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
