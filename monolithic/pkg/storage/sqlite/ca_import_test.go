package sqlite

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
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	backendservices "github.com/lamassuiot/lamassuiot/backend/v3/pkg/services"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/errs"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

type sqliteImportKMS struct {
	services.KMSService
	db       *gorm.DB
	entered  chan struct{}
	release  chan struct{}
	calls    atomic.Int32
	bindings atomic.Int32
}

func (kms *sqliteImportKMS) ImportKey(ctx context.Context, _ services.ImportKeyInput) (*models.Key, error) {
	if kms.calls.Add(1) == 1 {
		close(kms.entered)
		select {
		case <-kms.release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	// Exercise the same single-connection pool while the CA ID guard is held.
	if err := kms.db.WithContext(ctx).Exec("INSERT INTO kms_keys (key_id, name, algorithm, size, public_key, engine_id) VALUES (?, ?, ?, ?, ?, ?)",
		"01", "key", "ECDSA", 256, "public", "test-engine").Error; err != nil {
		return nil, err
	}
	return &models.Key{KeyID: "01", EngineID: "test-engine"}, nil
}

func (kms *sqliteImportKMS) UpdateKeyMetadata(_ context.Context, input services.UpdateKeyMetadataInput) (*models.Key, error) {
	kms.bindings.Add(1)
	return &models.Key{KeyID: input.ID, EngineID: "test-engine"}, nil
}

type observedCARepo struct {
	storage.CACertificatesRepo
	enter chan struct{}
}

func (repo observedCARepo) WithIDLock(ctx context.Context, id string, fn func(storage.CACertificatesRepo) error) error {
	close(repo.enter)
	return repo.CACertificatesRepo.WithIDLock(ctx, id, fn)
}

func sqliteImportFixture(t *testing.T) (*gorm.DB, *logrus.Entry, storage.CACertificatesRepo) {
	t.Helper()
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	log := logrus.NewEntry(logger)
	db, err := CreateSQLiteDBConnection(log, filepath.Join(t.TempDir(), "ca.sqlite"))
	require.NoError(t, err)
	pool, err := db.DB()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, pool.Close()) })
	require.NoError(t, initializeSchema(db))
	repo, err := newCARepository(log, db)
	require.NoError(t, err)
	return db, log, repo
}

func sqliteImportInput(t *testing.T, serial int64) services.ImportCAInput {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "imported root"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		SubjectKeyId: []byte{1}, AuthorityKeyId: []byte{1}, IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return services.ImportCAInput{ID: "shared-ca", CACertificate: (*models.X509Certificate)(cert), Key: key}
}

func TestConcurrentImportCAOnSQLite(t *testing.T) {
	db, log, repo := sqliteImportFixture(t)
	// A second repository and service must share the same guard.
	otherRepo, err := newCARepository(log, db)
	require.NoError(t, err)
	secondEntered := make(chan struct{})
	kms := &sqliteImportKMS{db: db, entered: make(chan struct{}), release: make(chan struct{})}
	svc, err := backendservices.NewCAService(backendservices.CAServiceBuilder{CAStorage: repo, KMSService: kms, Logger: log})
	require.NoError(t, err)
	otherSvc, err := backendservices.NewCAService(backendservices.CAServiceBuilder{
		CAStorage: observedCARepo{CACertificatesRepo: otherRepo, enter: secondEntered}, KMSService: kms, Logger: log,
	})
	require.NoError(t, err)
	first, second := sqliteImportInput(t, 1), sqliteImportInput(t, 2)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
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
	select {
	case <-secondEntered:
	case <-ctx.Done():
		t.Fatal("second import did not enter the guard")
	}
	close(kms.release)
	require.NoError(t, <-winner)
	require.ErrorIs(t, <-loser, errs.ErrCAAlreadyExists)
	require.EqualValues(t, 1, kms.calls.Load(), "the loser must not import a key")
	require.EqualValues(t, 1, kms.bindings.Load(), "the loser must not bind a key")
	for _, table := range []string{"ca_certificates", "certificates", "kms_keys"} {
		var count int64
		require.NoError(t, db.Table(table).Count(&count).Error)
		require.EqualValues(t, 1, count, table)
	}
}

func TestSQLiteCAIDGuardCancellationAndFailure(t *testing.T) {
	_, _, repo := sqliteImportFixture(t)
	ctx := context.Background()
	err := repo.WithIDLock(ctx, "held", func(storage.CACertificatesRepo) error {
		waiting, cancel := context.WithTimeout(ctx, 20*time.Millisecond)
		defer cancel()
		err := repo.WithIDLock(waiting, "held", func(storage.CACertificatesRepo) error {
			t.Error("cancelled waiter entered the callback")
			return nil
		})
		require.ErrorIs(t, err, context.DeadlineExceeded)
		// Different IDs can proceed while one is held.
		return repo.WithIDLock(ctx, "other", func(storage.CACertificatesRepo) error { return nil })
	})
	require.NoError(t, err)
	injected := errors.New("import failed")
	require.ErrorIs(t, repo.WithIDLock(ctx, "held", func(storage.CACertificatesRepo) error { return injected }), injected)
	require.NoError(t, repo.WithIDLock(ctx, "held", func(storage.CACertificatesRepo) error { return nil }))
}

func TestSQLiteCAIDUniqueConstraint(t *testing.T) {
	db, _, repo := sqliteImportFixture(t)
	ca := func(serial string) *models.CACertificate {
		return &models.CACertificate{ID: "duplicate", CertificateSerialNumber: serial}
	}
	require.NoError(t, db.Exec("INSERT INTO certificates (serial_number) VALUES ('a'), ('b')").Error)
	_, err := repo.Insert(context.Background(), ca("a"))
	require.NoError(t, err)
	_, err = repo.Insert(context.Background(), ca("b"))
	require.ErrorIs(t, err, errs.ErrCAAlreadyExists)
	// A foreign-key violation must not become a duplicate-CA error.
	_, err = repo.Insert(context.Background(), &models.CACertificate{ID: "other", CertificateSerialNumber: "missing"})
	require.ErrorIs(t, err, gorm.ErrForeignKeyViolated)
	require.NotErrorIs(t, err, errs.ErrCAAlreadyExists)
}

func TestSQLiteCAIDUpgradeRejectsExistingDuplicates(t *testing.T) {
	db, _, _ := sqliteImportFixture(t)
	require.NoError(t, db.Exec("DROP INDEX ca_certificates_id_unique").Error)
	require.NoError(t, db.Exec("INSERT INTO certificates (serial_number) VALUES ('a'), ('b')").Error)
	require.NoError(t, db.Exec("INSERT INTO ca_certificates (serial_number, id) VALUES ('a', 'duplicate'), ('b', 'duplicate')").Error)
	require.ErrorIs(t, initializeSchema(db), gorm.ErrDuplicatedKey)
	var count int64
	require.NoError(t, db.Table("ca_certificates").Count(&count).Error)
	require.EqualValues(t, 2, count, "the upgrade must not discard either CA")
	// After explicit cleanup, initializing an existing database creates the index.
	require.NoError(t, db.Exec("DELETE FROM ca_certificates WHERE serial_number = 'b'").Error)
	require.NoError(t, initializeSchema(db))
	require.Error(t, db.Exec("INSERT INTO ca_certificates (serial_number, id) VALUES ('b', 'duplicate')").Error)
}

func TestSQLiteCAInsertConflictRollsBackCertificate(t *testing.T) {
	db, log, repo := sqliteImportFixture(t)
	kms := &sqliteImportKMS{db: db, entered: make(chan struct{}), release: make(chan struct{})}
	close(kms.release)
	svc, err := backendservices.NewCAService(backendservices.CAServiceBuilder{CAStorage: repo, KMSService: kms, Logger: log})
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	original, err := svc.ImportCA(ctx, sqliteImportInput(t, 1))
	require.NoError(t, err)
	duplicate := *original
	duplicate.CertificateSerialNumber = ""
	duplicate.Certificate.SerialNumber = "new-serial"
	ca, err := repo.Insert(ctx, &duplicate)
	require.ErrorIs(t, err, errs.ErrCAAlreadyExists)
	require.Nil(t, ca)
	for _, table := range []string{"ca_certificates", "certificates"} {
		var count int64
		require.NoError(t, db.Table(table).Count(&count).Error)
		require.EqualValues(t, 1, count, "a skipped CA insert must roll back its new certificate")
	}
}
