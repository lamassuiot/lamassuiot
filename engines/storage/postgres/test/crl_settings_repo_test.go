package postgrestest

import (
	"context"
	"math/big"
	"testing"
	"time"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/config"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/errs"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/engines/storage/postgres"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

type crlSettingsFixture struct {
	repo    storage.CRLSettingsRepo
	certs   storage.CertificatesRepo
	kms     storage.KMSKeysRepo
	signer  *models.Certificate
	signer2 *models.Certificate
	caDB    *gorm.DB
}

func newCRLSettingsFixture(t *testing.T) (crlSettingsFixture, func()) {
	t.Helper()
	cfg, suite := BeforeSuite([]string{postgres.KMS_SCHEMA, postgres.CA_SCHEMA, postgres.VA_SCHEMA}, false)
	logger := helpers.SetupLogger(config.Info, "test", "CRL settings")
	require.NoError(t, postgres.MigrateDatabase(logger, cfg, postgres.KMS_SCHEMA))
	require.NoError(t, postgres.MigrateDatabase(logger, cfg, postgres.CA_SCHEMA))
	require.NoError(t, postgres.MigrateDatabase(logger, cfg, postgres.VA_SCHEMA))
	kms, err := postgres.NewKMSPostgresRepository(logger, suite.DB[postgres.KMS_SCHEMA])
	require.NoError(t, err)
	insertTestKey(t, kms, "e1", "k1")
	insertTestKey(t, kms, "e2", "k2")
	certs, err := postgres.NewCertificateRepository(logger, suite.DB[postgres.CA_SCHEMA])
	require.NoError(t, err)
	repo, err := postgres.NewCRLSettingsRepository(logger, suite.DB[postgres.VA_SCHEMA])
	require.NoError(t, err)
	signer := newTestCertificate(t, 101, "e1", "k1")
	_, err = certs.Insert(context.Background(), signer)
	require.NoError(t, err)
	signer2 := newTestCertificate(t, 102, "e2", "k2")
	_, err = certs.Insert(context.Background(), signer2)
	require.NoError(t, err)
	return crlSettingsFixture{repo: repo, certs: certs, kms: kms, signer: signer, signer2: signer2, caDB: suite.DB[postgres.CA_SCHEMA]}, func() { suite.AfterSuite() }
}

func (f crlSettingsFixture) settings(caID string, legacySKI *string) *models.CRLSettings {
	return &models.CRLSettings{
		CAID:           caID,
		LegacySKI:      legacySKI,
		Status:         models.CRLSettingsActive,
		SignerEngineID: &f.signer.EngineID,
		SignerKeyID:    &f.signer.KeyID,
		Options: models.CRLSettingsOptions{
			SignerSerialNumber: f.signer.SerialNumber,
			Validity:           models.TimeDuration(time.Hour),
			RefreshInterval:    models.TimeDuration(30 * time.Minute),
			RegenerateOnRevoke: true,
		},
		LatestCRL: models.LatestCRLMeta{Version: models.BigInt{Int: big.NewInt(0)}, ValidFrom: time.Now()},
	}
}

func (f crlSettingsFixture) key(cert *models.Certificate) models.CRLSignerKey {
	return models.CRLSignerKey{EngineID: cert.EngineID, KeyID: cert.KeyID}
}

func TestCRLSettingsRepo(t *testing.T) {
	f, cleanup := newCRLSettingsFixture(t)
	defer cleanup()
	ctx := context.Background()
	ski := "3f9a"

	t.Run("insert and get by CA id and by legacy SKI", func(t *testing.T) {
		_, err := f.repo.Insert(ctx, f.settings("ca-a", &ski))
		require.NoError(t, err)
		_, err = f.repo.Insert(ctx, f.settings("ca-b", nil))
		require.NoError(t, err)

		ok, got, err := f.repo.Get(ctx, "ca-a")
		require.NoError(t, err)
		require.True(t, ok)
		require.Equal(t, models.CRLSettingsActive, got.Status)
		require.Equal(t, f.signer.SerialNumber, got.Options.SignerSerialNumber)
		require.Equal(t, models.TimeDuration(time.Hour), got.Options.Validity)
		require.NotNil(t, got.LegacySKI)

		ok, _, err = f.repo.Get(ctx, "missing")
		require.NoError(t, err)
		require.False(t, ok)

		ok, got, err = f.repo.GetByLegacySKI(ctx, ski)
		require.NoError(t, err)
		require.True(t, ok)
		require.Equal(t, "ca-a", got.CAID)

		_, got, err = f.repo.Get(ctx, "ca-b")
		require.NoError(t, err)
		require.Nil(t, got.LegacySKI)
	})

	t.Run("legacy SKI is unique", func(t *testing.T) {
		_, err := f.repo.Insert(ctx, f.settings("ca-c", &ski))
		require.Error(t, err)
	})

	t.Run("the signer must be an existing certificate", func(t *testing.T) {
		s := f.settings("ca-d", nil)
		s.Options.SignerSerialNumber = "missing"
		_, err := f.repo.Insert(ctx, s)
		require.ErrorIs(t, err, errs.ErrCertificateNotFound)
		_, err = f.repo.UpdateOptions(ctx, "ca-a", s.Options, f.key(f.signer))
		require.ErrorIs(t, err, errs.ErrCertificateNotFound)
		_, stored, err := f.repo.Get(ctx, "ca-a")
		require.NoError(t, err)
		require.Equal(t, f.signer.SerialNumber, stored.Options.SignerSerialNumber)
	})

	t.Run("updating the options leaves status and latest CRL alone", func(t *testing.T) {
		require.NoError(t, f.repo.UpdateLatestCRL(ctx, "ca-b", big.NewInt(0), models.LatestCRLMeta{
			Version: models.BigInt{Int: big.NewInt(5)}, ValidFrom: time.Now(), ValidUntil: time.Now().Add(time.Hour),
		}))
		opts := f.settings("ca-b", nil).Options
		opts.Validity = models.TimeDuration(2 * time.Hour)
		opts.RegenerateOnRevoke = false
		updated, err := f.repo.UpdateOptions(ctx, "ca-b", opts, f.key(f.signer))
		require.NoError(t, err)
		require.Equal(t, models.TimeDuration(2*time.Hour), updated.Options.Validity)
		require.False(t, updated.Options.RegenerateOnRevoke)
		require.Equal(t, models.CRLSettingsActive, updated.Status)
		require.Equal(t, "5", updated.LatestCRL.Version.String())

		_, err = f.repo.UpdateOptions(ctx, "nope", opts, f.key(f.signer))
		require.ErrorIs(t, err, errs.ErrCRLSettingsNotFound)
	})

	t.Run("latest CRL is compare-and-swap on the version", func(t *testing.T) {
		latest := models.LatestCRLMeta{Version: models.BigInt{Int: big.NewInt(1)}, ValidFrom: time.Now(), ValidUntil: time.Now().Add(time.Hour)}
		require.NoError(t, f.repo.UpdateLatestCRL(ctx, "ca-a", big.NewInt(0), latest))
		require.ErrorIs(t, f.repo.UpdateLatestCRL(ctx, "ca-a", big.NewInt(0), latest), errs.ErrCRLSettingsConflict)
		_, got, err := f.repo.Get(ctx, "ca-a")
		require.NoError(t, err)
		require.Equal(t, "1", got.LatestCRL.Version.String())
		require.Equal(t, models.TimeDuration(time.Hour), got.Options.Validity, "options untouched")
	})

	t.Run("the signer certificate cannot be deleted while it is referenced", func(t *testing.T) {
		require.ErrorIs(t, f.certs.Delete(ctx, f.signer.SerialNumber), errs.ErrCertificateInUse, "still the signer of ca-b")
	})
}

func str(s *string) string {
	if s == nil {
		return "<nil>"
	}
	return *s
}

// The status transitions only move forward and decide which signer columns the settings keep (§4, §5).
func TestCRLSettingsRepoLifecycle(t *testing.T) {
	f, cleanup := newCRLSettingsFixture(t)
	defer cleanup()
	ctx := context.Background()
	get := func(caID string) *models.CRLSettings {
		ok, s, err := f.repo.Get(ctx, caID)
		require.NoError(t, err)
		require.True(t, ok, caID)
		return s
	}
	insert := func(caID string) {
		_, err := f.repo.Insert(ctx, f.settings(caID, nil))
		require.NoError(t, err)
	}
	latest := func(v int64) models.LatestCRLMeta {
		return models.LatestCRLMeta{Version: models.BigInt{Int: big.NewInt(v)}, ValidFrom: time.Now(), ValidUntil: time.Now().Add(time.Hour)}
	}

	t.Run("insert stores the key of the signer", func(t *testing.T) {
		insert("ins")
		s := get("ins")
		require.Equal(t, "e1", str(s.SignerEngineID))
		require.Equal(t, "k1", str(s.SignerKeyID))

		noKey := f.settings("ins-nokey", nil)
		noKey.SignerKeyID = nil
		_, err := f.repo.Insert(ctx, noKey)
		require.ErrorIs(t, err, errs.ErrValidateBadRequest)
	})

	t.Run("updating the options moves the key with the signer", func(t *testing.T) {
		insert("upd")
		opts := f.settings("upd", nil).Options
		opts.SignerSerialNumber = f.signer2.SerialNumber
		updated, err := f.repo.UpdateOptions(ctx, "upd", opts, f.key(f.signer2))
		require.NoError(t, err)
		require.Equal(t, f.signer2.SerialNumber, updated.Options.SignerSerialNumber)
		require.Equal(t, "e2", str(updated.SignerEngineID))
		require.Equal(t, "k2", str(updated.SignerKeyID))
	})

	t.Run("final is conditional on the version of the final CRL", func(t *testing.T) {
		insert("fin")
		require.NoError(t, f.repo.UpdateLatestCRL(ctx, "fin", big.NewInt(0), latest(3)))
		require.ErrorIs(t, f.repo.MarkFinal(ctx, "fin", big.NewInt(2)), errs.ErrCRLSettingsConflict)
		require.Equal(t, models.CRLSettingsActive, get("fin").Status)

		require.NoError(t, f.repo.MarkFinal(ctx, "fin", big.NewInt(3)))
		s := get("fin")
		require.Equal(t, models.CRLSettingsFinal, s.Status)
		require.Nil(t, s.SignerEngineID)
		require.Nil(t, s.SignerKeyID)
		require.Equal(t, f.signer.SerialNumber, s.Options.SignerSerialNumber, "the certificate is still retained")

		require.NoError(t, f.repo.MarkFinal(ctx, "fin", nil), "a retried transition is a no-op")
		require.Equal(t, models.CRLSettingsFinal, get("fin").Status)
	})

	t.Run("final settings neither take options nor new CRLs", func(t *testing.T) {
		_, err := f.repo.UpdateOptions(ctx, "fin", f.settings("fin", nil).Options, f.key(f.signer))
		require.ErrorIs(t, err, errs.ErrCRLSettingsNotActive)
		require.ErrorIs(t, f.repo.UpdateLatestCRL(ctx, "fin", big.NewInt(3), latest(4)), errs.ErrCRLSettingsNotActive)
		s := get("fin")
		require.Equal(t, "3", s.LatestCRL.Version.String())
		require.Nil(t, s.SignerKeyID)
	})

	t.Run("final without a CRL ignores the version", func(t *testing.T) {
		insert("exp")
		require.NoError(t, f.repo.MarkFinal(ctx, "exp", nil))
		require.Equal(t, models.CRLSettingsFinal, get("exp").Status)
	})

	t.Run("archived releases the certificate and never goes back", func(t *testing.T) {
		require.NoError(t, f.repo.MarkArchived(ctx, "fin"))
		s := get("fin")
		require.Equal(t, models.CRLSettingsArchived, s.Status)
		require.Empty(t, s.Options.SignerSerialNumber)
		require.NoError(t, f.repo.MarkArchived(ctx, "fin"), "a retried transition is a no-op")
		require.NoError(t, f.repo.MarkFinal(ctx, "fin", nil))
		require.Equal(t, models.CRLSettingsArchived, get("fin").Status)
		_, err := f.repo.UpdateOptions(ctx, "fin", f.settings("fin", nil).Options, f.key(f.signer))
		require.ErrorIs(t, err, errs.ErrCRLSettingsNotActive)

		insert("act")
		require.NoError(t, f.repo.MarkArchived(ctx, "act"), "active settings of a CA that no longer exists")
		require.Equal(t, models.CRLSettingsArchived, get("act").Status)
	})

	t.Run("transitions of missing settings", func(t *testing.T) {
		require.ErrorIs(t, f.repo.MarkFinal(ctx, "missing", nil), errs.ErrCRLSettingsNotFound)
		require.ErrorIs(t, f.repo.MarkArchived(ctx, "missing"), errs.ErrCRLSettingsNotFound)
	})

	t.Run("only archived settings are deleted", func(t *testing.T) {
		require.ErrorIs(t, f.repo.Delete(ctx, "upd"), errs.ErrCRLSettingsNotArchived)
		require.ErrorIs(t, f.repo.Delete(ctx, "exp"), errs.ErrCRLSettingsNotArchived)
		require.ErrorIs(t, f.repo.Delete(ctx, "missing"), errs.ErrCRLSettingsNotFound)
		require.NoError(t, f.repo.Delete(ctx, "fin"))
		ok, _, err := f.repo.Get(ctx, "fin")
		require.NoError(t, err)
		require.False(t, ok)
	})
}

// ACTIVE settings retain the KMS key of their signer: the KMS cannot delete it until the settings are FINAL, even once
// the certificate released it. CRLSettingsHoldingKey names the CAs whose settings retain it.
func TestReleaseKeyRetainedByCRLSettings(t *testing.T) {
	f, cleanup := newCRLSettingsFixture(t)
	defer cleanup()
	ctx := context.Background()
	_, err := f.repo.Insert(ctx, f.settings("ca-a", nil))
	require.NoError(t, err)
	serials := []string{f.signer.SerialNumber}

	_, err = f.repo.Insert(ctx, f.settings("ca-b", nil))
	require.NoError(t, err)
	holders := func(serials []string) []string {
		got, err := f.certs.CRLSettingsHoldingKey(ctx, serials)
		require.NoError(t, err)
		return got
	}
	require.Equal(t, []string{"ca-a", "ca-b"}, holders(serials))
	require.Empty(t, holders([]string{f.signer2.SerialNumber}), "a certificate no settings use")
	require.Empty(t, holders(nil))

	require.NoError(t, f.certs.ReleaseKey(ctx, serials))
	require.ErrorIs(t, f.kms.Delete(ctx, "k1", "e1"), errs.ErrKeyInUse, "the settings still retain the key")

	require.NoError(t, f.repo.MarkFinal(ctx, "ca-a", nil))
	require.Equal(t, []string{"ca-b"}, holders(serials))
	require.NoError(t, f.repo.MarkFinal(ctx, "ca-b", nil))
	require.Empty(t, holders(serials))
	require.NoError(t, f.kms.Delete(ctx, "k1", "e1"))
}

// CRLSettingsHoldingKey only reads: it neither waits for nor takes the locks of the certificates it checks, so it does not
// block a concurrent writer of those rows.
func TestCRLSettingsHoldingKeyDoesNotLockTheCertificates(t *testing.T) {
	f, cleanup := newCRLSettingsFixture(t)
	defer cleanup()
	_, err := f.repo.Insert(context.Background(), f.settings("ca-a", nil))
	require.NoError(t, err)

	writer := f.caDB.Begin()
	defer writer.Rollback()
	require.NoError(t, writer.Exec("SELECT 1 FROM certificates WHERE serial_number IN ? FOR UPDATE",
		[]string{f.signer.SerialNumber, f.signer2.SerialNumber}).Error)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	holders, err := f.certs.CRLSettingsHoldingKey(ctx, []string{f.signer.SerialNumber})
	require.NoError(t, err)
	require.Equal(t, []string{"ca-a"}, holders)
	holders, err = f.certs.CRLSettingsHoldingKey(ctx, []string{f.signer2.SerialNumber})
	require.NoError(t, err)
	require.Empty(t, holders)
}
