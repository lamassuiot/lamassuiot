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
)

type crlSettingsFixture struct {
	repo   storage.CRLSettingsRepo
	certs  storage.CertificatesRepo
	signer *models.Certificate
}

func newCRLSettingsFixture(t *testing.T) (crlSettingsFixture, func()) {
	t.Helper()
	cfg, suite := BeforeSuite([]string{postgres.KMS_SCHEMA, postgres.CA_SCHEMA, postgres.VA_SCHEMA}, false)
	logger := helpers.SetupLogger(config.Info, "test", "CRL settings")
	require.NoError(t, postgres.MigrateDatabase(logger, cfg, postgres.CA_SCHEMA))
	require.NoError(t, postgres.MigrateDatabase(logger, cfg, postgres.VA_SCHEMA))
	certs, err := postgres.NewCertificateRepository(logger, suite.DB[postgres.CA_SCHEMA])
	require.NoError(t, err)
	repo, err := postgres.NewCRLSettingsRepository(logger, suite.DB[postgres.VA_SCHEMA])
	require.NoError(t, err)
	signer := newTestCertificate(t, 101, "", "")
	_, err = certs.Insert(context.Background(), signer)
	require.NoError(t, err)
	return crlSettingsFixture{repo: repo, certs: certs, signer: signer}, func() { suite.AfterSuite() }
}

func (f crlSettingsFixture) settings(caID string, legacySKI *string) *models.CRLSettings {
	return &models.CRLSettings{
		CAID:      caID,
		LegacySKI: legacySKI,
		Status:    models.CRLSettingsActive,
		Options: models.CRLSettingsOptions{
			SignerSerialNumber: f.signer.SerialNumber,
			Validity:           models.TimeDuration(time.Hour),
			RefreshInterval:    models.TimeDuration(30 * time.Minute),
			RegenerateOnRevoke: true,
		},
		LatestCRL: models.LatestCRLMeta{Version: models.BigInt{Int: big.NewInt(0)}, ValidFrom: time.Now()},
	}
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
		_, err = f.repo.UpdateOptions(ctx, "ca-a", s.Options)
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
		updated, err := f.repo.UpdateOptions(ctx, "ca-b", opts)
		require.NoError(t, err)
		require.Equal(t, models.TimeDuration(2*time.Hour), updated.Options.Validity)
		require.False(t, updated.Options.RegenerateOnRevoke)
		require.Equal(t, models.CRLSettingsActive, updated.Status)
		require.Equal(t, "5", updated.LatestCRL.Version.String())

		_, err = f.repo.UpdateOptions(ctx, "nope", opts)
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
