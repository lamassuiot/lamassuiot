package postgrestest

import (
	"context"
	"math/big"
	"testing"
	"time"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/errs"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCRLSettingsTenantIsolation(t *testing.T) {
	f, cleanup := newCRLSettingsFixture(t)
	defer cleanup()

	ctxA := tenantTestContext("tenant-a", models.TenantActive)
	ctxB := tenantTestContext("tenant-b", models.TenantActive)

	newSigner := func(ctx context.Context, serial int, keyID string) *models.Certificate {
		_, err := f.kms.Insert(ctx, &models.Key{
			KeyID: keyID, EngineID: "e1", Name: keyID, Algorithm: "ECDSA", Size: 256, PublicKey: "pub-" + keyID,
			HasPrivateKey: true, CreationTS: time.Now().UTC().Truncate(time.Second),
			Aliases: []string{}, Tags: []string{}, Metadata: map[string]any{},
		})
		require.NoError(t, err)
		signer := newTestCertificate(t, serial, "e1", keyID)
		_, err = f.certs.Insert(ctx, signer)
		require.NoError(t, err)
		return signer
	}
	signerA := newSigner(ctxA, 201, "ka")
	signerB := newSigner(ctxB, 202, "kb")

	settingsFor := func(caID string, legacySKI *string, signer *models.Certificate) *models.CRLSettings {
		settings := f.settings(caID, legacySKI)
		settings.Options.SignerSerialNumber = signer.SerialNumber
		settings.SignerEngineID = &signer.EngineID
		settings.SignerKeyID = &signer.KeyID
		return settings
	}

	t.Run("insert takes the tenant from the context", func(t *testing.T) {
		settings := settingsFor("ca-1", nil, signerA)
		settings.TenantID = "tenant-b"
		inserted, err := f.repo.Insert(ctxA, settings)
		require.NoError(t, err)
		assert.Equal(t, "tenant-a", inserted.TenantID)
	})

	t.Run("the signer must belong to the same tenant", func(t *testing.T) {
		_, err := f.repo.Insert(ctxA, settingsFor("ca-cross", nil, signerB))
		assert.ErrorIs(t, err, errs.ErrCertificateNotFound)
	})

	t.Run("another tenant cannot read it", func(t *testing.T) {
		exists, _, err := f.repo.Get(ctxA, "ca-1")
		require.NoError(t, err)
		assert.True(t, exists)

		exists, _, err = f.repo.Get(ctxB, "ca-1")
		require.NoError(t, err)
		assert.False(t, exists)
	})

	t.Run("another tenant cannot update its options", func(t *testing.T) {
		options := settingsFor("ca-1", nil, signerB).Options
		options.Validity = models.TimeDuration(5 * time.Hour)
		_, err := f.repo.UpdateOptions(ctxB, "ca-1", options, f.key(signerB))
		assert.ErrorIs(t, err, errs.ErrCRLSettingsNotFound)

		_, got, err := f.repo.Get(ctxA, "ca-1")
		require.NoError(t, err)
		assert.Equal(t, models.TimeDuration(time.Hour), got.Options.Validity)
	})

	t.Run("another tenant cannot update its latest CRL", func(t *testing.T) {
		now := time.Now()
		latest := models.LatestCRLMeta{Version: models.BigInt{Int: big.NewInt(1)}, ValidFrom: now, ValidUntil: now.Add(time.Hour)}
		err := f.repo.UpdateLatestCRL(ctxB, "ca-1", big.NewInt(0), latest)
		assert.ErrorIs(t, err, errs.ErrCRLSettingsNotFound)

		_, got, err := f.repo.Get(ctxA, "ca-1")
		require.NoError(t, err)
		assert.Equal(t, int64(0), got.LatestCRL.Version.Int64())
	})

	t.Run("another tenant cannot find it by its legacy SKI", func(t *testing.T) {
		ski := "aa11"
		_, err := f.repo.Insert(ctxA, settingsFor("ca-2", &ski, signerA))
		require.NoError(t, err)

		exists, _, err := f.repo.GetByLegacySKI(ctxA, ski)
		require.NoError(t, err)
		assert.True(t, exists)

		exists, _, err = f.repo.GetByLegacySKI(ctxB, ski)
		require.NoError(t, err)
		assert.False(t, exists)
	})

	t.Run("lists are scoped to the tenant", func(t *testing.T) {
		_, err := f.repo.Insert(ctxB, settingsFor("ca-3", nil, signerB))
		require.NoError(t, err)

		caIDs := []string{}
		_, err = f.repo.GetAll(ctxB, storage.StorageListRequest[models.CRLSettings]{
			ExhaustiveRun: true,
			ApplyFunc: func(settings models.CRLSettings) {
				caIDs = append(caIDs, settings.CAID)
			},
		})
		require.NoError(t, err)
		assert.Equal(t, []string{"ca-3"}, caIDs)
	})

	t.Run("another tenant cannot move it through its lifecycle", func(t *testing.T) {
		assert.ErrorIs(t, f.repo.MarkFinal(ctxB, "ca-1", nil), errs.ErrCRLSettingsNotFound)
		assert.ErrorIs(t, f.repo.MarkArchived(ctxB, "ca-1"), errs.ErrCRLSettingsNotFound)
		assert.ErrorIs(t, f.repo.Delete(ctxB, "ca-1"), errs.ErrCRLSettingsNotFound)

		_, got, err := f.repo.Get(ctxA, "ca-1")
		require.NoError(t, err)
		assert.Equal(t, models.CRLSettingsActive, got.Status)
		require.NotNil(t, got.SignerKeyID)
		assert.Equal(t, "ka", *got.SignerKeyID)
	})

	t.Run("the settings holding a key are scoped to the tenant", func(t *testing.T) {
		holders, err := f.certs.CRLSettingsHoldingKey(ctxA, []string{signerA.SerialNumber, signerB.SerialNumber})
		require.NoError(t, err)
		assert.Equal(t, []string{"ca-1", "ca-2"}, holders)

		holders, err = f.certs.CRLSettingsHoldingKey(ctxB, []string{signerA.SerialNumber, signerB.SerialNumber})
		require.NoError(t, err)
		assert.Equal(t, []string{"ca-3"}, holders)
	})

	t.Run("another tenant cannot release the key of its certificates", func(t *testing.T) {
		require.NoError(t, f.certs.ReleaseKey(ctxB, []string{signerA.SerialNumber}))
		_, stored, err := f.certs.SelectExistsBySerialNumber(ctxA, signerA.SerialNumber)
		require.NoError(t, err)
		assert.Equal(t, "ka", stored.KeyID)

		require.NoError(t, f.certs.ReleaseKey(ctxA, []string{signerA.SerialNumber}))
		_, stored, err = f.certs.SelectExistsBySerialNumber(ctxA, signerA.SerialNumber)
		require.NoError(t, err)
		assert.Empty(t, stored.KeyID)
	})
}
