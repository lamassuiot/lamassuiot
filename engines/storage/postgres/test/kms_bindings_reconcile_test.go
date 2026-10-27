package postgrestest

import (
	"context"
	"testing"
	"time"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/config"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	postgres "github.com/lamassuiot/lamassuiot/v4/engines/storage/postgres"
	"github.com/stretchr/testify/require"
)

// Reconciliation makes the certificate bindings in a serial range exactly the ones the CA reports,
// without undoing recent bindings: their certificates may postdate the CA's snapshot. Their age is
// measured with the database clock, so the caller's clock does not matter.
func TestKMSStoreReconcileCertificateBindings(t *testing.T) {
	cfg, suite := BeforeSuite([]string{postgres.KMS_SCHEMA}, false)
	defer suite.AfterSuite()

	logger := helpers.SetupLogger(config.Info, "PostgreSQL", "Test")
	require.NoError(t, postgres.MigrateDatabase(logger, cfg, postgres.KMS_SCHEMA))

	store, err := postgres.NewKMSPostgresRepository(logger, suite.DB[postgres.KMS_SCHEMA])
	require.NoError(t, err)
	ctx := context.Background()

	for _, keyID := range []string{"k1", "k2"} {
		_, err := store.Insert(ctx, &models.Key{
			KeyID: keyID, EngineID: "engine", Name: keyID, Algorithm: "ECDSA", Size: 256, PublicKey: "pub", HasPrivateKey: true,
			CreationTS: time.Now().UTC().Truncate(time.Second), Aliases: []string{}, Tags: []string{}, Metadata: map[string]any{},
		})
		require.NoError(t, err)
	}
	bind := func(keyID, resourceType, serial string) {
		t.Helper()
		_, err := store.BindResource(ctx, keyID, "engine", models.KMSBindResource{ResourceType: resourceType, ResourceID: serial})
		require.NoError(t, err)
	}
	bound := func(keyID string) []string {
		t.Helper()
		bindings, err := store.SelectBindings(ctx, keyID, "engine")
		require.NoError(t, err)
		ids := []string{}
		for _, b := range bindings {
			ids = append(ids, b.ResourceType+"/"+b.ResourceID)
		}
		return ids
	}

	bind("k1", models.KMSBindResourceTypeCertificate, "b-stale")   // in range, no longer used
	bind("k1", models.KMSBindResourceTypeCertificate, "c-kept")    // in range, still used
	bind("k1", models.KMSBindResourceTypeCertificate, "z-outside") // outside the range
	bind("k1", "device", "d-other-type")                           // not a certificate
	// Everything above was bound an hour ago, by the database clock.
	require.NoError(t, suite.DB[postgres.KMS_SCHEMA].Exec(`UPDATE key_bindings SET created_at = now() - interval '1 hour'`).Error)
	bind("k2", models.KMSBindResourceTypeCertificate, "e-new") // bound while reconciling

	stats, err := store.ReconcileCertificateBindings(ctx, storage.ReconcileCertificateBindingsInput{
		After: "a", UpTo: "m", MinAge: 10 * time.Minute,
		Bindings: []models.CertificateKeyRef{
			{SerialNumber: "c-kept", KeyID: "k1", EngineID: "engine"},
			{SerialNumber: "d-missing", KeyID: "k2", EngineID: "engine"},
			{SerialNumber: "f-unknown-key", KeyID: "gone", EngineID: "engine"},
		},
	})
	require.NoError(t, err)

	require.Equal(t, []string{"certificate/c-kept", "certificate/z-outside", "device/d-other-type"}, bound("k1"))
	require.Equal(t, []string{"certificate/d-missing", "certificate/e-new"}, bound("k2"), "bindings newer than the run are kept")
	require.Equal(t, models.ReconcileStats{Added: 1, Removed: 1, MissingKeys: 1}, stats)

	t.Run("an open range reaches the last serial", func(t *testing.T) {
		_, err := store.ReconcileCertificateBindings(ctx, storage.ReconcileCertificateBindingsInput{After: "m", MinAge: 10 * time.Minute})
		require.NoError(t, err)
		require.Equal(t, []string{"certificate/c-kept", "device/d-other-type"}, bound("k1"))
	})
}
