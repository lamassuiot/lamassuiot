package postgrestest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/config"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/errs"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	postgres "github.com/lamassuiot/lamassuiot/v4/engines/storage/postgres"
	"github.com/stretchr/testify/require"
)

func certBinding(serial string) models.KMSBindResource {
	return models.KMSBindResource{ResourceType: models.KMSBindResourceTypeCertificate, ResourceID: serial}
}

func boundSerials(t *testing.T, bindings []models.KeyBinding) []string {
	t.Helper()
	serials := []string{}
	for _, b := range bindings {
		require.Equal(t, models.KMSBindResourceTypeCertificate, b.ResourceType)
		serials = append(serials, b.ResourceID)
	}
	return serials
}

// A key in use by a certificate is bound to it, and the database refuses to delete a bound key.
func TestKMSStoreKeyBindings(t *testing.T) {
	cfg, suite := BeforeSuite([]string{postgres.KMS_SCHEMA}, false)
	defer suite.AfterSuite()

	logger := helpers.SetupLogger(config.Info, "PostgreSQL", "Test")
	require.NoError(t, postgres.MigrateDatabase(logger, cfg, postgres.KMS_SCHEMA))

	store, err := postgres.NewKMSPostgresRepository(logger, suite.DB[postgres.KMS_SCHEMA])
	require.NoError(t, err)
	ctx := context.Background()

	insertKey := func(keyID, engineID string) {
		t.Helper()
		_, err := store.Insert(ctx, &models.Key{
			KeyID: keyID, EngineID: engineID, Name: keyID, Algorithm: "ECDSA", Size: 256, PublicKey: "pub", HasPrivateKey: true,
			CreationTS: time.Now().UTC().Truncate(time.Second), Aliases: []string{}, Tags: []string{}, Metadata: map[string]any{},
		})
		require.NoError(t, err)
	}
	insertKey("shared", "engine-a")
	insertKey("shared", "engine-b")

	t.Run("bind is idempotent and reports whether it changed anything", func(t *testing.T) {
		created, err := store.BindResource(ctx, "shared", "engine-a", certBinding("aa"))
		require.NoError(t, err)
		require.True(t, created)

		created, err = store.BindResource(ctx, "shared", "engine-a", certBinding("aa"))
		require.NoError(t, err)
		require.False(t, created)

		bindings, err := store.SelectBindings(ctx, "shared", "engine-a")
		require.NoError(t, err)
		require.Equal(t, []string{"aa"}, boundSerials(t, bindings))
	})

	t.Run("bindings belong to one engine's copy of the key", func(t *testing.T) {
		bindings, err := store.SelectBindings(ctx, "shared", "engine-b")
		require.NoError(t, err)
		require.Empty(t, bindings)
	})

	t.Run("binding a key that does not exist fails", func(t *testing.T) {
		_, err := store.BindResource(ctx, "shared", "engine-missing", certBinding("aa"))
		require.ErrorIs(t, err, errs.ErrKeyNotFound)
	})

	t.Run("a bound key cannot be deleted", func(t *testing.T) {
		err := store.Delete(ctx, "shared", "engine-a")
		require.ErrorIs(t, err, errs.ErrKeyInUse)

		exists, _, err := store.SelectExistsByKeyID(ctx, "shared", "engine-a")
		require.NoError(t, err)
		require.True(t, exists)
	})

	t.Run("a bound key is not deleted and the engine is not touched", func(t *testing.T) {
		engineCalled := false
		err := store.DeleteWith(ctx, "shared", "engine-a", func() error { engineCalled = true; return nil })
		require.ErrorIs(t, err, errs.ErrKeyInUse)
		require.False(t, engineCalled, "the engine copy must survive while the key is bound")
	})

	t.Run("a failed engine deletion keeps the key", func(t *testing.T) {
		err := store.DeleteWith(ctx, "shared", "engine-b", func() error { return errors.New("engine unavailable") })
		require.Error(t, err)

		exists, _, err := store.SelectExistsByKeyID(ctx, "shared", "engine-b")
		require.NoError(t, err)
		require.True(t, exists)
	})

	t.Run("unbind is idempotent and frees the key", func(t *testing.T) {
		deleted, err := store.UnbindResource(ctx, "shared", "engine-a", certBinding("aa"))
		require.NoError(t, err)
		require.True(t, deleted)

		deleted, err = store.UnbindResource(ctx, "shared", "engine-a", certBinding("aa"))
		require.NoError(t, err)
		require.False(t, deleted)

		require.NoError(t, store.Delete(ctx, "shared", "engine-a"))
		exists, _, err := store.SelectExistsByKeyID(ctx, "shared", "engine-a")
		require.NoError(t, err)
		require.False(t, exists)
	})
}
