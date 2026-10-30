package postgrestest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/config"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	postgres "github.com/lamassuiot/lamassuiot/v4/engines/storage/postgres"
	"github.com/stretchr/testify/require"
)

// Renaming a key changes its key_id with its engine copy, keeps the old name as an alias and carries its
// bindings along.
func TestKMSStoreRenameKey(t *testing.T) {
	cfg, suite := BeforeSuite([]string{postgres.KMS_SCHEMA}, false)
	defer suite.AfterSuite()

	logger := helpers.SetupLogger(config.Info, "PostgreSQL", "Test")
	require.NoError(t, postgres.MigrateDatabase(logger, cfg, postgres.KMS_SCHEMA))

	store, err := postgres.NewKMSPostgresRepository(logger, suite.DB[postgres.KMS_SCHEMA])
	require.NoError(t, err)
	ctx := context.Background()

	_, err = store.Insert(ctx, &models.Key{
		KeyID: "ski", EngineID: "engine-a", Name: "imported", Algorithm: "ECDSA", Size: 256, PublicKey: "pub", HasPrivateKey: true,
		CreationTS: time.Now().UTC().Truncate(time.Second), Aliases: []string{"my-alias"}, Tags: []string{}, Metadata: map[string]any{},
	})
	require.NoError(t, err)
	_, err = store.BindResource(ctx, "ski", "engine-a", certBinding("aa"))
	require.NoError(t, err)

	t.Run("a failed engine rename leaves the key as it was", func(t *testing.T) {
		renamed, err := store.RenameKey(ctx, "engine-a", "ski", "digest", func() error { return errors.New("engine unavailable") })
		require.Error(t, err)
		require.False(t, renamed)

		exists, _, err := store.SelectExistsByKeyID(ctx, "ski", "engine-a")
		require.NoError(t, err)
		require.True(t, exists)
	})

	t.Run("the key, its aliases and its bindings move to the new name", func(t *testing.T) {
		engineRenamed := false
		renamed, err := store.RenameKey(ctx, "engine-a", "ski", "digest", func() error { engineRenamed = true; return nil })
		require.NoError(t, err)
		require.True(t, renamed)
		require.True(t, engineRenamed)

		exists, key, err := store.SelectExistsByKeyID(ctx, "digest", "engine-a")
		require.NoError(t, err)
		require.True(t, exists)
		require.ElementsMatch(t, []string{"my-alias", "ski"}, key.Aliases, "the old name stays reachable as an alias")

		bindings, err := store.SelectBindings(ctx, "digest", "engine-a")
		require.NoError(t, err)
		require.Equal(t, []string{"aa"}, boundSerials(t, bindings))
	})

	t.Run("renaming a key that is no longer there does nothing", func(t *testing.T) {
		engineRenamed := false
		renamed, err := store.RenameKey(ctx, "engine-a", "ski", "digest", func() error { engineRenamed = true; return nil })
		require.NoError(t, err)
		require.False(t, renamed)
		require.False(t, engineRenamed, "the engine is not touched for a key already renamed")
	})
}
