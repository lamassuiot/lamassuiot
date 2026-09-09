package sqlite

import (
	"context"
	"testing"
	"time"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/engines/storage/postgres/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The monolithic deployment runs the Postgres KMS repository on SQLite, so every query it
// issues has to work on both dialects.
func TestKMSStoreOnSQLite(t *testing.T) {
	logger := helpers.SetupLogger(config.Info, "SQLite", "Test")
	db, err := CreateSQLiteDBConnection(logger, "file::memory:?cache=shared")
	require.NoError(t, err)
	require.NoError(t, initializeSchema(db))

	store, err := postgres.NewKMSPostgresRepository(logger, db)
	require.NoError(t, err)

	ctx := context.Background()
	newKey := func(keyID, engineID, alias string) *models.Key {
		return &models.Key{
			KeyID: keyID, EngineID: engineID, Name: keyID, Algorithm: "RSA", Size: 2048,
			PublicKey: "pub", HasPrivateKey: true, CreationTS: time.Now().UTC().Truncate(time.Second),
			Aliases: []string{alias}, Tags: []string{}, Metadata: map[string]any{},
		}
	}

	_, err = store.Insert(ctx, newKey("shared-key", "hsm-offline", "offline-alias"))
	require.NoError(t, err)
	_, err = store.Insert(ctx, newKey("shared-key", "online-1", "online-alias"))
	require.NoError(t, err, "the same key_id must be storable in a second engine")

	t.Run("alias lookup", func(t *testing.T) {
		exists, key, err := store.SelectExistsByAlias(ctx, "online-alias")
		require.NoError(t, err)
		require.True(t, exists)
		assert.Equal(t, "online-1", key.EngineID)

		exists, _, err = store.SelectExistsByAlias(ctx, "missing-alias")
		require.NoError(t, err)
		assert.False(t, exists)
	})

	t.Run("composite identity", func(t *testing.T) {
		copies, err := store.SelectByKeyID(ctx, "shared-key")
		require.NoError(t, err)
		assert.Len(t, copies, 2)

		require.NoError(t, store.Delete(ctx, "shared-key", "online-1"))

		copies, err = store.SelectByKeyID(ctx, "shared-key")
		require.NoError(t, err)
		require.Len(t, copies, 1, "deleting one copy must not delete the other")
		assert.Equal(t, "hsm-offline", copies[0].EngineID)
	})
}
