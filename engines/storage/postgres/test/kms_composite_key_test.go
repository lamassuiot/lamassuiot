package postgrestest

import (
	"context"
	"testing"
	"time"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	postgres "github.com/lamassuiot/lamassuiot/engines/storage/postgres/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A key is identified by (key_id, engine_id): the same key_id can be held by several engines
// at once, e.g. the private key in an offline HSM and the public key in an online engine.
func TestKMSStoreCompositeKeyIdentity(t *testing.T) {
	cfg, suite := BeforeSuite([]string{postgres.KMS_SCHEMA}, false)
	defer suite.AfterSuite()

	logger := helpers.SetupLogger(config.Info, "PostgreSQL", "Test")
	require.NoError(t, postgres.MigrateDatabase(logger, cfg, postgres.KMS_SCHEMA))

	store, err := postgres.NewKMSPostgresRepository(logger, suite.DB[postgres.KMS_SCHEMA])
	require.NoError(t, err)

	ctx := context.Background()
	const keyID = "shared-key-id"

	newKey := func(engineID string, hasPrivateKey bool, name string) *models.Key {
		return &models.Key{
			KeyID:         keyID,
			EngineID:      engineID,
			Name:          name,
			Algorithm:     "RSA",
			Size:          2048,
			PublicKey:     "pub",
			HasPrivateKey: hasPrivateKey,
			CreationTS:    time.Now().UTC().Truncate(time.Second),
			Aliases:       []string{},
			Tags:          []string{},
			Metadata:      map[string]any{},
		}
	}

	_, err = store.Insert(ctx, newKey("hsm-offline", true, "offline copy"))
	require.NoError(t, err)
	_, err = store.Insert(ctx, newKey("online-1", false, "online copy"))
	require.NoError(t, err, "the same key_id must be storable in a second engine")

	copies, err := store.SelectByKeyID(ctx, keyID)
	require.NoError(t, err)
	assert.Len(t, copies, 2)

	t.Run("reads address a single engine", func(t *testing.T) {
		exists, key, err := store.SelectExistsByKeyID(ctx, keyID, "hsm-offline")
		require.NoError(t, err)
		require.True(t, exists)
		assert.Equal(t, "hsm-offline", key.EngineID)
		assert.True(t, key.HasPrivateKey)

		exists, key, err = store.SelectExistsByKeyID(ctx, keyID, "online-1")
		require.NoError(t, err)
		require.True(t, exists)
		assert.Equal(t, "online-1", key.EngineID)
		assert.False(t, key.HasPrivateKey)

		exists, _, err = store.SelectExistsByKeyID(ctx, keyID, "unknown-engine")
		require.NoError(t, err)
		assert.False(t, exists)
	})

	t.Run("updates do not reach the other engine", func(t *testing.T) {
		_, key, err := store.SelectExistsByKeyID(ctx, keyID, "online-1")
		require.NoError(t, err)

		key.Name = "renamed online copy"
		_, err = store.Update(ctx, key)
		require.NoError(t, err)

		_, updated, err := store.SelectExistsByKeyID(ctx, keyID, "online-1")
		require.NoError(t, err)
		assert.Equal(t, "renamed online copy", updated.Name)

		_, untouched, err := store.SelectExistsByKeyID(ctx, keyID, "hsm-offline")
		require.NoError(t, err)
		assert.Equal(t, "offline copy", untouched.Name)
	})

	t.Run("deletes remove one copy only", func(t *testing.T) {
		require.NoError(t, store.Delete(ctx, keyID, "online-1"))

		exists, _, err := store.SelectExistsByKeyID(ctx, keyID, "online-1")
		require.NoError(t, err)
		assert.False(t, exists)

		exists, _, err = store.SelectExistsByKeyID(ctx, keyID, "hsm-offline")
		require.NoError(t, err)
		assert.True(t, exists, "deleting the online copy must not delete the offline one")

		copies, err := store.SelectByKeyID(ctx, keyID)
		require.NoError(t, err)
		assert.Len(t, copies, 1)
		assert.Equal(t, "hsm-offline", copies[0].EngineID)
	})
}
