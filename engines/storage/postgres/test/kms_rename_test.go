package postgrestest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Renaming a key changes its key_id with its engine copy, keeps the old name as an alias and carries the
// references of the certificates that use it along.
func TestKMSStoreRenameKey(t *testing.T) {
	_, kmsStore, certStore := newKMSAndCertStores(t)
	ctx := context.Background()

	_, err := kmsStore.Insert(ctx, &models.Key{
		KeyID: "ski", EngineID: "engine-a", Name: "imported", Algorithm: "ECDSA", Size: 256, PublicKey: "pub", HasPrivateKey: true,
		CreationTS: time.Now().UTC().Truncate(time.Second), Aliases: []string{"my-alias"}, Tags: []string{}, Metadata: map[string]any{},
	})
	require.NoError(t, err)
	cert := newTestCertificate(t, 1, "engine-a", "ski")
	_, err = certStore.Insert(ctx, cert)
	require.NoError(t, err)

	t.Run("a failed engine rename leaves the key as it was", func(t *testing.T) {
		renamed, err := kmsStore.RenameKey(ctx, "engine-a", "ski", "digest", func() error { return errors.New("engine unavailable") })
		require.Error(t, err)
		require.False(t, renamed)

		exists, _, err := kmsStore.SelectExistsByKeyID(ctx, "ski", "engine-a")
		require.NoError(t, err)
		require.True(t, exists)
	})

	t.Run("the key, its aliases and the references to it move to the new name", func(t *testing.T) {
		engineRenamed := false
		renamed, err := kmsStore.RenameKey(ctx, "engine-a", "ski", "digest", func() error { engineRenamed = true; return nil })
		require.NoError(t, err)
		require.True(t, renamed)
		require.True(t, engineRenamed)

		exists, key, err := kmsStore.SelectExistsByKeyID(ctx, "digest", "engine-a")
		require.NoError(t, err)
		require.True(t, exists)
		require.ElementsMatch(t, []string{"my-alias", "ski"}, key.Aliases, "the old name stays reachable as an alias")

		exists, stored, err := certStore.SelectExistsBySerialNumber(ctx, cert.SerialNumber)
		require.NoError(t, err)
		require.True(t, exists)
		assert.Equal(t, "digest", stored.KeyID, "the certificate follows its key")
	})

	t.Run("renaming a key that is no longer there does nothing", func(t *testing.T) {
		engineRenamed := false
		renamed, err := kmsStore.RenameKey(ctx, "engine-a", "ski", "digest", func() error { engineRenamed = true; return nil })
		require.NoError(t, err)
		require.False(t, renamed)
		require.False(t, engineRenamed, "the engine is not touched for a key already renamed")
	})
}
