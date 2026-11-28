package postgrestest

import (
	"context"
	"testing"
	"time"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/errs"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/stretchr/testify/require"
)

// Recording the private key of a key writes has_private_key and an empty name only: what was saved in the row after it
// was read, such as the aliases, tags and metadata another request changed while the key was being imported, is kept.
func TestKMSStoreRecordPrivateKey(t *testing.T) {
	_, kmsStore, _ := newKMSAndCertStores(t)
	ctx := context.Background()

	insert := func(keyID, name string) *models.Key {
		t.Helper()
		key, err := kmsStore.Insert(ctx, &models.Key{
			KeyID: keyID, EngineID: "engine-a", Name: name, Algorithm: "ECDSA", Size: 256, PublicKey: "pub", Digest: fakeDigest(keyID),
			CreationTS: time.Now().UTC().Truncate(time.Second), Aliases: []string{}, Tags: []string{}, Metadata: map[string]any{},
		})
		require.NoError(t, err)
		return key
	}

	t.Run("the private key is recorded and the changes saved since the row was read are kept", func(t *testing.T) {
		read := insert("public-only", "")
		edited := *read
		edited.Aliases = []string{"added meanwhile"}
		edited.Tags = []string{"tagged meanwhile"}
		edited.Metadata = map[string]any{"edited": "meanwhile"}
		_, err := kmsStore.Update(ctx, &edited)
		require.NoError(t, err)

		got, err := kmsStore.RecordPrivateKey(ctx, "public-only", "engine-a", "imported")
		require.NoError(t, err)
		require.True(t, got.HasPrivateKey)
		require.Equal(t, "pkcs11:token-id=engine-a;id=public-only;type=private", got.PKCS11URI)

		_, stored, err := kmsStore.SelectExistsByKeyID(ctx, "public-only", "engine-a")
		require.NoError(t, err)
		require.True(t, stored.HasPrivateKey)
		require.Equal(t, "imported", stored.Name, "a key without a name takes the one given")
		require.Equal(t, []string{"added meanwhile"}, stored.Aliases)
		require.Equal(t, []string{"tagged meanwhile"}, stored.Tags)
		require.Equal(t, map[string]any{"edited": "meanwhile"}, stored.Metadata)
		require.Equal(t, read.ID, stored.ID)
	})

	t.Run("a key that has a name keeps it", func(t *testing.T) {
		insert("named", "original")
		got, err := kmsStore.RecordPrivateKey(ctx, "named", "engine-a", "imported")
		require.NoError(t, err)
		require.Equal(t, "original", got.Name)
	})

	t.Run("a key that is not there is not found", func(t *testing.T) {
		_, err := kmsStore.RecordPrivateKey(ctx, "missing", "engine-a", "imported")
		require.ErrorIs(t, err, errs.ErrKeyNotFound)
		insert("other-engine", "")
		_, err = kmsStore.RecordPrivateKey(ctx, "other-engine", "engine-b", "imported")
		require.ErrorIs(t, err, errs.ErrKeyNotFound, "the key_id of another engine does not match")
	})
}
