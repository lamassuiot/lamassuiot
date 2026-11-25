package postgrestest

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/config"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	postgres "github.com/lamassuiot/lamassuiot/v4/engines/storage/postgres"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// A key is stored with an id the database assigns and the digest of its public key, and found by either.
func TestKMSStoreKeyIdentity(t *testing.T) {
	cfg, suite := BeforeSuite([]string{postgres.KMS_SCHEMA}, false)
	defer suite.AfterSuite()

	logger := helpers.SetupLogger(config.Info, "PostgreSQL", "Test")
	require.NoError(t, postgres.MigrateDatabase(logger, cfg, postgres.KMS_SCHEMA))

	store, err := postgres.NewKMSPostgresRepository(logger, suite.DB[postgres.KMS_SCHEMA])
	require.NoError(t, err)
	ctx := context.Background()

	// a real public key: the storage derives the digest of it when the caller does not set one
	publicKey, digest := realPublicKey(t)
	newKey := func(keyID, engineID string) *models.Key {
		return &models.Key{
			KeyID: keyID, EngineID: engineID, Name: keyID + "@" + engineID, Algorithm: "ECDSA", Size: 256, PublicKey: publicKey,
			HasPrivateKey: true, CreationTS: time.Now().UTC().Truncate(time.Second),
			Aliases: []string{}, Tags: []string{}, Metadata: map[string]any{},
		}
	}

	first, err := store.Insert(ctx, newKey(digest, "engine-1"))
	require.NoError(t, err)
	// the same public key in a second engine, held there under another name
	second, err := store.Insert(ctx, newKey("a-name-of-its-own", "engine-2"))
	require.NoError(t, err)

	t.Run("insert assigns the id and derives the digest", func(t *testing.T) {
		assert.True(t, helpers.IsKeyUUID(first.ID), "id %q", first.ID)
		assert.Equal(t, digest, first.Digest)
		assert.NotEqual(t, first.ID, second.ID)
	})

	t.Run("a public key is stored once per engine, whatever its name", func(t *testing.T) {
		_, err := store.Insert(ctx, newKey("yet-another-name", "engine-1"))
		require.Error(t, err)
	})

	t.Run("a public key that is not one is not stored", func(t *testing.T) {
		bad := newKey("garbled", "engine-3")
		bad.PublicKey = "not-a-public-key"
		_, err := store.Insert(ctx, bad)
		require.Error(t, err)
	})

	t.Run("SelectExistsByID finds the key", func(t *testing.T) {
		exists, key, err := store.SelectExistsByID(ctx, second.ID)
		require.NoError(t, err)
		require.True(t, exists)
		assert.Equal(t, "engine-2", key.EngineID)
		assert.Equal(t, second.ID, key.ID)
		assert.Equal(t, digest, key.Digest)

		exists, key, err = store.SelectExistsByID(ctx, strings.ToUpper(second.ID))
		require.NoError(t, err)
		require.True(t, exists, "an id in uppercase is the same id")
		assert.Equal(t, second.ID, key.ID)
	})

	t.Run("SelectExistsByID finds nothing for an unknown id or something that is not an id", func(t *testing.T) {
		for _, id := range []string{"0190a6c4-7f3e-7b2a-9c1d-3e5f6a7b8c99", "not-an-id", "", digest} {
			exists, key, err := store.SelectExistsByID(ctx, id)
			require.NoError(t, err, "id %q", id)
			assert.False(t, exists)
			assert.Nil(t, key)
		}
	})

	t.Run("SelectByDigest returns the copy of every engine", func(t *testing.T) {
		keys, err := store.SelectByDigest(ctx, digest)
		require.NoError(t, err)
		require.Len(t, keys, 2)
		assert.Equal(t, "engine-1", keys[0].EngineID)
		assert.Equal(t, "engine-2", keys[1].EngineID)

		keys, err = store.SelectByDigest(ctx, strings.Repeat("0", 64))
		require.NoError(t, err)
		assert.Empty(t, keys)
	})

	t.Run("an update keeps the id and the digest", func(t *testing.T) {
		changed := *second
		changed.Name = "renamed"
		changed.ID = "" // a key rebuilt without its id is still updated, not inserted
		changed.Digest = strings.Repeat("0", 64)
		_, err := store.Update(ctx, &changed)
		require.NoError(t, err)

		exists, key, err := store.SelectExistsByID(ctx, second.ID)
		require.NoError(t, err)
		require.True(t, exists)
		assert.Equal(t, "renamed", key.Name)
		assert.Equal(t, digest, key.Digest)
	})

	t.Run("an update of a key that is not stored reports it missing and stores nothing", func(t *testing.T) {
		otherPublicKey, _ := realPublicKey(t)
		missing := newKey("never-stored", "engine-1")
		missing.PublicKey = otherPublicKey
		_, err := store.Update(ctx, missing)
		require.ErrorIs(t, err, gorm.ErrRecordNotFound)

		keys, err := store.SelectByKeyID(ctx, "never-stored")
		require.NoError(t, err)
		assert.Empty(t, keys)
	})
}

// realPublicKey returns the public key of a fresh key pair as the KMS stores it, and its digest.
func realPublicKey(t *testing.T) (string, string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	spki, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	require.NoError(t, err)
	digest, err := helpers.PublicKeyDigest(&priv.PublicKey)
	require.NoError(t, err)
	return base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: spki})), digest
}
