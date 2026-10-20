package kms

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/errs"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/services"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetKeysByPublicKey(t *testing.T) {
	kmsTest, err := StartKMSServiceTestServer(t)
	require.NoError(t, err)
	ctx := context.Background()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	imported, err := kmsTest.HttpKMSSDK.ImportKey(ctx, services.ImportKeyInput{
		Name:       "lookup-key",
		PrivateKey: priv,
		EngineID:   "filesystem-1",
	})
	require.NoError(t, err)

	t.Run("FindsKeyByPublicKey", func(t *testing.T) {
		keys, err := kmsTest.HttpKMSSDK.GetKeysByPublicKey(ctx, services.GetKeysByPublicKeyInput{PublicKey: priv.Public()})
		require.NoError(t, err)
		require.Len(t, keys, 1)
		assert.Equal(t, imported.KeyID, keys[0].KeyID)
		assert.Equal(t, imported.EngineID, keys[0].EngineID)
		assert.True(t, keys[0].HasPrivateKey)
	})

	t.Run("FiltersByEngine", func(t *testing.T) {
		keys, err := kmsTest.HttpKMSSDK.GetKeysByPublicKey(ctx, services.GetKeysByPublicKeyInput{PublicKey: priv.Public(), EngineID: "filesystem-1"})
		require.NoError(t, err)
		require.Len(t, keys, 1)
		assert.Equal(t, imported.KeyID, keys[0].KeyID)

		keys, err = kmsTest.HttpKMSSDK.GetKeysByPublicKey(ctx, services.GetKeysByPublicKeyInput{PublicKey: priv.Public(), EngineID: "other-engine"})
		require.NoError(t, err)
		assert.Empty(t, keys)
	})

	t.Run("UnknownKeyReturnsEmptyList", func(t *testing.T) {
		other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		keys, err := kmsTest.HttpKMSSDK.GetKeysByPublicKey(ctx, services.GetKeysByPublicKeyInput{PublicKey: other.Public()})
		require.NoError(t, err)
		assert.Empty(t, keys)
	})

	t.Run("MissingPublicKeyIsRejected", func(t *testing.T) {
		_, err := kmsTest.Service.GetKeysByPublicKey(ctx, services.GetKeysByPublicKeyInput{})
		assert.ErrorIs(t, err, errs.ErrValidateBadRequest)
	})
}
