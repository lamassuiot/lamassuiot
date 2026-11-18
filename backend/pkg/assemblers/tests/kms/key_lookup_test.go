package kms

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"testing"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/errs"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/services"
	"github.com/stretchr/testify/require"
)

// keyIDOf is how every crypto engine names a key: the hex SHA-256 of its DER SubjectPublicKeyInfo.
func keyIDOf(t *testing.T, pub *ecdsa.PublicKey) string {
	t.Helper()
	spki, err := x509.MarshalPKIXPublicKey(pub)
	require.NoError(t, err)
	digest := sha256.Sum256(spki)
	return hex.EncodeToString(digest[:])
}

func engineIDsOf(keys []*models.Key) []string {
	ids := make([]string, 0, len(keys))
	for _, key := range keys {
		ids = append(ids, key.EngineID)
	}
	return ids
}

func TestGetKeysByPublicKey(t *testing.T) {
	kmsTest, err := StartKMSServiceTestServer(t)
	require.NoError(t, err)
	ctx := context.Background()

	// The same key pair held by two engines, as after importing a CA key in a second engine.
	held, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	for _, engineID := range []string{"filesystem-1", "vault-1"} {
		_, err := kmsTest.Service.ImportKey(ctx, services.ImportKeyInput{PrivateKey: held, EngineID: engineID, Name: "lookup " + engineID})
		require.NoError(t, err)
	}
	wantKeyID := keyIDOf(t, &held.PublicKey)

	unrelated, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// The HTTP client must honour the same contract as the service it calls.
	for name, svc := range map[string]services.KMSService{"service": kmsTest.Service, "http": kmsTest.HttpKMSSDK} {
		t.Run(name, func(t *testing.T) {
			t.Run("without engine returns the copy of every engine", func(t *testing.T) {
				keys, err := svc.GetKeysByPublicKey(ctx, services.GetKeysByPublicKeyInput{PublicKey: &held.PublicKey})
				require.NoError(t, err)
				require.ElementsMatch(t, []string{"filesystem-1", "vault-1"}, engineIDsOf(keys))
				for _, key := range keys {
					require.Equal(t, wantKeyID, key.KeyID)
				}
			})

			t.Run("with engine returns only that engine's copy", func(t *testing.T) {
				keys, err := svc.GetKeysByPublicKey(ctx, services.GetKeysByPublicKeyInput{PublicKey: &held.PublicKey, EngineID: "vault-1"})
				require.NoError(t, err)
				require.Len(t, keys, 1)
				require.Equal(t, "vault-1", keys[0].EngineID)
				require.Equal(t, wantKeyID, keys[0].KeyID)
			})

			t.Run("with an engine that does not hold the key returns none", func(t *testing.T) {
				keys, err := svc.GetKeysByPublicKey(ctx, services.GetKeysByPublicKeyInput{PublicKey: &unrelated.PublicKey, EngineID: "vault-1"})
				require.NoError(t, err)
				require.Empty(t, keys)
			})

			t.Run("unknown public key returns none", func(t *testing.T) {
				keys, err := svc.GetKeysByPublicKey(ctx, services.GetKeysByPublicKeyInput{PublicKey: &unrelated.PublicKey})
				require.NoError(t, err)
				require.Empty(t, keys)
			})

			t.Run("missing public key is a bad request", func(t *testing.T) {
				_, err := svc.GetKeysByPublicKey(ctx, services.GetKeysByPublicKeyInput{})
				require.ErrorIs(t, err, errs.ErrValidateBadRequest)
			})
		})
	}
}
