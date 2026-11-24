package kms

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/errs"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/services"
	"github.com/stretchr/testify/require"
)

// A key is found by its id, by the digest of its public key or by an alias, and an alias can never be written in
// the form of an id or a digest, which are read as such before any alias is consulted.
func TestKeyIdentifiers(t *testing.T) {
	kmsTest, err := StartKMSServiceTestServer(t)
	require.NoError(t, err)
	ctx := context.Background()

	// the same key pair in two engines, and an unrelated key with an alias
	held, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	copies := map[string]*models.Key{}
	for _, engineID := range []string{"filesystem-1", "vault-1"} {
		key, err := kmsTest.Service.ImportKey(ctx, services.ImportKeyInput{PrivateKey: held, EngineID: engineID, Name: "identifiers " + engineID})
		require.NoError(t, err)
		copies[engineID] = key
	}
	wantDigest := keyIDOf(t, &held.PublicKey)

	single, err := kmsTest.Service.CreateKey(ctx, services.CreateKeyInput{Name: "single", Algorithm: "ECDSA", Size: 256, EngineID: "filesystem-1"})
	require.NoError(t, err)
	_, err = kmsTest.Service.UpdateKeyAliases(ctx, services.UpdateKeyAliasesInput{
		ID:      single.PKCS11URI,
		Patches: []models.PatchOperation{{Op: models.PatchAdd, Path: "/-", Value: "single-alias"}},
	})
	require.NoError(t, err)

	t.Run("a stored key has an id and the digest of its public key", func(t *testing.T) {
		for engineID, key := range copies {
			require.True(t, helpers.IsKeyUUID(key.ID), "%s: id %q is not a UUID", engineID, key.ID)
			require.Equal(t, wantDigest, key.Digest)
		}
		require.NotEqual(t, copies["filesystem-1"].ID, copies["vault-1"].ID, "each copy has its own id")
		require.True(t, helpers.IsKeyUUID(single.ID))
		require.Equal(t, single.KeyID, single.Digest, "a key created by the KMS is named by its digest")
	})

	// The HTTP client must honour the same contract as the service it calls.
	for name, svc := range map[string]services.KMSService{"service": kmsTest.Service, "http": kmsTest.HttpKMSSDK} {
		t.Run(name, func(t *testing.T) {
			get := func(identifier string) (*models.Key, error) {
				return svc.GetKey(ctx, services.GetKeyInput{Identifier: identifier})
			}

			t.Run("by id", func(t *testing.T) {
				key, err := get(copies["vault-1"].ID)
				require.NoError(t, err)
				require.Equal(t, "vault-1", key.EngineID, "the id picks one copy")
				require.Equal(t, copies["vault-1"].ID, key.ID)
			})

			t.Run("by id in uppercase", func(t *testing.T) {
				key, err := get(strings.ToUpper(single.ID))
				require.NoError(t, err)
				require.Equal(t, single.ID, key.ID)
			})

			t.Run("by digest", func(t *testing.T) {
				key, err := get(single.Digest)
				require.NoError(t, err)
				require.Equal(t, single.ID, key.ID)
			})

			t.Run("by alias", func(t *testing.T) {
				key, err := get("single-alias")
				require.NoError(t, err)
				require.Equal(t, single.ID, key.ID)
			})

			t.Run("a digest held by two engines needs the engine", func(t *testing.T) {
				_, err := get(wantDigest)
				require.ErrorIs(t, err, errs.ErrKeyEngineRequired)
			})

			t.Run("an id or a digest of no key is not found", func(t *testing.T) {
				_, err := get("0190a6c4-7f3e-7b2a-9c1d-3e5f6a7b8c99")
				require.ErrorIs(t, err, errs.ErrKeyNotFound)
				_, err = get(strings.Repeat("0", 64))
				require.ErrorIs(t, err, errs.ErrKeyNotFound)
			})

			t.Run("an alias shaped like an id, a digest or a pkcs11 URI is refused", func(t *testing.T) {
				for _, alias := range []string{
					"0190a6c4-7f3e-7b2a-9c1d-3e5f6a7b8c77",
					strings.ToUpper("0190a6c4-7f3e-7b2a-9c1d-3e5f6a7b8c77"),
					strings.Repeat("5", 64),
					strings.Repeat("A", 64),
					"pkcs11:token-id=filesystem-1;id=x;type=private",
				} {
					_, err := svc.UpdateKeyAliases(ctx, services.UpdateKeyAliasesInput{
						ID:      single.ID,
						Patches: []models.PatchOperation{{Op: models.PatchAdd, Path: "/-", Value: alias}},
					})
					require.ErrorIs(t, err, errs.ErrKeyAliasReservedFormat, "alias %q", alias)
				}

				key, err := get(single.ID)
				require.NoError(t, err)
				require.Equal(t, []string{"single-alias"}, key.Aliases, "a refused alias is not stored")
			})
		})
	}
}
