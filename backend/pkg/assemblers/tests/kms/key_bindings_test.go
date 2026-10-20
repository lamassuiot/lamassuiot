package kms

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/errs"
	chelpers "github.com/lamassuiot/lamassuiot/v4/core/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/services"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKeyBindings(t *testing.T) {
	kmsTest, err := StartKMSServiceTestServer(t)
	require.NoError(t, err)
	ctx := context.Background()
	kmsSDK := kmsTest.HttpKMSSDK

	importKey := func(t *testing.T) *models.Key {
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		key, err := kmsSDK.ImportKey(ctx, services.ImportKeyInput{
			Name:       "bindings-key",
			PrivateKey: priv,
			EngineID:   "filesystem-1",
			Metadata:   map[string]any{"owner": "test"},
		})
		require.NoError(t, err)
		return key
	}
	bindings := func(t *testing.T, key *models.Key) []models.KMSBindResource {
		bound, err := key.BoundResources()
		require.NoError(t, err)
		return bound
	}

	certA := models.KMSBindResource{ResourceType: models.KMSBindResourceTypeCertificate, ResourceID: "aa-01"}
	certB := models.KMSBindResource{ResourceType: models.KMSBindResourceTypeCertificate, ResourceID: "bb-02"}

	t.Run("BindIsIdempotent", func(t *testing.T) {
		key := importKey(t)

		for _, resource := range []models.KMSBindResource{certA, certA, certB} {
			key, err = kmsSDK.BindKeyResource(ctx, services.KeyResourceBindingInput{Identifier: key.PKCS11URI, Resource: resource})
			require.NoError(t, err)
		}
		assert.ElementsMatch(t, []models.KMSBindResource{certA, certB}, bindings(t, key))

		stored, err := kmsSDK.GetKey(ctx, services.GetKeyInput{Identifier: key.PKCS11URI})
		require.NoError(t, err)
		assert.ElementsMatch(t, []models.KMSBindResource{certA, certB}, bindings(t, stored))
		assert.Equal(t, "test", stored.Metadata["owner"])
	})

	t.Run("UnbindRemovesResource", func(t *testing.T) {
		key := importKey(t)
		for _, resource := range []models.KMSBindResource{certA, certB} {
			_, err = kmsSDK.BindKeyResource(ctx, services.KeyResourceBindingInput{Identifier: key.PKCS11URI, Resource: resource})
			require.NoError(t, err)
		}

		key, err = kmsSDK.UnbindKeyResource(ctx, services.KeyResourceBindingInput{Identifier: key.PKCS11URI, Resource: certA})
		require.NoError(t, err)
		assert.Equal(t, []models.KMSBindResource{certB}, bindings(t, key))

		// Unbinding a resource that is not bound changes nothing.
		key, err = kmsSDK.UnbindKeyResource(ctx, services.KeyResourceBindingInput{Identifier: key.PKCS11URI, Resource: certA})
		require.NoError(t, err)
		assert.Equal(t, []models.KMSBindResource{certB}, bindings(t, key))
	})

	t.Run("BindingUnknownKeyFails", func(t *testing.T) {
		_, err := kmsSDK.BindKeyResource(ctx, services.KeyResourceBindingInput{Identifier: "pkcs11:token-id=filesystem-1;id=unknown;type=private", Resource: certA})
		assert.ErrorIs(t, err, errs.ErrKeyNotFound)
	})

	t.Run("IncompleteResourceIsRejected", func(t *testing.T) {
		key := importKey(t)
		_, err := kmsTest.Service.BindKeyResource(ctx, services.KeyResourceBindingInput{
			Identifier: key.PKCS11URI,
			Resource:   models.KMSBindResource{ResourceType: models.KMSBindResourceTypeCertificate},
		})
		assert.ErrorIs(t, err, errs.ErrValidateBadRequest)
	})

	t.Run("MetadataPatchesCannotChangeBindings", func(t *testing.T) {
		key := importKey(t)
		_, err = kmsSDK.BindKeyResource(ctx, services.KeyResourceBindingInput{Identifier: key.PKCS11URI, Resource: certA})
		require.NoError(t, err)

		bindingsPointer := chelpers.JSONPointerBuilder(models.KMSBindResourceKey)
		for name, patches := range map[string][]models.PatchOperation{
			"Remove":     chelpers.NewPatchBuilder().Remove(bindingsPointer).Build(),
			"Replace":    chelpers.NewPatchBuilder().Replace(bindingsPointer, []models.KMSBindResource{}).Build(),
			"AddElement": chelpers.NewPatchBuilder().Add(chelpers.JSONPointerBuilder(models.KMSBindResourceKey, "-"), certB).Build(),
		} {
			_, err := kmsTest.Service.UpdateKeyMetadata(ctx, services.UpdateKeyMetadataInput{ID: key.PKCS11URI, Patches: patches})
			assert.ErrorIs(t, err, errs.ErrKeyBindingsReadOnly, name)
		}

		// Replacing the whole metadata keeps the bindings.
		key, err = kmsTest.Service.UpdateKeyMetadata(ctx, services.UpdateKeyMetadataInput{
			ID:      key.PKCS11URI,
			Patches: chelpers.NewPatchBuilder().Replace(chelpers.JSONPointerBuilder(), map[string]any{"owner": "other"}).Build(),
		})
		require.NoError(t, err)
		assert.Equal(t, []models.KMSBindResource{certA}, bindings(t, key))
		assert.Equal(t, "other", key.Metadata["owner"])
	})

	t.Run("CreateAndImportCannotSetBindings", func(t *testing.T) {
		forged := map[string]any{models.KMSBindResourceKey: []models.KMSBindResource{certA}}

		_, err := kmsTest.Service.CreateKey(ctx, services.CreateKeyInput{Algorithm: "RSA", Size: 2048, Name: "forged", Metadata: forged})
		assert.ErrorIs(t, err, errs.ErrKeyBindingsReadOnly)

		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		_, err = kmsTest.Service.ImportKey(ctx, services.ImportKeyInput{PrivateKey: priv, Name: "forged", Metadata: forged})
		assert.ErrorIs(t, err, errs.ErrKeyBindingsReadOnly)
	})
}
