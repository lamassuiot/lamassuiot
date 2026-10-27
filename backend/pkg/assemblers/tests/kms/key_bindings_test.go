package kms

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/errs"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/services"
	"github.com/stretchr/testify/require"
)

func certificateResource(serial string) models.KMSBindResource {
	return models.KMSBindResource{ResourceType: models.KMSBindResourceTypeCertificate, ResourceID: serial}
}

func boundSerialsOf(t *testing.T, bindings []models.KeyBinding) []string {
	t.Helper()
	serials := []string{}
	for _, b := range bindings {
		serials = append(serials, b.ResourceID)
	}
	return serials
}

func TestKeyBindings(t *testing.T) {
	kmsTest, err := StartKMSServiceTestServer(t)
	require.NoError(t, err)
	ctx := context.Background()

	for name, svc := range map[string]services.KMSService{"service": kmsTest.Service, "http": kmsTest.HttpKMSSDK} {
		t.Run(name, func(t *testing.T) {
			priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			require.NoError(t, err)
			key, err := kmsTest.Service.ImportKey(ctx, services.ImportKeyInput{PrivateKey: priv, EngineID: "filesystem-1", Name: "bindings " + name})
			require.NoError(t, err)
			id := key.PKCS11URI

			bind := func(serial string) (bool, error) {
				return svc.BindKeyResource(ctx, services.KeyResourceBindingInput{Identifier: id, Resource: certificateResource(serial)})
			}
			unbind := func(serial string) (bool, error) {
				return svc.UnbindKeyResource(ctx, services.KeyResourceBindingInput{Identifier: id, Resource: certificateResource(serial)})
			}
			bound := func() []string {
				bindings, err := svc.GetKeyBindings(ctx, services.GetKeyInput{Identifier: id})
				require.NoError(t, err)
				return boundSerialsOf(t, bindings)
			}

			changed, err := bind("aa")
			require.NoError(t, err)
			require.True(t, changed)
			changed, err = bind("aa")
			require.NoError(t, err)
			require.False(t, changed, "binding an already bound resource changes nothing")
			require.Equal(t, []string{"aa"}, bound())

			changed, err = svc.RebindKeyResource(ctx, services.RebindKeyResourceInput{
				Identifier: id, From: certificateResource("aa"), To: certificateResource("bb"),
			})
			require.NoError(t, err)
			require.True(t, changed)
			require.Equal(t, []string{"bb"}, bound())

			changed, err = unbind("bb")
			require.NoError(t, err)
			require.True(t, changed)
			changed, err = unbind("bb")
			require.NoError(t, err)
			require.False(t, changed)
			require.Empty(t, bound())

			_, err = svc.BindKeyResource(ctx, services.KeyResourceBindingInput{Identifier: "pkcs11:token-id=missing-engine;id=missing;type=private", Resource: certificateResource("aa")})
			require.ErrorIs(t, err, errs.ErrKeyNotFound)

			_, err = svc.BindKeyResource(ctx, services.KeyResourceBindingInput{Identifier: id, Resource: models.KMSBindResource{ResourceType: models.KMSBindResourceTypeCertificate}})
			require.ErrorIs(t, err, errs.ErrValidateBadRequest, "a binding names its resource")
		})
	}
}

func TestDeleteKeyInUse(t *testing.T) {
	kmsTest, err := StartKMSServiceTestServer(t)
	require.NoError(t, err)
	ctx := context.Background()

	for name, svc := range map[string]services.KMSService{"service": kmsTest.Service, "http": kmsTest.HttpKMSSDK} {
		t.Run(name, func(t *testing.T) {
			priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			require.NoError(t, err)
			key, err := kmsTest.Service.ImportKey(ctx, services.ImportKeyInput{PrivateKey: priv, EngineID: "filesystem-1", Name: "delete in use " + name})
			require.NoError(t, err)
			id := key.PKCS11URI
			_, err = kmsTest.Service.BindKeyResource(ctx, services.KeyResourceBindingInput{Identifier: id, Resource: certificateResource("in-use")})
			require.NoError(t, err)

			err = svc.DeleteKeyByID(ctx, services.GetKeyInput{Identifier: id})
			require.ErrorIs(t, err, errs.ErrKeyInUse)

			// The engine still holds the key: the certificate using it can still sign.
			digest := sha256.Sum256([]byte("still signing"))
			signature, err := kmsTest.Service.SignMessage(ctx, services.SignMessageInput{
				Identifier: id, Algorithm: "ECDSA_SHA_256", Message: digest[:], MessageType: models.Hashed,
			})
			require.NoError(t, err)
			require.True(t, ecdsa.VerifyASN1(&priv.PublicKey, digest[:], signature.Signature))

			_, err = kmsTest.Service.UnbindKeyResource(ctx, services.KeyResourceBindingInput{Identifier: id, Resource: certificateResource("in-use")})
			require.NoError(t, err)
			require.NoError(t, svc.DeleteKeyByID(ctx, services.GetKeyInput{Identifier: id}))
			_, err = kmsTest.Service.GetKey(ctx, services.GetKeyInput{Identifier: id})
			require.ErrorIs(t, err, errs.ErrKeyNotFound)
		})
	}
}
