package ca

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/services"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A CA created on a key held by several engines is bound to the copy of the requested engine only:
// binding another copy would keep it from being deleted while nothing uses it.
func TestCreateCABindsTheKeyCopyOfItsEngine(t *testing.T) {
	require.NoError(t, serverTest.BeforeEach())
	ctx := context.Background()
	caTest := serverTest.CA

	engines, err := serverTest.KMS.Service.GetCryptoEngineProvider(ctx)
	require.NoError(t, err)
	require.Len(t, engines, 2, "the test needs the default engine and another one")
	var defaultEngine, otherEngine string
	for _, engine := range engines {
		if engine.Default {
			defaultEngine = engine.ID
		} else {
			otherEngine = engine.ID
		}
	}

	profile, err := caTest.Service.CreateIssuanceProfile(ctx, services.CreateIssuanceProfileInput{
		Profile: models.IssuanceProfile{Validity: models.Validity{Type: models.Duration, Duration: models.TimeDuration(time.Hour)}},
	})
	require.NoError(t, err)
	signer, err := caTest.Service.CreateCA(ctx, services.CreateCAInput{
		KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
		Subject:      models.Subject{CommonName: "KeyEngineSigner"},
		CAExpiration: models.Validity{Type: models.Duration, Duration: models.TimeDuration(time.Hour * 24)},
		ProfileID:    profile.ID,
	})
	require.NoError(t, err)

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	for _, engine := range []string{defaultEngine, otherEngine} {
		_, err := serverTest.KMS.Service.ImportKey(ctx, services.ImportKeyInput{PrivateKey: priv, EngineID: engine, Name: "shared key"})
		require.NoError(t, err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	require.NoError(t, err)
	digest := sha256.Sum256(spki)
	keyID := hex.EncodeToString(digest[:])

	ca, err := caTest.Service.CreateCA(ctx, services.CreateCAInput{
		ParentID:     signer.ID,
		EngineID:     otherEngine,
		KeyMetadata:  models.KeyMetadata{KeyID: keyID},
		Subject:      models.Subject{CommonName: "KeyEngineCA"},
		CAExpiration: models.Validity{Type: models.Duration, Duration: models.TimeDuration(time.Hour * 12)},
		ProfileID:    profile.ID,
	})
	require.NoError(t, err)
	assert.Equal(t, otherEngine, ca.Certificate.EngineID)

	bindings := func(engine string) []models.KMSBindResource {
		key, err := serverTest.KMS.Service.GetKey(ctx, services.GetKeyInput{Identifier: fmt.Sprintf("pkcs11:token-id=%s;id=%s;type=private", engine, keyID)})
		require.NoError(t, err)
		bound, err := key.BoundResources()
		require.NoError(t, err)
		return bound
	}
	assert.Equal(t, []models.KMSBindResource{{ResourceType: models.KMSBindResourceTypeCertificate, ResourceID: ca.Certificate.SerialNumber}}, bindings(otherEngine))
	assert.Empty(t, bindings(defaultEngine), "the copy of the default engine is not used")
}
