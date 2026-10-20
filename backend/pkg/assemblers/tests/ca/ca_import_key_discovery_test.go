package ca

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"testing"
	"time"

	chelpers "github.com/lamassuiot/lamassuiot/v4/core/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/services"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Importing a CA without its key links it, on a best-effort basis, to the private key held by any
// crypto engine: the requested engine is only a preference.
func TestImportCAWithoutKeyDiscoversKeyInAnyEngine(t *testing.T) {
	ctx := context.Background()

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

	// importCA imports a new CA without its key, after storing that key in the given engines.
	importCA := func(t *testing.T, preferredEngine string, keyEngines ...string) *models.CACertificate {
		t.Helper()
		require.NoError(t, serverTest.BeforeEach())
		profile, err := serverTest.CA.Service.CreateIssuanceProfile(ctx, services.CreateIssuanceProfileInput{
			Profile: models.IssuanceProfile{Validity: models.Validity{Type: models.Duration, Duration: models.TimeDuration(time.Hour)}},
		})
		require.NoError(t, err)

		caCert, caKey, err := chelpers.GenerateSelfSignedCA(x509.RSA, time.Hour*24, "KeyDiscoveryCA")
		require.NoError(t, err)
		for _, engine := range keyEngines {
			_, err := serverTest.KMS.Service.ImportKey(ctx, services.ImportKeyInput{PrivateKey: caKey.(*rsa.PrivateKey), EngineID: engine, Name: "ca key"})
			require.NoError(t, err)
		}

		ca, err := serverTest.CA.Service.ImportCA(ctx, services.ImportCAInput{
			CACertificate: (*models.X509Certificate)(caCert),
			ProfileID:     profile.ID,
			EngineID:      preferredEngine,
		})
		require.NoError(t, err)
		return ca
	}

	t.Run("KeyOnlyInAnotherEngine", func(t *testing.T) {
		ca := importCA(t, defaultEngine, otherEngine)

		assert.Equal(t, models.CertificateTypeManaged, ca.Certificate.Type)
		assert.Equal(t, otherEngine, ca.Certificate.EngineID)
		assertCACanSign(t, serverTest.CA, ca)
	})

	t.Run("PreferredEngineWins", func(t *testing.T) {
		ca := importCA(t, otherEngine, defaultEngine, otherEngine)

		assert.Equal(t, otherEngine, ca.Certificate.EngineID)
		assertCACanSign(t, serverTest.CA, ca)
	})

	t.Run("DefaultEngineWithoutPreference", func(t *testing.T) {
		ca := importCA(t, "", otherEngine, defaultEngine)

		assert.Equal(t, defaultEngine, ca.Certificate.EngineID)
		assertCACanSign(t, serverTest.CA, ca)
	})

	t.Run("KeyInNoEngine", func(t *testing.T) {
		ca := importCA(t, defaultEngine)

		assert.Equal(t, models.CertificateTypeImportedWithoutKey, ca.Certificate.Type)
		assert.Empty(t, ca.Certificate.EngineID)
	})
}
