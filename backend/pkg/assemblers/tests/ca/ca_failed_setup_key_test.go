package ca

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"testing"
	"time"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/errs"
	chelpers "github.com/lamassuiot/lamassuiot/v4/core/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/services"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A CA that fails to be stored leaves neither a key created for it nor a binding to it behind.
func TestFailedCASetupLeavesNoKeyOrBinding(t *testing.T) {
	ctx := context.Background()
	caTest := serverTest.CA
	kms := serverTest.KMS.Service

	newProfile := func(t *testing.T) string {
		require.NoError(t, serverTest.BeforeEach())
		profile, err := caTest.Service.CreateIssuanceProfile(ctx, services.CreateIssuanceProfileInput{
			Profile: models.IssuanceProfile{Validity: models.Validity{Type: models.Duration, Duration: models.TimeDuration(time.Hour)}},
		})
		require.NoError(t, err)
		return profile.ID
	}
	newCert := func(t *testing.T, cn string) (*x509.Certificate, *rsa.PrivateKey) {
		cert, key, err := chelpers.GenerateSelfSignedCA(x509.RSA, time.Hour*24, cn)
		require.NoError(t, err)
		return cert, key.(*rsa.PrivateKey)
	}
	keysOf := func(t *testing.T, cert *x509.Certificate) []*models.Key {
		keys, err := kms.GetKeysByPublicKey(ctx, services.GetKeysByPublicKeyInput{PublicKey: cert.PublicKey})
		require.NoError(t, err)
		return keys
	}

	// Importing the same certificate again under the same ID fails when storing it.
	t.Run("ImportCAWithKey", func(t *testing.T) {
		profileID := newProfile(t)
		cert, key := newCert(t, "Imported Twice")
		_, err := caTest.Service.ImportCA(ctx, services.ImportCAInput{ID: "imported-twice", CACertificate: (*models.X509Certificate)(cert), ProfileID: profileID})
		require.NoError(t, err)

		_, err = caTest.Service.ImportCA(ctx, services.ImportCAInput{ID: "imported-twice", CACertificate: (*models.X509Certificate)(cert), Key: key, ProfileID: profileID})
		require.Error(t, err)

		assert.Empty(t, keysOf(t, cert), "the key imported for the failed CA is deleted")
	})

	t.Run("ImportCAWithDiscoveredKey", func(t *testing.T) {
		profileID := newProfile(t)
		cert, key := newCert(t, "Imported Twice")
		_, err := caTest.Service.ImportCA(ctx, services.ImportCAInput{ID: "imported-twice", CACertificate: (*models.X509Certificate)(cert), ProfileID: profileID})
		require.NoError(t, err)
		_, err = kms.ImportKey(ctx, services.ImportKeyInput{PrivateKey: key, Name: "already in the KMS"})
		require.NoError(t, err)

		_, err = caTest.Service.ImportCA(ctx, services.ImportCAInput{ID: "imported-twice", CACertificate: (*models.X509Certificate)(cert), ProfileID: profileID})
		require.Error(t, err)

		keys := keysOf(t, cert)
		require.Len(t, keys, 1, "a key that was already in the KMS is kept")
		bound, err := keys[0].BoundResources()
		require.NoError(t, err)
		assert.Empty(t, bound, "nor is it bound to the CA that was not stored")
	})

	t.Run("CreateCA", func(t *testing.T) {
		profileID := newProfile(t)
		before, err := kms.GetKeyStats(ctx, services.GetKeyStatsInput{})
		require.NoError(t, err)

		_, err = caTest.Service.CreateCA(ctx, services.CreateCAInput{
			ParentID:     "missing-parent",
			KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
			Subject:      models.Subject{CommonName: "Orphan"},
			CAExpiration: models.Validity{Type: models.Duration, Duration: models.TimeDuration(time.Hour * 12)},
			ProfileID:    profileID,
		})
		require.ErrorIs(t, err, errs.ErrCANotFound)

		after, err := kms.GetKeyStats(ctx, services.GetKeyStatsInput{})
		require.NoError(t, err)
		assert.Equal(t, before.TotalKeys, after.TotalKeys, "the key created for the failed CA is deleted")
	})
}
