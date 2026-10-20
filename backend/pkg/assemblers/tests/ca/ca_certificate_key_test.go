package ca

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"testing"
	"time"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/errs"
	chelpers "github.com/lamassuiot/lamassuiot/v4/core/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/services"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetCertificateKey(t *testing.T) {
	require.NoError(t, serverTest.BeforeEach())
	caTest := serverTest.CA
	caSDK := caTest.HttpCASDK
	ctx := context.Background()

	profile, err := caTest.Service.CreateIssuanceProfile(ctx, services.CreateIssuanceProfileInput{
		Profile: models.IssuanceProfile{
			Validity: models.Validity{Type: models.Duration, Duration: models.TimeDuration(time.Hour)},
		},
	})
	require.NoError(t, err)

	// The KMS key ID is the hex SHA-256 of the DER SubjectPublicKeyInfo.
	kmsKeyID := func(cert *models.X509Certificate) string {
		spki, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
		require.NoError(t, err)
		digest := sha256.Sum256(spki)
		return hex.EncodeToString(digest[:])
	}

	t.Run("ManagedCA", func(t *testing.T) {
		ca, err := caTest.Service.CreateCA(ctx, services.CreateCAInput{
			KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
			Subject:      models.Subject{CommonName: "CertificateKeyManagedCA"},
			CAExpiration: models.Validity{Type: models.Duration, Duration: models.TimeDuration(time.Hour * 24)},
			ProfileID:    profile.ID,
		})
		require.NoError(t, err)

		key, err := caSDK.GetCertificateKey(ctx, services.GetCertificateKeyInput{SerialNumber: ca.Certificate.SerialNumber})
		require.NoError(t, err)
		assert.Equal(t, kmsKeyID(ca.Certificate.Certificate), key.KeyID)
		assert.Equal(t, ca.Certificate.SubjectKeyID, key.KeyID, "Lamassu writes the KMS key ID as the SKI")
		assert.Equal(t, ca.Certificate.EngineID, key.EngineID)
		assert.True(t, key.HasPrivateKey)
	})

	// Imported certificates keep the SKI their issuer wrote, here a UUID, so it cannot find the key.
	t.Run("ImportedCAWithForeignSKI", func(t *testing.T) {
		caCert, caKey, err := chelpers.GenerateSelfSignedCA(x509.RSA, time.Hour*24, "CertificateKeyImportedCA")
		require.NoError(t, err)
		ca, err := caTest.Service.ImportCA(ctx, services.ImportCAInput{
			CACertificate: (*models.X509Certificate)(caCert),
			ProfileID:     profile.ID,
			Key:           caKey.(*rsa.PrivateKey),
		})
		require.NoError(t, err)
		require.NotEqual(t, kmsKeyID(ca.Certificate.Certificate), hex.EncodeToString(caCert.SubjectKeyId))

		key, err := caSDK.GetCertificateKey(ctx, services.GetCertificateKeyInput{SerialNumber: ca.Certificate.SerialNumber})
		require.NoError(t, err)
		assert.Equal(t, kmsKeyID(ca.Certificate.Certificate), key.KeyID)
		assert.Equal(t, ca.Certificate.EngineID, key.EngineID)
		assert.True(t, key.HasPrivateKey)
	})

	t.Run("ImportedCAWithoutKey", func(t *testing.T) {
		caCert, _, err := chelpers.GenerateSelfSignedCA(x509.RSA, time.Hour*24, "CertificateKeyExternalCA")
		require.NoError(t, err)
		ca, err := caTest.Service.ImportCA(ctx, services.ImportCAInput{
			CACertificate: (*models.X509Certificate)(caCert),
			ProfileID:     profile.ID,
		})
		require.NoError(t, err)

		_, err = caSDK.GetCertificateKey(ctx, services.GetCertificateKeyInput{SerialNumber: ca.Certificate.SerialNumber})
		assert.ErrorIs(t, err, errs.ErrKeyNotFound)
	})

	t.Run("CertificateWithKeyOutsideKMS", func(t *testing.T) {
		ca, err := caTest.Service.CreateCA(ctx, services.CreateCAInput{
			KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
			Subject:      models.Subject{CommonName: "CertificateKeyIssuerCA"},
			CAExpiration: models.Validity{Type: models.Duration, Duration: models.TimeDuration(time.Hour * 24)},
			ProfileID:    profile.ID,
		})
		require.NoError(t, err)

		leafKey, err := chelpers.GenerateRSAKey(2048)
		require.NoError(t, err)
		csr, err := chelpers.GenerateCertificateRequest(models.Subject{CommonName: "certificate-key-leaf"}, leafKey)
		require.NoError(t, err)
		leaf, err := caTest.Service.SignCertificate(ctx, services.SignCertificateInput{
			CAID:              ca.ID,
			CertRequest:       (*models.X509CertificateRequest)(csr),
			IssuanceProfileID: profile.ID,
		})
		require.NoError(t, err)

		_, err = caSDK.GetCertificateKey(ctx, services.GetCertificateKeyInput{SerialNumber: leaf.SerialNumber})
		assert.ErrorIs(t, err, errs.ErrKeyNotFound)
	})

	t.Run("UnknownCertificate", func(t *testing.T) {
		_, err := caSDK.GetCertificateKey(ctx, services.GetCertificateKeyInput{SerialNumber: "00-11-22"})
		assert.ErrorIs(t, err, errs.ErrCertificateNotFound)
	})
}

// A certificate whose key Lamassu generates is bound to that key until the certificate is deleted.
func TestCertificateKeyBindingFollowsCertificate(t *testing.T) {
	require.NoError(t, serverTest.BeforeEach())
	caTest := serverTest.CA
	ctx := context.Background()

	profile, err := caTest.Service.CreateIssuanceProfile(ctx, services.CreateIssuanceProfileInput{
		Profile: models.IssuanceProfile{
			Validity: models.Validity{Type: models.Duration, Duration: models.TimeDuration(time.Hour)},
		},
	})
	require.NoError(t, err)
	ca, err := caTest.Service.CreateCA(ctx, services.CreateCAInput{
		KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.RSA), Bits: 2048},
		Subject:      models.Subject{CommonName: "CertificateKeyBindingCA"},
		CAExpiration: models.Validity{Type: models.Duration, Duration: models.TimeDuration(time.Hour * 24)},
		ProfileID:    profile.ID,
	})
	require.NoError(t, err)

	cert, err := caTest.Service.CreateCertificate(ctx, services.CreateCertificateInput{
		CAID:    ca.ID,
		KeySpec: services.CertificateKeySpec{Type: models.KeyType(x509.RSA), Bits: 2048},
		Subject: models.Subject{CommonName: "certificate-key-binding-leaf"},
	})
	require.NoError(t, err)

	key, err := caTest.HttpCASDK.GetCertificateKey(ctx, services.GetCertificateKeyInput{SerialNumber: cert.SerialNumber})
	require.NoError(t, err)
	binding := models.KMSBindResource{ResourceType: models.KMSBindResourceTypeCertificate, ResourceID: cert.SerialNumber}
	bound, err := key.BoundResources()
	require.NoError(t, err)
	assert.Equal(t, []models.KMSBindResource{binding}, bound)

	// A certificate can only be deleted once its issuer CA is gone.
	revokeAndDeleteCA(t, caTest, ca.ID, false)
	require.NoError(t, caTest.Service.DeleteCertificate(ctx, services.DeleteCertificateInput{SerialNumber: cert.SerialNumber}))

	key, err = serverTest.KMS.Service.GetKey(ctx, services.GetKeyInput{Identifier: key.PKCS11URI})
	require.NoError(t, err, "deleting a certificate keeps its key")
	bound, err = key.BoundResources()
	require.NoError(t, err)
	assert.Empty(t, bound)
}
