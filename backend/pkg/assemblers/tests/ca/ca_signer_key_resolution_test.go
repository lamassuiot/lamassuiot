package ca

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"testing"
	"time"

	backendservices "github.com/lamassuiot/lamassuiot/v4/backend/pkg/services"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/errs"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/services"
	"github.com/stretchr/testify/require"
)

// signWith signs a fixed message with the certificate signer, as the CA does to issue a certificate.
func signWith(t *testing.T, cert *models.Certificate) ([]byte, []byte, error) {
	t.Helper()
	digest := sha256.Sum256([]byte("message signed by the CA"))
	signer := backendservices.NewCertificateSigner(context.Background(), cert, serverTest.KMS.Service)
	signature, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	return digest[:], signature, err
}

func TestCertificateSignerResolvesTheCertificateKey(t *testing.T) {
	require.NoError(t, serverTest.BeforeEach())
	ctx := context.Background()

	// A CA certificate whose SKI is not the digest of its key, with the key in filesystem-1.
	x509Cert, key := selfSignedCAWithForeignSKI(t, "signer-foreign-ski")
	_, err := serverTest.KMS.Service.ImportKey(ctx, services.ImportKeyInput{PrivateKey: key, EngineID: "filesystem-1", Name: "signer-foreign-ski"})
	require.NoError(t, err)
	keyID := kmsKeyIDOf(t, &key.PublicKey)

	t.Run("certificate with key_id signs with that key", func(t *testing.T) {
		digest, signature, err := signWith(t, &models.Certificate{Certificate: (*models.X509Certificate)(x509Cert), EngineID: "filesystem-1", KeyID: keyID})
		require.NoError(t, err)
		require.True(t, ecdsa.VerifyASN1(&key.PublicKey, digest, signature))
	})

	t.Run("certificate stored before key_id existed falls back to its public key", func(t *testing.T) {
		digest, signature, err := signWith(t, &models.Certificate{Certificate: (*models.X509Certificate)(x509Cert), EngineID: "filesystem-1"})
		require.NoError(t, err)
		require.True(t, ecdsa.VerifyASN1(&key.PublicKey, digest, signature))
	})

	t.Run("key_id in an engine that does not hold it is not found", func(t *testing.T) {
		_, _, err := signWith(t, &models.Certificate{Certificate: (*models.X509Certificate)(x509Cert), EngineID: "vault-1", KeyID: keyID})
		require.ErrorIs(t, err, errs.ErrKeyNotFound)
	})

	t.Run("key outside the KMS is not found", func(t *testing.T) {
		outside, _ := selfSignedCAWithForeignSKI(t, "signer-outside")
		_, _, err := signWith(t, &models.Certificate{Certificate: (*models.X509Certificate)(outside), EngineID: "filesystem-1"})
		require.ErrorIs(t, err, errs.ErrKeyNotFound)
	})

	// From here on vault-1 holds a copy of the same key.
	_, err = serverTest.KMS.Service.ImportKey(ctx, services.ImportKeyInput{PrivateKey: key, EngineID: "vault-1", Name: "signer-foreign-ski copy"})
	require.NoError(t, err)

	t.Run("a copy in another engine does not stop the certificate from signing", func(t *testing.T) {
		for _, cert := range map[string]*models.Certificate{
			"with key_id": {Certificate: (*models.X509Certificate)(x509Cert), EngineID: "filesystem-1", KeyID: keyID},
			"legacy":      {Certificate: (*models.X509Certificate)(x509Cert), EngineID: "filesystem-1"},
		} {
			digest, signature, err := signWith(t, cert)
			require.NoError(t, err)
			require.True(t, ecdsa.VerifyASN1(&key.PublicKey, digest, signature))
		}
	})

	t.Run("without engine, a key held by several engines is ambiguous", func(t *testing.T) {
		_, _, err := signWith(t, &models.Certificate{Certificate: (*models.X509Certificate)(x509Cert)})
		require.ErrorIs(t, err, errs.ErrKeyEngineRequired)
	})
}

func TestCAImportedWithAForeignSKIIssuesCertificates(t *testing.T) {
	require.NoError(t, serverTest.BeforeEach())
	ctx := context.Background()
	caSDK := serverTest.CA.HttpCASDK

	profile, err := caSDK.CreateIssuanceProfile(ctx, services.CreateIssuanceProfileInput{
		Profile: models.IssuanceProfile{Validity: models.Validity{Type: models.Duration, Duration: models.TimeDuration(time.Hour)}},
	})
	require.NoError(t, err)

	caCert, caKey := selfSignedCAWithForeignSKI(t, "issuing-foreign-ski")
	ca, err := caSDK.ImportCA(ctx, services.ImportCAInput{ProfileID: profile.ID, Key: caKey, CACertificate: (*models.X509Certificate)(caCert)})
	require.NoError(t, err)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, leafKey)
	require.NoError(t, err)
	csr, err := x509.ParseCertificateRequest(csrDER)
	require.NoError(t, err)

	leaf, err := caSDK.SignCertificate(ctx, services.SignCertificateInput{
		CAID: ca.ID, CertRequest: (*models.X509CertificateRequest)(csr), IssuanceProfileID: profile.ID,
	})
	require.NoError(t, err)
	require.NoError(t, (*x509.Certificate)(leaf.Certificate).CheckSignatureFrom(caCert))
}
