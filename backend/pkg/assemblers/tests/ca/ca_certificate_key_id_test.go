package ca

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"testing"
	"time"

	chelpers "github.com/lamassuiot/lamassuiot/v4/core/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/services"
	"github.com/stretchr/testify/require"
)

// kmsKeyIDOf is how every crypto engine names a key: the hex SHA-256 of its DER SubjectPublicKeyInfo.
func kmsKeyIDOf(t *testing.T, pub crypto.PublicKey) string {
	t.Helper()
	spki, err := x509.MarshalPKIXPublicKey(pub)
	require.NoError(t, err)
	digest := sha256.Sum256(spki)
	return hex.EncodeToString(digest[:])
}

// selfSignedCAWithForeignSKI returns a CA certificate whose SKI is not the digest of its key, as
// most CAs issued outside Lamassu have (RFC 5280 method 1 uses SHA-1).
func selfSignedCAWithForeignSKI(t *testing.T, cn string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		SubjectKeyId:          []byte{0xca, 0xfe, 0xba, 0xbe},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert, key
}

func TestCertificatesRecordTheirKMSKey(t *testing.T) {
	require.NoError(t, serverTest.BeforeEach())
	ctx := context.Background()
	caSDK := serverTest.CA.HttpCASDK
	caSvc := serverTest.CA.Service

	profile, err := caSDK.CreateIssuanceProfile(ctx, services.CreateIssuanceProfileInput{
		Profile: models.IssuanceProfile{Validity: models.Validity{Type: models.Duration, Duration: models.TimeDuration(time.Hour)}},
	})
	require.NoError(t, err)

	// requireStoredKeyID checks both the API response and what was stored.
	requireStoredKeyID := func(t *testing.T, want string, got *models.Certificate) {
		t.Helper()
		require.Equal(t, want, got.KeyID)
		stored, err := caSvc.GetCertificateBySerialNumber(ctx, services.GetCertificatesBySerialNumberInput{SerialNumber: got.SerialNumber})
		require.NoError(t, err)
		require.Equal(t, want, stored.KeyID)
	}

	t.Run("CA created with a generated key", func(t *testing.T) {
		ca, err := caSDK.CreateCA(ctx, services.CreateCAInput{
			KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.ECDSA), Bits: 256},
			Subject:      models.Subject{CommonName: "key-id-created-ca"},
			CAExpiration: models.Validity{Type: models.Duration, Duration: models.TimeDuration(24 * time.Hour)},
			ProfileID:    profile.ID,
		})
		require.NoError(t, err)
		requireStoredKeyID(t, kmsKeyIDOf(t, ca.Certificate.Certificate.PublicKey), &ca.Certificate)
	})

	t.Run("CA imported with its key", func(t *testing.T) {
		cert, key := selfSignedCAWithForeignSKI(t, "key-id-imported-with-key")
		ca, err := caSDK.ImportCA(ctx, services.ImportCAInput{ProfileID: profile.ID, Key: key, CACertificate: (*models.X509Certificate)(cert)})
		require.NoError(t, err)
		requireStoredKeyID(t, kmsKeyIDOf(t, &key.PublicKey), &ca.Certificate)
	})

	t.Run("CA imported without a key the KMS holds", func(t *testing.T) {
		cert, _ := selfSignedCAWithForeignSKI(t, "key-id-imported-without-key")
		ca, err := caSDK.ImportCA(ctx, services.ImportCAInput{CACertificate: (*models.X509Certificate)(cert)})
		require.NoError(t, err)
		requireStoredKeyID(t, "", &ca.Certificate)
	})

	issuer, err := caSDK.CreateCA(ctx, services.CreateCAInput{
		KeyMetadata:  models.KeyMetadata{Type: models.KeyType(x509.ECDSA), Bits: 256},
		Subject:      models.Subject{CommonName: "key-id-issuer"},
		CAExpiration: models.Validity{Type: models.Duration, Duration: models.TimeDuration(24 * time.Hour)},
		ProfileID:    profile.ID,
	})
	require.NoError(t, err)

	t.Run("certificate issued with a generated key", func(t *testing.T) {
		cert, err := caSDK.CreateCertificate(ctx, services.CreateCertificateInput{
			CAID:    issuer.ID,
			KeySpec: services.CertificateKeySpec{Type: models.KeyType(x509.ECDSA), Bits: 256},
			Subject: models.Subject{CommonName: "key-id-generated-leaf"},
		})
		require.NoError(t, err)
		requireStoredKeyID(t, kmsKeyIDOf(t, cert.Certificate.PublicKey), cert)
	})

	t.Run("certificate signed for a key outside the KMS", func(t *testing.T) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		csr, err := chelpers.GenerateCertificateRequest(models.Subject{CommonName: "key-id-external-leaf"}, key)
		require.NoError(t, err)
		cert, err := caSDK.SignCertificate(ctx, services.SignCertificateInput{
			CAID: issuer.ID, CertRequest: (*models.X509CertificateRequest)(csr), IssuanceProfileID: profile.ID,
		})
		require.NoError(t, err)
		requireStoredKeyID(t, "", cert)
	})
}
