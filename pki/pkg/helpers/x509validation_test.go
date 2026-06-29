package helpers

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	chelpers "github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
)

func TestValidateCertificate(t *testing.T) {
	// Load the CA certificate
	caCertFilePath := "testdata/cacertificate.pem"
	caCert, err := chelpers.ReadCertificateFromFile(caCertFilePath)
	if err != nil {
		t.Fatalf("Failed to read CA certificate from file: %v", err)
	}

	// Load the certificate to be validated
	certFilePath := "testdata/samecaeccertificate.pem"
	cert, err := chelpers.ReadCertificateFromFile(certFilePath)
	if err != nil {
		t.Fatalf("Failed to read certificate from file: %v", err)
	}

	// Call the ValidateCertificate function
	err = ValidateCertificate(caCert, cert, false)

	// Check if an error occurred during validation
	if err != nil {
		t.Errorf("Certificate validation failed: %v", err)
	}

	// Load the certificate to be validated
	certFilePath = "testdata/noncacert.pem"
	cert, err = chelpers.ReadCertificateFromFile(certFilePath)
	if err != nil {
		t.Fatalf("Failed to read certificate from file: %v", err)
	}

	// Call the ValidateCertificate function
	err = ValidateCertificate(caCert, cert, false)

	// Check if an error occurred during validation
	if err == nil {
		t.Errorf("Certificate validation should have failed")
	}

}

// generateTestCA creates an in-memory ECDSA CA and returns the cert and key.
func generateTestCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	ca, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return ca, key
}

// generateLeafCert issues a leaf certificate from the given CA with the provided NotBefore/NotAfter.
func generateLeafCert(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, notBefore, notAfter time.Time) *x509.Certificate {
	t.Helper()
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkixNameWithCN("test-device"),
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &leafKey.PublicKey, caKey)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

// TestValidateCertificates_FutureDated verifies that a certificate whose NotBefore is in the
// future is always rejected, regardless of the considerExpiration flag.
// This guards against the vulnerability where setting considerExpiration=false (i.e. AllowExpired)
// pinned opts.CurrentTime to NotBefore, inadvertently validating future-dated certificates.
func TestValidateCertificates_FutureDated(t *testing.T) {
	ca, caKey := generateTestCA(t)

	futureCert := generateLeafCert(t, ca, caKey,
		time.Now().Add(365*24*time.Hour),   // NotBefore: 1 year in the future
		time.Now().Add(2*365*24*time.Hour), // NotAfter:  2 years in the future
	)

	// considerExpiration=false simulates the AllowExpired enrollment path — must still reject.
	err := ValidateCertificate(ca, futureCert, false)
	assert.Error(t, err, "future-dated certificate must be rejected when considerExpiration=false")
	assert.Contains(t, err.Error(), "not yet valid")

	// considerExpiration=true — must also reject (regression guard).
	err = ValidateCertificate(ca, futureCert, true)
	assert.Error(t, err, "future-dated certificate must be rejected when considerExpiration=true")
}
