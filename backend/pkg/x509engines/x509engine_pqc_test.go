package x509engines

import (
	"context"
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
	"time"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	software "github.com/lamassuiot/lamassuiot/engines/crypto/software/v3"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// pqcTestEngine returns an X509Engine wired with a VA domain for use in PQC tests.
func pqcTestEngine(t *testing.T) X509Engine {
	t.Helper()
	return NewX509Engine(logrus.NewEntry(logrus.New()), []string{"va.example.com"}, nil)
}

// pqcSoftEngine returns a SoftwareCryptoEngine for PQC key generation in tests.
func pqcSoftEngine(t *testing.T) *software.SoftwareCryptoEngine {
	t.Helper()
	return software.NewSoftwareCryptoEngine(logrus.NewEntry(logrus.New()))
}

// pqcValidity returns a Duration-based Validity for tests.
func pqcValidity(d time.Duration) models.Validity {
	return models.Validity{
		Type:     models.Duration,
		Duration: models.TimeDuration(d),
	}
}

// pqcCAProfile returns a minimal CA issuance profile.
func pqcCAProfile(d time.Duration) models.IssuanceProfile {
	return models.IssuanceProfile{
		Validity:               pqcValidity(d),
		SignAsCA:               true,
		KeyUsage:               models.X509KeyUsage(x509.KeyUsageCertSign | x509.KeyUsageCRLSign),
		HonorSubject:           true,
		HonorExtensions:        true,
		HonorKeyUsage:          false,
		HonorExtendedKeyUsages: true,
	}
}

// pqcLeafProfile returns a minimal leaf issuance profile.
func pqcLeafProfile(d time.Duration) models.IssuanceProfile {
	return models.IssuanceProfile{
		Validity:               pqcValidity(d),
		SignAsCA:               false,
		HonorSubject:           true,
		HonorExtensions:        true,
		HonorKeyUsage:          true,
		HonorExtendedKeyUsages: true,
	}
}

// makeCSR creates a certificate request signed with the given signer.
func makeCSR(t *testing.T, signer crypto.Signer, cn string) *x509.CertificateRequest {
	t.Helper()
	template := x509.CertificateRequest{
		Subject: pkix.Name{CommonName: cn},
	}
	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, signer)
	require.NoError(t, err, "creating CSR for %s", cn)
	csr, err := x509.ParseCertificateRequest(csrBytes)
	require.NoError(t, err, "parsing CSR for %s", cn)
	return csr
}

// --- SLH-DSA tests ---

// TestCreateRootCAWithSLHDSA verifies that CreateRootCA produces a valid,
// self-signed CA certificate when the signing key is SLH-DSA (SHA2-128s).
func TestCreateRootCAWithSLHDSA(t *testing.T) {
	engine := pqcTestEngine(t)
	soft := pqcSoftEngine(t)
	ctx := context.Background()

	// paramSet 1 = SHA2-128s (smallest / fastest for tests)
	keyID, signer, err := soft.CreateSLHDSAPrivateKey(ctx, 1)
	require.NoError(t, err)

	subject := models.Subject{CommonName: "SLH-DSA Test Root CA"}
	cert, err := engine.CreateRootCA(ctx, signer, keyID, subject, pqcValidity(time.Hour), pqcCAProfile(time.Hour))
	require.NoError(t, err)
	require.NotNil(t, cert)

	assert.Equal(t, "SLH-DSA Test Root CA", cert.Subject.CommonName)
	assert.True(t, cert.IsCA)
	assert.True(t, cert.BasicConstraintsValid)
	assert.NotEmpty(t, cert.OCSPServer)
	assert.NotEmpty(t, cert.CRLDistributionPoints)
}

// TestSignCertificateRequestWithSLHDSACA_ECDSALeaf verifies that an SLH-DSA CA
// signs an ECDSA end-entity CSR and produces a certificate with the correct issuer.
func TestSignCertificateRequestWithSLHDSACA_ECDSALeaf(t *testing.T) {
	engine := pqcTestEngine(t)
	soft := pqcSoftEngine(t)
	ctx := context.Background()

	// 1. SLH-DSA root CA (paramSet 1 = SHA2-128s)
	caKeyID, caSigner, err := soft.CreateSLHDSAPrivateKey(ctx, 1)
	require.NoError(t, err)
	caCert, err := engine.CreateRootCA(ctx, caSigner, caKeyID, models.Subject{CommonName: "SLH-DSA CA"}, pqcValidity(time.Hour), pqcCAProfile(time.Hour))
	require.NoError(t, err)

	// 2. ECDSA end-entity key + CSR
	_, ecSigner, err := soft.CreateECDSAPrivateKey(ctx, elliptic.P256())
	require.NoError(t, err)
	csr := makeCSR(t, ecSigner, "ecdsa-leaf")

	// 3. Sign the CSR with the SLH-DSA CA
	leafCert, err := engine.SignCertificateRequest(ctx, csr, caCert, caSigner, pqcLeafProfile(time.Hour))
	require.NoError(t, err)
	require.NotNil(t, leafCert)

	assert.Equal(t, "ecdsa-leaf", leafCert.Subject.CommonName)
	assert.Equal(t, "SLH-DSA CA", leafCert.Issuer.CommonName)
	assert.False(t, leafCert.IsCA)
}

// TestSignCertificateRequestWithSLHDSALeaf verifies that a standard ECDSA CA
// can sign an SLH-DSA end-entity CSR.
func TestSignCertificateRequestWithSLHDSALeaf(t *testing.T) {
	engine := pqcTestEngine(t)
	soft := pqcSoftEngine(t)
	ctx := context.Background()

	// 1. ECDSA root CA
	caKeyID, caSigner, err := soft.CreateECDSAPrivateKey(ctx, elliptic.P256())
	require.NoError(t, err)
	caCert, err := engine.CreateRootCA(ctx, caSigner, caKeyID, models.Subject{CommonName: "ECDSA CA"}, pqcValidity(time.Hour), pqcCAProfile(time.Hour))
	require.NoError(t, err)

	// 2. SLH-DSA end-entity key + CSR
	_, slhSigner, err := soft.CreateSLHDSAPrivateKey(ctx, 1)
	require.NoError(t, err)
	csr := makeCSR(t, slhSigner, "slhdsa-leaf")

	// 3. Sign with ECDSA CA
	leafCert, err := engine.SignCertificateRequest(ctx, csr, caCert, caSigner, pqcLeafProfile(time.Hour))
	require.NoError(t, err)
	require.NotNil(t, leafCert)

	assert.Equal(t, "slhdsa-leaf", leafCert.Subject.CommonName)
	assert.Equal(t, "ECDSA CA", leafCert.Issuer.CommonName)
}

// TestSLHDSACASignsSLHDSALeaf verifies an end-to-end PQC chain where both
// the CA and the leaf use SLH-DSA keys.
func TestSLHDSACASignsSLHDSALeaf(t *testing.T) {
	engine := pqcTestEngine(t)
	soft := pqcSoftEngine(t)
	ctx := context.Background()

	// CA key (paramSet 1 = SHA2-128s)
	caKeyID, caSigner, err := soft.CreateSLHDSAPrivateKey(ctx, 1)
	require.NoError(t, err)
	caCert, err := engine.CreateRootCA(ctx, caSigner, caKeyID, models.Subject{CommonName: "SLH-DSA CA"}, pqcValidity(time.Hour), pqcCAProfile(time.Hour))
	require.NoError(t, err)

	// Leaf key (paramSet 1 = SHA2-128s)
	_, leafSigner, err := soft.CreateSLHDSAPrivateKey(ctx, 1)
	require.NoError(t, err)
	csr := makeCSR(t, leafSigner, "slhdsa-to-slhdsa-leaf")

	leafCert, err := engine.SignCertificateRequest(ctx, csr, caCert, caSigner, pqcLeafProfile(time.Hour))
	require.NoError(t, err)
	require.NotNil(t, leafCert)

	assert.Equal(t, "slhdsa-to-slhdsa-leaf", leafCert.Subject.CommonName)
	assert.Equal(t, "SLH-DSA CA", leafCert.Issuer.CommonName)
}

// --- Composite ML-DSA-RSA tests ---

// TestCreateRootCAWithCompositeMLDSARSA verifies that CreateRootCA produces a
// valid, self-signed CA certificate when the key is Composite ML-DSA-RSA
// (variant 1 = MLDSA44-RSA2048-PSS-SHA256).
func TestCreateRootCAWithCompositeMLDSARSA(t *testing.T) {
	engine := pqcTestEngine(t)
	soft := pqcSoftEngine(t)
	ctx := context.Background()

	// variant 1 = MLDSA44-RSA2048-PSS-SHA256
	keyID, signer, err := soft.CreateCompositeMLDSARSAPrivateKey(ctx, 1)
	require.NoError(t, err)

	subject := models.Subject{CommonName: "Composite ML-DSA-RSA Test Root CA"}
	cert, err := engine.CreateRootCA(ctx, signer, keyID, subject, pqcValidity(time.Hour), pqcCAProfile(time.Hour))
	require.NoError(t, err)
	require.NotNil(t, cert)

	assert.Equal(t, "Composite ML-DSA-RSA Test Root CA", cert.Subject.CommonName)
	assert.True(t, cert.IsCA)
	assert.True(t, cert.BasicConstraintsValid)
	assert.NotEmpty(t, cert.OCSPServer)
	assert.NotEmpty(t, cert.CRLDistributionPoints)
}

// TestSignCertificateRequestWithCompositeMLDSARSACA_ECDSALeaf verifies that a
// Composite ML-DSA-RSA CA can sign an ECDSA end-entity CSR.
func TestSignCertificateRequestWithCompositeMLDSARSACA_ECDSALeaf(t *testing.T) {
	engine := pqcTestEngine(t)
	soft := pqcSoftEngine(t)
	ctx := context.Background()

	// 1. Composite root CA (variant 1)
	caKeyID, caSigner, err := soft.CreateCompositeMLDSARSAPrivateKey(ctx, 1)
	require.NoError(t, err)
	caCert, err := engine.CreateRootCA(ctx, caSigner, caKeyID, models.Subject{CommonName: "Composite CA"}, pqcValidity(time.Hour), pqcCAProfile(time.Hour))
	require.NoError(t, err)

	// 2. ECDSA end-entity key + CSR
	_, ecSigner, err := soft.CreateECDSAPrivateKey(ctx, elliptic.P256())
	require.NoError(t, err)
	csr := makeCSR(t, ecSigner, "ecdsa-leaf")

	// 3. Sign with Composite CA
	leafCert, err := engine.SignCertificateRequest(ctx, csr, caCert, caSigner, pqcLeafProfile(time.Hour))
	require.NoError(t, err)
	require.NotNil(t, leafCert)

	assert.Equal(t, "ecdsa-leaf", leafCert.Subject.CommonName)
	assert.Equal(t, "Composite CA", leafCert.Issuer.CommonName)
	assert.False(t, leafCert.IsCA)
}

// TestSignCertificateRequestWithCompositeMLDSARSALeaf verifies that a standard
// ECDSA CA can sign a Composite ML-DSA-RSA end-entity CSR.
func TestSignCertificateRequestWithCompositeMLDSARSALeaf(t *testing.T) {
	engine := pqcTestEngine(t)
	soft := pqcSoftEngine(t)
	ctx := context.Background()

	// 1. ECDSA root CA
	caKeyID, caSigner, err := soft.CreateECDSAPrivateKey(ctx, elliptic.P256())
	require.NoError(t, err)
	caCert, err := engine.CreateRootCA(ctx, caSigner, caKeyID, models.Subject{CommonName: "ECDSA CA"}, pqcValidity(time.Hour), pqcCAProfile(time.Hour))
	require.NoError(t, err)

	// 2. Composite end-entity key + CSR (variant 1)
	_, compSigner, err := soft.CreateCompositeMLDSARSAPrivateKey(ctx, 1)
	require.NoError(t, err)
	csr := makeCSR(t, compSigner, "composite-leaf")

	// 3. Sign with ECDSA CA
	leafCert, err := engine.SignCertificateRequest(ctx, csr, caCert, caSigner, pqcLeafProfile(time.Hour))
	require.NoError(t, err)
	require.NotNil(t, leafCert)

	assert.Equal(t, "composite-leaf", leafCert.Subject.CommonName)
	assert.Equal(t, "ECDSA CA", leafCert.Issuer.CommonName)
}

// TestCompositeCASignsCompositeLeaf verifies an end-to-end hybrid chain where
// both the CA and the leaf use Composite ML-DSA-RSA keys.
func TestCompositeCASignsCompositeLeaf(t *testing.T) {
	engine := pqcTestEngine(t)
	soft := pqcSoftEngine(t)
	ctx := context.Background()

	// CA key (variant 1 = MLDSA44-RSA2048-PSS-SHA256)
	caKeyID, caSigner, err := soft.CreateCompositeMLDSARSAPrivateKey(ctx, 1)
	require.NoError(t, err)
	caCert, err := engine.CreateRootCA(ctx, caSigner, caKeyID, models.Subject{CommonName: "Composite CA"}, pqcValidity(time.Hour), pqcCAProfile(time.Hour))
	require.NoError(t, err)

	// Leaf key (variant 1)
	_, leafSigner, err := soft.CreateCompositeMLDSARSAPrivateKey(ctx, 1)
	require.NoError(t, err)
	csr := makeCSR(t, leafSigner, "composite-to-composite-leaf")

	leafCert, err := engine.SignCertificateRequest(ctx, csr, caCert, caSigner, pqcLeafProfile(time.Hour))
	require.NoError(t, err)
	require.NotNil(t, leafCert)

	assert.Equal(t, "composite-to-composite-leaf", leafCert.Subject.CommonName)
	assert.Equal(t, "Composite CA", leafCert.Issuer.CommonName)
}
