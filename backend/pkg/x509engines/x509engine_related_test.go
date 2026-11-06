package x509engines

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	chelpers "github.com/lamassuiot/lamassuiot/v4/core/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"go.mozilla.org/pkcs7"
)

type relatedCertFixture struct {
	engine X509Engine
	ca     *x509.Certificate
	signer *ecdsa.PrivateKey
}

func newRelatedCertFixture(t *testing.T) relatedCertFixture {
	t.Helper()
	engine := NewX509Engine(logrus.NewEntry(logrus.New()), []string{"va.example.com"}, nil)

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ca, err := engine.CreateRootCA(context.Background(), caKey, "ca-key", models.Subject{CommonName: "Related Test CA"}, pqcValidity(time.Hour), pqcCAProfile(time.Hour))
	require.NoError(t, err)

	return relatedCertFixture{engine: engine, ca: ca, signer: caKey}
}

func newRelatedCert(t *testing.T, serial int64, usage x509.KeyUsage) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: "related"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     usage,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert, key
}

// relatedProfile returns a leaf profile with related certificates enabled.
func relatedProfile(hosts []string, maxAge time.Duration) models.IssuanceProfile {
	p := pqcLeafProfile(time.Hour)
	p.RelatedCertificate = models.IssuanceProfileRelatedCertificate{Enabled: true, AllowedHosts: hosts, MaxAge: models.TimeDuration(maxAge)}
	return p
}

func pkcs7DataURI(t *testing.T, cert *x509.Certificate) string {
	t.Helper()
	der, err := pkcs7.DegenerateCertificate(cert.Raw)
	require.NoError(t, err)
	return "data:application/pkcs7-mime;base64," + base64.StdEncoding.EncodeToString(der)
}

func derDataURI(cert *x509.Certificate) string {
	return "data:application/pkix-cert;base64," + base64.StdEncoding.EncodeToString(cert.Raw)
}

// relatedCSR builds a CSR carrying a relatedCertRequest attribute.
func relatedCSR(t *testing.T, related *x509.Certificate, relatedKey *ecdsa.PrivateKey, requestTime time.Time, uris []string, extensions ...pkix.Extension) *x509.CertificateRequest {
	t.Helper()
	attr, err := x509.CreateRelatedCertRequestAttribute(rand.Reader, related, relatedKey, requestTime, uris)
	require.NoError(t, err)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.CertificateRequest{
		Subject:         pkix.Name{CommonName: "bound"},
		ExtraAttributes: []asn1.RawValue{attr},
		ExtraExtensions: extensions,
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	require.NoError(t, err)
	csr, err := x509.ParseCertificateRequest(der)
	require.NoError(t, err)
	return csr
}

func TestSignCertificateRequestWithRelatedCertificate(t *testing.T) {
	ctx := context.Background()
	related, relatedKey := newRelatedCert(t, 7, x509.KeyUsageDigitalSignature)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/related.crt":
			w.Write(related.Raw)
		case "/related.p7":
			der, _ := pkcs7.DegenerateCertificate(related.Raw)
			w.Write(der)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	serverURL, err := url.Parse(server.URL)
	require.NoError(t, err)
	httpURI := server.URL + "/related.crt"

	t.Run("PKCS#7 data URI", func(t *testing.T) {
		f := newRelatedCertFixture(t)
		csr := relatedCSR(t, related, relatedKey, time.Now(), []string{pkcs7DataURI(t, related)})

		cert, err := f.engine.SignCertificateRequest(ctx, csr, f.ca, f.signer, relatedProfile(nil, 0))
		require.NoError(t, err)
		require.NoError(t, x509.VerifyRelatedCertificate(cert, related))
	})

	t.Run("data URI with a plain certificate", func(t *testing.T) {
		f := newRelatedCertFixture(t)
		csr := relatedCSR(t, related, relatedKey, time.Now(), []string{derDataURI(related)})

		_, err := f.engine.SignCertificateRequest(ctx, csr, f.ca, f.signer, relatedProfile(nil, 0))
		require.Error(t, err)
	})

	t.Run("http URI serving PKCS#7", func(t *testing.T) {
		f := newRelatedCertFixture(t)
		csr := relatedCSR(t, related, relatedKey, time.Now(), []string{server.URL + "/related.p7"})

		_, err := f.engine.SignCertificateRequest(ctx, csr, f.ca, f.signer, relatedProfile([]string{serverURL.Hostname()}, 0))
		require.Error(t, err)
	})

	t.Run("http URI on an allowed host", func(t *testing.T) {
		f := newRelatedCertFixture(t)
		csr := relatedCSR(t, related, relatedKey, time.Now(), []string{httpURI})

		cert, err := f.engine.SignCertificateRequest(ctx, csr, f.ca, f.signer, relatedProfile([]string{serverURL.Hostname()}, 0))
		require.NoError(t, err)
		require.NoError(t, x509.VerifyRelatedCertificate(cert, related))
	})

	t.Run("http URI on a host that is not allowed", func(t *testing.T) {
		f := newRelatedCertFixture(t)
		csr := relatedCSR(t, related, relatedKey, time.Now(), []string{httpURI})

		_, err := f.engine.SignCertificateRequest(ctx, csr, f.ca, f.signer, relatedProfile(nil, 0))
		require.ErrorContains(t, err, "is not allowed")
	})

	t.Run("falls back to the next URI", func(t *testing.T) {
		f := newRelatedCertFixture(t)
		csr := relatedCSR(t, related, relatedKey, time.Now(), []string{"ftp://example.com/related.crt", pkcs7DataURI(t, related)})

		cert, err := f.engine.SignCertificateRequest(ctx, csr, f.ca, f.signer, relatedProfile(nil, 0))
		require.NoError(t, err)
		require.NoError(t, x509.VerifyRelatedCertificate(cert, related))
	})

	t.Run("unsupported URI scheme", func(t *testing.T) {
		f := newRelatedCertFixture(t)
		csr := relatedCSR(t, related, relatedKey, time.Now(), []string{"ftp://example.com/related.crt"})

		_, err := f.engine.SignCertificateRequest(ctx, csr, f.ca, f.signer, relatedProfile(nil, 0))
		require.ErrorContains(t, err, "unsupported URI scheme")
	})

	t.Run("stale attribute", func(t *testing.T) {
		f := newRelatedCertFixture(t)
		csr := relatedCSR(t, related, relatedKey, time.Now().Add(-time.Hour), []string{pkcs7DataURI(t, related)})

		_, err := f.engine.SignCertificateRequest(ctx, csr, f.ca, f.signer, relatedProfile(nil, 0))
		require.ErrorContains(t, err, "not fresh")
	})

	t.Run("custom max age", func(t *testing.T) {
		f := newRelatedCertFixture(t)
		csr := relatedCSR(t, related, relatedKey, time.Now().Add(-time.Hour), []string{pkcs7DataURI(t, related)})

		_, err := f.engine.SignCertificateRequest(ctx, csr, f.ca, f.signer, relatedProfile(nil, 2*time.Hour))
		require.NoError(t, err)
	})

	t.Run("different related certificate", func(t *testing.T) {
		f := newRelatedCertFixture(t)
		other, _ := newRelatedCert(t, 8, x509.KeyUsageDigitalSignature)
		csr := relatedCSR(t, related, relatedKey, time.Now(), []string{pkcs7DataURI(t, other)})

		_, err := f.engine.SignCertificateRequest(ctx, csr, f.ca, f.signer, relatedProfile(nil, 0))
		require.ErrorContains(t, err, "not the one identified")
	})

	t.Run("signature from another key", func(t *testing.T) {
		f := newRelatedCertFixture(t)
		impostor, _ := newRelatedCert(t, 7, x509.KeyUsageDigitalSignature)
		csr := relatedCSR(t, related, relatedKey, time.Now(), []string{pkcs7DataURI(t, impostor)})

		_, err := f.engine.SignCertificateRequest(ctx, csr, f.ca, f.signer, relatedProfile(nil, 0))
		require.Error(t, err)
	})

	t.Run("key usage not allowed by the related certificate", func(t *testing.T) {
		f := newRelatedCertFixture(t)
		keyUsage, err := chelpers.GenerateKeyUsagePKIExtension(x509.KeyUsageKeyEncipherment)
		require.NoError(t, err)
		csr := relatedCSR(t, related, relatedKey, time.Now(), []string{pkcs7DataURI(t, related)}, keyUsage)

		_, err = f.engine.SignCertificateRequest(ctx, csr, f.ca, f.signer, relatedProfile(nil, 0))
		require.ErrorContains(t, err, "key usages")
	})

	t.Run("related certificates not enabled by the profile", func(t *testing.T) {
		f := newRelatedCertFixture(t)
		csr := relatedCSR(t, related, relatedKey, time.Now(), []string{pkcs7DataURI(t, related)})

		_, err := f.engine.SignCertificateRequest(ctx, csr, f.ca, f.signer, pqcLeafProfile(time.Hour))
		require.ErrorContains(t, err, "not enabled")
	})

	t.Run("host allowed only by another profile", func(t *testing.T) {
		f := newRelatedCertFixture(t)
		csr := relatedCSR(t, related, relatedKey, time.Now(), []string{httpURI})

		_, err := f.engine.SignCertificateRequest(ctx, csr, f.ca, f.signer, relatedProfile([]string{"other.example.com"}, 0))
		require.ErrorContains(t, err, "is not allowed")
	})

	t.Run("CSR without the attribute", func(t *testing.T) {
		f := newRelatedCertFixture(t)
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		cert, err := f.engine.SignCertificateRequest(ctx, makeCSR(t, key, "plain"), f.ca, f.signer, relatedProfile(nil, 0))
		require.NoError(t, err)
		require.Error(t, x509.VerifyRelatedCertificate(cert, related))
	})
}
