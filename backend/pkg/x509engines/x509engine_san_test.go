package x509engines

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/url"
	"testing"
	"time"

	chelpers "github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
)

func TestGenerateCertificateRequestFromCertificate_SAN(t *testing.T) {
	tempDir, _, _ := setup(t)
	defer teardown(tempDir)

	// Create a certificate with SANs
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test Cert",
		},
		NotBefore:      time.Now(),
		NotAfter:       time.Now().Add(time.Hour),
		DNSNames:       []string{"example.com"},
		IPAddresses:    []net.IP{net.ParseIP("127.0.0.1")},
		EmailAddresses: []string{"test@example.com"},
		URIs:           []*url.URL{{Scheme: "http", Host: "example.com"}},
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	// Generate CSR from certificate
	csrSigner := priv // Use the same key for signing CSR
	csr, err := chelpers.GenerateCertificateRequestFromCertificate(csrSigner, cert)
	if err != nil {
		t.Fatalf("GenerateCertificateRequestFromCertificate failed: %v", err)
	}

	// Verify SAN extension in CSR
	// x509.ParseCertificateRequest parses extensions into fields
	if len(csr.DNSNames) != 1 || csr.DNSNames[0] != "example.com" {
		t.Errorf("Expected DNSName example.com, got %v", csr.DNSNames)
	}
	if len(csr.IPAddresses) != 1 || !csr.IPAddresses[0].Equal(net.ParseIP("127.0.0.1")) {
		t.Errorf("Expected IPAddress 127.0.0.1, got %v", csr.IPAddresses)
	}
	if len(csr.EmailAddresses) != 1 || csr.EmailAddresses[0] != "test@example.com" {
		t.Errorf("Expected EmailAddress test@example.com, got %v", csr.EmailAddresses)
	}
	if len(csr.URIs) != 1 || csr.URIs[0].String() != "http://example.com" {
		t.Errorf("Expected URI http://example.com, got %v", csr.URIs)
	}
}
