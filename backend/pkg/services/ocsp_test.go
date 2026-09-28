package services

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"
)

func TestOCSPIssuerMatches(t *testing.T) {
	issuerA := testOCSPIssuer(t, "issuer-a")
	issuerB := testOCSPIssuer(t, "issuer-b")

	requestBytes, err := ocsp.CreateRequest(issuerA, issuerA, nil)
	if err != nil {
		t.Fatalf("could not create OCSP request: %s", err)
	}
	request, err := ocsp.ParseRequest(requestBytes)
	if err != nil {
		t.Fatalf("could not parse OCSP request: %s", err)
	}

	if !ocspIssuerMatches(request, issuerA) {
		t.Fatal("expected the request issuer to match")
	}
	if ocspIssuerMatches(request, issuerB) {
		t.Fatal("expected a different issuer to be rejected")
	}
}

func testOCSPIssuer(t *testing.T, commonName string) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("could not generate issuer key: %s", err)
	}
	serial := big.NewInt(1)
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("could not create issuer certificate: %s", err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("could not parse issuer certificate: %s", err)
	}
	return certificate
}
