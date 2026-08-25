package cmp

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"

	corecmp "github.com/lamassuiot/lamassuiot/core/v3/pkg/cmp"
)

// These tests exercise the backend KGA orchestration (buildKGAKeyPackage) end
// to end: they build the RFC 9483 §4.1.6 key package and recover it through the
// CMP client decoder (corecmp.DecodeKGAResponse), proving the server-built CMS
// round-trips. The low-level CMS wire-format assertions (struct shapes, OIDs,
// key wrap, KDF) live in core/pkg/cms; here we only care that the whole KGA
// flow interoperates.

var oidKGACmKGA = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 32}

// makeCert builds a self-signed certificate for key with the given EKUs and a
// SubjectKeyId. Good enough for exercising the KGA envelope (the suite's
// trust-anchor/EKU checks are validated end-to-end, not here).
func makeCert(t *testing.T, key crypto.Signer, cn string, ekus []asn1.ObjectIdentifier) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(int64(len(cn)) + 1),
		Subject:      pkix.Name{CommonName: cn},
		SubjectKeyId: []byte(cn + "-ski"),
	}
	tmpl.UnknownExtKeyUsage = append(tmpl.UnknownExtKeyUsage, ekus...)
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return c
}

// decodeAsClient wraps the server-built EnvelopedData in an ip body and decodes
// it exactly as a CMP client would, returning the recovered private key.
func decodeAsClient(t *testing.T, envelopedDataDER []byte, issuedCert *x509.Certificate, recipient crypto.Signer, extraCerts []*x509.Certificate) crypto.Signer {
	t.Helper()
	bodyDER, err := corecmp.MarshalKGACertRepBody(0, int(corecmp.StatusAccepted), issuedCert.Raw, envelopedDataDER)
	if err != nil {
		t.Fatalf("marshal cert rep body: %v", err)
	}
	result, err := corecmp.DecodeKGAResponse(corecmp.ParsedMessage{
		Body:       corecmp.EncodedBody{Type: corecmp.BodyIP, DER: bodyDER},
		ExtraCerts: extraCerts,
	}, corecmp.KGADecryptOptions{Recipient: recipient})
	if err != nil {
		t.Fatalf("DecodeKGAResponse: %v", err)
	}
	return result.PrivateKey
}

func TestBuildKGAKeyPackage_KTRI(t *testing.T) {
	kgaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	kgaCert := makeCert(t, kgaKey, "kga", []asn1.ObjectIdentifier{oidKGACmKGA})

	recipKey, _ := rsa.GenerateKey(rand.Reader, 2048) // EE keyEncipherment key
	recipCert := makeCert(t, recipKey, "ee-ktri", nil)

	genKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader) // the delivered key

	der, err := buildKGAKeyPackage(kgaBuildInput{
		GeneratedKey:  genKey,
		RecipientCert: recipCert,
		KGACert:       kgaCert,
		KGASigner:     kgaKey,
	})
	if err != nil {
		t.Fatalf("buildKGAKeyPackage: %v", err)
	}

	issuedCert := makeCert(t, genKey, "issued-ktri", nil)
	// KTRI: the recipient EE cert is extraCerts[0]; the KGA cert follows.
	delivered := decodeAsClient(t, der, issuedCert, recipKey, []*x509.Certificate{recipCert, kgaCert})

	got, ok := delivered.(*ecdsa.PrivateKey)
	if !ok || !got.PublicKey.Equal(&genKey.PublicKey) {
		t.Fatal("CMP client did not recover the KTRI-delivered key")
	}
}

func TestBuildKGAKeyPackage_KARI(t *testing.T) {
	kgaKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	kgaCert := makeCert(t, kgaKey, "kga", []asn1.ObjectIdentifier{oidKGACmKGA})

	origKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader) // RA originator (extraCerts[0])
	origCert := makeCert(t, origKey, "ra-originator", nil)

	recipKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader) // EE keyAgreement key
	recipCert := makeCert(t, recipKey, "ee-kari", nil)

	genKey, _ := rsa.GenerateKey(rand.Reader, 2048) // delivered key

	der, err := buildKGAKeyPackage(kgaBuildInput{
		GeneratedKey:       genKey,
		RecipientCert:      recipCert,
		KARIOriginatorKey:  origKey,
		KARIOriginatorCert: origCert,
		KGACert:            kgaCert,
		KGASigner:          kgaKey,
	})
	if err != nil {
		t.Fatalf("buildKGAKeyPackage: %v", err)
	}

	issuedCert := makeCert(t, genKey, "issued-kari", nil)
	// KARI: the originator cert MUST be extraCerts[0] so the client can ECDH.
	delivered := decodeAsClient(t, der, issuedCert, recipKey, []*x509.Certificate{origCert, kgaCert})

	got, ok := delivered.(*rsa.PrivateKey)
	if !ok || !got.PublicKey.Equal(&genKey.PublicKey) {
		t.Fatal("CMP client did not recover the KARI-delivered key")
	}
}
