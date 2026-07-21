package cms

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
)

var oidCmKGA = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 32}

// makeCert builds a self-signed certificate for key with the given EKUs and a
// SubjectKeyId derived from cn.
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

// buildKeyPackage mirrors the CMP KGA layering: an AsymmetricKeyPackage inside a
// KGA-signed SignedData inside an EnvelopedData delivered to the recipient.
func buildKeyPackage(t *testing.T, genKey crypto.Signer, recipCert, kgaCert *x509.Certificate, kgaSigner crypto.Signer, originatorKey *ecdsa.PrivateKey, originatorCert *x509.Certificate) []byte {
	t.Helper()
	akp, err := MarshalAsymmetricKeyPackage(genKey)
	if err != nil {
		t.Fatalf("MarshalAsymmetricKeyPackage: %v", err)
	}
	sd, err := BuildSignedData(SignedDataInput{
		EContentType: OIDKeyPackage(),
		EContent:     akp,
		SignerCert:   kgaCert,
		Signer:       kgaSigner,
	})
	if err != nil {
		t.Fatalf("BuildSignedData: %v", err)
	}
	env, err := BuildEnvelopedData(EnvelopedDataInput{
		Content:        sd,
		ContentType:    OIDSignedData(),
		RecipientCert:  recipCert,
		OriginatorKey:  originatorKey,
		OriginatorCert: originatorCert,
	})
	if err != nil {
		t.Fatalf("BuildEnvelopedData: %v", err)
	}
	return env
}

// openKeyPackage mirrors the client side: open the EnvelopedData, verify the
// SignedData, and parse out the delivered key.
func openKeyPackage(t *testing.T, env []byte, recipient crypto.Signer, extraCerts []*x509.Certificate) crypto.Signer {
	t.Helper()
	content, contentType, err := DecryptEnvelopedData(env, recipient, extraCerts)
	if err != nil {
		t.Fatalf("DecryptEnvelopedData: %v", err)
	}
	if !contentType.Equal(OIDSignedData()) {
		t.Fatalf("enveloped content type = %v, want signedData", contentType)
	}
	verified, err := VerifySignedData(content, extraCerts, VerifyOptions{RequiredEKUs: []asn1.ObjectIdentifier{oidCmKGA}})
	if err != nil {
		t.Fatalf("VerifySignedData: %v", err)
	}
	if !verified.EContentType.Equal(OIDKeyPackage()) {
		t.Fatalf("eContentType = %v, want id-ct-KP-aKeyPackage", verified.EContentType)
	}
	key, err := ParseAsymmetricKeyPackage(verified.EContent)
	if err != nil {
		t.Fatalf("ParseAsymmetricKeyPackage: %v", err)
	}
	return key
}

func TestSignedEnveloped_KTRI(t *testing.T) {
	kgaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	kgaCert := makeCert(t, kgaKey, "kga", []asn1.ObjectIdentifier{oidCmKGA})

	recipKey, _ := rsa.GenerateKey(rand.Reader, 2048) // EE keyEncipherment key
	recipCert := makeCert(t, recipKey, "ee-ktri", nil)

	genKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader) // the delivered key

	env := buildKeyPackage(t, genKey, recipCert, kgaCert, kgaKey, nil, nil)

	// EnvelopedData version 2 with a ktri subjectKeyIdentifier rid.
	var ed envelopedData
	if _, err := asn1.Unmarshal(env, &ed); err != nil {
		t.Fatalf("decode EnvelopedData: %v", err)
	}
	if ed.Version != 2 {
		t.Fatalf("EnvelopedData version = %d, want 2", ed.Version)
	}
	var ktri keyTransRecipientInfo
	if _, err := asn1.Unmarshal(ed.RecipientInfos.Bytes, &ktri); err != nil {
		t.Fatalf("decode ktri: %v", err)
	}
	if ktri.Version != 2 {
		t.Fatalf("ktri version = %d, want 2", ktri.Version)
	}
	if ktri.RID.Class != asn1.ClassContextSpecific || ktri.RID.Tag != 0 {
		t.Fatalf("ktri rid = class %d/tag %d, want context/0 (subjectKeyIdentifier)", ktri.RID.Class, ktri.RID.Tag)
	}
	if !ktri.KeyEncryptionAlgorithm.Algorithm.Equal(oidRSAESOAEP) {
		t.Fatalf("ktri keyEncAlg = %v, want id-RSAES-OAEP", ktri.KeyEncryptionAlgorithm.Algorithm)
	}

	delivered := openKeyPackage(t, env, recipKey, []*x509.Certificate{recipCert, kgaCert})
	got := delivered.Public().(*ecdsa.PublicKey)
	if !got.Equal(&genKey.PublicKey) {
		t.Fatal("delivered key does not match the generated key")
	}
}

func TestSignedEnveloped_KARI(t *testing.T) {
	kgaKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	kgaCert := makeCert(t, kgaKey, "kga", []asn1.ObjectIdentifier{oidCmKGA})

	origKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader) // RA originator (extraCerts[0])
	origCert := makeCert(t, origKey, "ra-originator", nil)

	recipKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader) // EE keyAgreement key
	recipCert := makeCert(t, recipKey, "ee-kari", nil)

	genKey, _ := rsa.GenerateKey(rand.Reader, 2048) // delivered key

	env := buildKeyPackage(t, genKey, recipCert, kgaCert, kgaKey, origKey, origCert)

	// kari alternative is IMPLICIT [1].
	var ed envelopedData
	if _, err := asn1.Unmarshal(env, &ed); err != nil {
		t.Fatalf("decode EnvelopedData: %v", err)
	}
	var ri asn1.RawValue
	if _, err := asn1.Unmarshal(ed.RecipientInfos.Bytes, &ri); err != nil {
		t.Fatalf("decode recipientInfo: %v", err)
	}
	if ri.Class != asn1.ClassContextSpecific || ri.Tag != 1 {
		t.Fatalf("recipientInfo = class %d/tag %d, want context/1 (kari)", ri.Class, ri.Tag)
	}

	// The originator cert is required in extraCerts for ECDH.
	delivered := openKeyPackage(t, env, recipKey, []*x509.Certificate{origCert, kgaCert})
	got := delivered.Public().(*rsa.PublicKey)
	if !got.Equal(&genKey.PublicKey) {
		t.Fatal("delivered key does not match the generated key")
	}
}

func TestBuildEnvelopedData_RecipientIDOverride(t *testing.T) {
	// The CMP challenge-response override forces an issuerAndSerialNumber rid
	// with a NULL-DN issuer and a chosen serial, even though the recipient cert
	// has an SKI.
	recipKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	recipCert := makeCert(t, recipKey, "ee", nil)

	nullDN, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true})
	if err != nil {
		t.Fatal(err)
	}
	env, err := BuildEnvelopedData(EnvelopedDataInput{
		Content:             []byte("some-nonce-content-bytes"),
		ContentType:         OIDData(),
		RecipientCert:       recipCert,
		RecipientIDOverride: &IssuerAndSerial{IssuerDER: nullDN, Serial: big.NewInt(0)},
	})
	if err != nil {
		t.Fatalf("BuildEnvelopedData: %v", err)
	}
	var ed envelopedData
	if _, err := asn1.Unmarshal(env, &ed); err != nil {
		t.Fatalf("decode EnvelopedData: %v", err)
	}
	var ktri keyTransRecipientInfo
	if _, err := asn1.Unmarshal(ed.RecipientInfos.Bytes, &ktri); err != nil {
		t.Fatalf("decode ktri: %v", err)
	}
	if ktri.Version != 0 {
		t.Fatalf("ktri version = %d, want 0 (issuerAndSerialNumber)", ktri.Version)
	}
	if ktri.RID.Tag != asn1.TagSequence {
		t.Fatalf("ktri rid tag = %d, want SEQUENCE (issuerAndSerialNumber)", ktri.RID.Tag)
	}
	// Round-trips back to the same content.
	content, _, err := DecryptEnvelopedData(env, recipKey, nil)
	if err != nil {
		t.Fatalf("DecryptEnvelopedData: %v", err)
	}
	if string(content) != "some-nonce-content-bytes" {
		t.Fatalf("recovered content = %q", content)
	}
}
