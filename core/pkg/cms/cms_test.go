package cms

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
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

// TestBuildSignedData_SignatureCoversSignedAttrs independently recomputes the
// expected digest and re-verifies the signature exactly as a conformant
// RFC 5652 verifier (e.g. openssl) would — NOT by reusing VerifySignedData or
// any of BuildSignedData's internal helpers — to guard against the signature
// covering the wrong bytes (e.g. encapContentInfo instead of signedAttrs,
// RFC 5652 §5.4).
func TestBuildSignedData_SignatureCoversSignedAttrs(t *testing.T) {
	kgaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	kgaCert := makeCert(t, kgaKey, "kga", []asn1.ObjectIdentifier{oidCmKGA})

	eContent := []byte("independent-verification-content")
	sdDER, err := BuildSignedData(SignedDataInput{
		EContentType: OIDKeyPackage(),
		EContent:     eContent,
		SignerCert:   kgaCert,
		Signer:       kgaKey,
	})
	if err != nil {
		t.Fatalf("BuildSignedData: %v", err)
	}

	var sd signedData
	if _, err := asn1.Unmarshal(sdDER, &sd); err != nil {
		t.Fatalf("decode SignedData: %v", err)
	}
	if len(sd.SignerInfos) != 1 {
		t.Fatalf("want exactly one SignerInfo, got %d", len(sd.SignerInfos))
	}
	si := sd.SignerInfos[0]

	// signedAttrs must carry contentType + messageDigest(hash of eContent).
	var attrs []attribute
	if _, err := asn1.UnmarshalWithParams(si.SignedAttrs.FullBytes, &attrs, "tag:0"); err != nil {
		t.Fatalf("decode signedAttrs: %v", err)
	}
	wantDigest := sha256.Sum256(sd.EncapContentInfo.EContent)
	var gotDigest []byte
	for _, a := range attrs {
		if a.Type.Equal(oidMessageDigest) {
			var values [][]byte
			if _, err := asn1.UnmarshalWithParams(a.Values.FullBytes, &values, "set"); err != nil {
				t.Fatalf("decode messageDigest attribute values: %v", err)
			}
			if len(values) != 1 {
				t.Fatalf("messageDigest attribute has %d values, want 1", len(values))
			}
			gotDigest = values[0]
		}
	}
	if gotDigest == nil {
		t.Fatal("signedAttrs missing id-messageDigest")
	}
	if !bytes.Equal(gotDigest, wantDigest[:]) {
		t.Fatalf("messageDigest attribute = %x, want sha256(eContent) = %x", gotDigest, wantDigest)
	}

	// RFC 5652 §5.4: the signature covers the DER of signedAttrs RE-TAGGED as a
	// UNIVERSAL SET OF — not the IMPLICIT [0] wire encoding, and NOT
	// encapContentInfo. This is the exact recomputation openssl performs.
	signedAttrsForSigning, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true,
		Bytes: si.SignedAttrs.Bytes,
	})
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(signedAttrsForSigning)
	if err := rsa.VerifyPKCS1v15(&kgaKey.PublicKey, crypto.SHA256, h[:], si.Signature); err != nil {
		t.Fatalf("independent signature verification failed (signature does not cover signedAttrs per RFC 5652 §5.4): %v", err)
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
