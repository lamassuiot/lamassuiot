package cmp

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"testing"
)

// spkiBody builds a SubjectPublicKeyInfo *body* (algorithm || subjectPublicKey,
// without the outer SEQUENCE) for use as a CertTemplate publicKey [6] content.
func spkiBody(t *testing.T, algOID asn1.ObjectIdentifier, params asn1.RawValue, keyBits []byte) []byte {
	t.Helper()
	algID, err := asn1.Marshal(struct {
		Algorithm  asn1.ObjectIdentifier
		Parameters asn1.RawValue `asn1:"optional"`
	}{Algorithm: algOID, Parameters: params})
	if err != nil {
		t.Fatal(err)
	}
	bs, err := asn1.Marshal(asn1.BitString{Bytes: keyBits, BitLength: len(keyBits) * 8})
	if err != nil {
		t.Fatal(err)
	}
	return append(algID, bs...)
}

func TestInspectKGATemplateKey(t *testing.T) {
	null := asn1.NullRawValue

	// Empty RSA key ⇒ for_kga, RSA hint.
	if empty, alg := inspectKGATemplateKey(spkiBody(t, oidRSAEncryption, null, nil)); !empty || alg != x509.RSA {
		t.Fatalf("empty RSA: got empty=%v alg=%v, want true/RSA", empty, alg)
	}
	// Empty EC key ⇒ for_kga, ECDSA hint.
	ecParams := asn1.RawValue{}
	if empty, alg := inspectKGATemplateKey(spkiBody(t, oidECPublicKey, ecParams, nil)); !empty || alg != x509.ECDSA {
		t.Fatalf("empty EC: got empty=%v alg=%v, want true/ECDSA", empty, alg)
	}
	// Non-empty key ⇒ NOT for_kga.
	if empty, _ := inspectKGATemplateKey(spkiBody(t, oidRSAEncryption, null, []byte{0x01, 0x02, 0x03})); empty {
		t.Fatal("non-empty key must not be flagged as for_kga")
	}
	// Empty key with an unknown algorithm ⇒ for_kga but no usable hint.
	if empty, alg := inspectKGATemplateKey(spkiBody(t, asn1.ObjectIdentifier{1, 2, 3, 4}, null, nil)); !empty || alg != x509.UnknownPublicKeyAlgorithm {
		t.Fatalf("empty unknown-alg: got empty=%v alg=%v, want true/Unknown", empty, alg)
	}
	// Garbage ⇒ safe default (treated as a normal key).
	if empty, _ := inspectKGATemplateKey([]byte{0xFF, 0x00}); empty {
		t.Fatal("malformed SPKI body must default to non-KGA")
	}
}

// TestMarshalKGACertRepBody verifies the RFC 9483 §4.1.6 CertifiedKeyPair
// encoding: the issued certificate under certOrEncCert [0], and the centrally
// generated key under privateKey [0] EXPLICIT → EncryptedKey CHOICE →
// envelopedData [0] IMPLICIT EnvelopedData. The decode below mirrors the
// compliance validator's pyasn1 schema (privateKey.getName() == "envelopedData").
func TestMarshalKGACertRepBody(t *testing.T) {
	// Stand-in DER blobs. certDER and envelopedDataDER only need to be
	// well-formed TLVs for the structural test; their contents are opaque here.
	certDER, err := asn1.Marshal(struct {
		A int
		B []byte
	}{A: 1, B: []byte("fake-cert")})
	if err != nil {
		t.Fatal(err)
	}
	// EnvelopedData is a SEQUENCE; use a recognisable body so we can assert the
	// re-tagging preserved it byte-for-byte.
	envBody := struct {
		Version int
		Tag     []byte
	}{Version: 2, Tag: []byte("enveloped-data-body")}
	envelopedDataDER, err := asn1.Marshal(envBody)
	if err != nil {
		t.Fatal(err)
	}

	bodyDER, err := marshalKGACertRepBody(0, 0, certDER, envelopedDataDER)
	if err != nil {
		t.Fatalf("marshalKGACertRepBody: %v", err)
	}

	// CertRepMessage ::= SEQUENCE { response SEQUENCE OF CertResponse }
	var msg serverCertRepMessage
	if _, err := asn1.Unmarshal(bodyDER, &msg); err != nil {
		t.Fatalf("decode CertRepMessage: %v", err)
	}
	if len(msg.Responses) != 1 {
		t.Fatalf("want 1 CertResponse, got %d", len(msg.Responses))
	}
	resp := msg.Responses[0]
	if resp.CertReqID != 0 {
		t.Fatalf("certReqId = %d, want 0", resp.CertReqID)
	}

	// CertifiedKeyPair ::= SEQUENCE { certOrEncCert, privateKey [0] ... }
	var ckp struct {
		CertOrEncCert asn1.RawValue
		PrivateKey    asn1.RawValue `asn1:"tag:0"`
	}
	if _, err := asn1.Unmarshal(resp.CertifiedKeyPair.FullBytes, &ckp); err != nil {
		t.Fatalf("decode CertifiedKeyPair: %v", err)
	}
	certOrEncCert := ckp.CertOrEncCert
	privateKey := ckp.PrivateKey

	// certOrEncCert ::= [0] certificate — its content must be the cert DER.
	if certOrEncCert.Class != asn1.ClassContextSpecific || certOrEncCert.Tag != 0 {
		t.Fatalf("certOrEncCert tag = class %d/tag %d, want context/0", certOrEncCert.Class, certOrEncCert.Tag)
	}
	if !bytes.Equal(certOrEncCert.Bytes, certDER) {
		t.Fatal("certOrEncCert content does not equal the issued cert DER")
	}

	// privateKey is EXPLICIT [0]; its single inner element is the EncryptedKey
	// CHOICE, chosen as envelopedData [0] IMPLICIT.
	if privateKey.Class != asn1.ClassContextSpecific || privateKey.Tag != 0 {
		t.Fatalf("privateKey tag = class %d/tag %d, want context/0", privateKey.Class, privateKey.Tag)
	}
	var envChoice asn1.RawValue
	if _, err := asn1.Unmarshal(privateKey.Bytes, &envChoice); err != nil {
		t.Fatalf("decode EncryptedKey CHOICE: %v", err)
	}
	if envChoice.Class != asn1.ClassContextSpecific || envChoice.Tag != 0 {
		t.Fatalf("envelopedData alternative tag = class %d/tag %d, want context/0", envChoice.Class, envChoice.Tag)
	}

	// The IMPLICIT [0] re-tag must have preserved the EnvelopedData SEQUENCE body:
	// re-wrapping the content as a UNIVERSAL SEQUENCE must reproduce the input DER.
	rebuilt, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: envChoice.Bytes,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rebuilt, envelopedDataDER) {
		t.Fatal("recovered EnvelopedData body does not match the input DER")
	}
}
