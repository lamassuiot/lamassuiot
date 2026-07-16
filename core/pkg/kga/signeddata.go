package kga

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
)

// buildSignedData produces the DER of the CMS SignedData that wraps the
// generated key as an AsymmetricKeyPackage and is signed by the KGA.
//
// RFC 9483 §4.1.6 quirk (as enforced by the compliance validator): the
// SignerInfo signature is computed over the DER of the EncapsulatedContentInfo,
// and signedAttrs (contentType + messageDigest) are present for structural
// validation. Both are produced here.
func buildSignedData(in BuildInput) ([]byte, error) {
	// OneAsymmetricKey (RFC 5958 v2) → AsymmetricKeyPackage ::= SEQUENCE OF OneAsymmetricKey.
	oneAsym, err := oneAsymmetricKeyV2(in.GeneratedKey)
	if err != nil {
		return nil, fmt.Errorf("marshal generated key (OneAsymmetricKey): %w", err)
	}
	aKeyPackage, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      oneAsym, // single OneAsymmetricKey
	})
	if err != nil {
		return nil, fmt.Errorf("marshal AsymmetricKeyPackage: %w", err)
	}

	encap := encapsulatedContentInfo{
		EContentType: oidCTKPAKeyPackage,
		EContent:     aKeyPackage,
	}
	encapDER, err := asn1.Marshal(encap)
	if err != nil {
		return nil, fmt.Errorf("marshal encapContentInfo: %w", err)
	}

	// signedAttrs: id-contentType (= id-ct-KP-aKeyPackage) and id-messageDigest
	// (= SHA-256 over the eContent, i.e. the AsymmetricKeyPackage DER).
	msgDigest := sha256.Sum256(aKeyPackage)
	signedAttrsImplicit, err := buildSignedAttrs(msgDigest[:])
	if err != nil {
		return nil, err
	}

	// Signature: over the encapContentInfo DER (RFC 9483 §4.1.6 validator).
	sigAlg, err := signatureAlgorithmFor(in.KGASigner)
	if err != nil {
		return nil, err
	}
	h := sha256.Sum256(encapDER)
	signature, err := in.KGASigner.Sign(rand.Reader, h[:], crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("KGA sign: %w", err)
	}

	// sid = [0] subjectKeyIdentifier of the KGA cert (RFC 5652 SignerIdentifier).
	if len(in.KGACert.SubjectKeyId) == 0 {
		return nil, fmt.Errorf("KGA certificate has no SubjectKeyId")
	}
	sid, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassContextSpecific,
		Tag:   0,
		Bytes: in.KGACert.SubjectKeyId,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal signer identifier: %w", err)
	}

	si := signerInfo{
		Version:            3, // subjectKeyIdentifier sid ⇒ CMS v3
		SID:                asn1.RawValue{FullBytes: sid},
		DigestAlgorithm:    pkix.AlgorithmIdentifier{Algorithm: oidSHA256},
		SignedAttrs:        asn1.RawValue{FullBytes: signedAttrsImplicit},
		SignatureAlgorithm: sigAlg,
		Signature:          signature,
	}

	// certificates [0] IMPLICIT CertificateSet — KGA cert first, then chain.
	certsField, err := buildCertificatesField(in.KGACert, in.KGAChain)
	if err != nil {
		return nil, err
	}

	sd := signedData{
		Version:          3,
		DigestAlgorithms: []pkix.AlgorithmIdentifier{{Algorithm: oidSHA256}},
		EncapContentInfo: encap,
		Certificates:     asn1.RawValue{FullBytes: certsField},
		SignerInfos:      []signerInfo{si},
	}
	return asn1.Marshal(sd)
}

// oneAsymmetricKeyV2 encodes signer's private key as an RFC 5958 OneAsymmetricKey
// with version v2 (=1) and an explicit publicKey [1] field. Go's
// x509.MarshalPKCS8PrivateKey only ever emits version v1 (=0) without the
// publicKey, which the RFC 9483 §4.1.6 compliance validator rejects ("version
// must be 1"). We therefore reuse the PKCS#8 encoding for the common fields
// (privateKeyAlgorithm, privateKey, optional attributes), bump the version to 1
// and append publicKey [1] IMPLICIT BIT STRING taken from the SPKI.
func oneAsymmetricKeyV2(signer crypto.Signer) ([]byte, error) {
	pkcs8, err := x509.MarshalPKCS8PrivateKey(signer)
	if err != nil {
		return nil, fmt.Errorf("marshal generated key (PKCS#8): %w", err)
	}

	var seq asn1.RawValue
	if _, err := asn1.Unmarshal(pkcs8, &seq); err != nil {
		return nil, fmt.Errorf("parse PKCS#8: %w", err)
	}
	rest := seq.Bytes
	var ver, algo, priv asn1.RawValue
	if rest, err = asn1.Unmarshal(rest, &ver); err != nil {
		return nil, fmt.Errorf("parse PKCS#8 version: %w", err)
	}
	if rest, err = asn1.Unmarshal(rest, &algo); err != nil {
		return nil, fmt.Errorf("parse PKCS#8 algorithm: %w", err)
	}
	if rest, err = asn1.Unmarshal(rest, &priv); err != nil {
		return nil, fmt.Errorf("parse PKCS#8 privateKey: %w", err)
	}
	attrsRaw := rest // [0] attributes if present, empty otherwise

	// publicKey [1] IMPLICIT BIT STRING from the SubjectPublicKeyInfo.
	spki, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return nil, fmt.Errorf("marshal public key: %w", err)
	}
	var spkiSeq struct {
		Algorithm asn1.RawValue
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(spki, &spkiSeq); err != nil {
		return nil, fmt.Errorf("parse SPKI: %w", err)
	}
	pubField, err := asn1.MarshalWithParams(spkiSeq.PublicKey, "tag:1")
	if err != nil {
		return nil, fmt.Errorf("marshal publicKey field: %w", err)
	}

	verV2, err := asn1.Marshal(1) // version v2 = 1
	if err != nil {
		return nil, fmt.Errorf("marshal version: %w", err)
	}

	inner := make([]byte, 0, len(verV2)+len(algo.FullBytes)+len(priv.FullBytes)+len(attrsRaw)+len(pubField))
	inner = append(inner, verV2...)
	inner = append(inner, algo.FullBytes...)
	inner = append(inner, priv.FullBytes...)
	inner = append(inner, attrsRaw...)
	inner = append(inner, pubField...)

	return asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      inner,
	})
}

// buildSignedAttrs builds the SignerInfo signedAttrs field: an IMPLICIT [0]
// SET OF Attribute carrying id-contentType and id-messageDigest.
func buildSignedAttrs(messageDigest []byte) ([]byte, error) {
	// contentType attribute: values = SET { id-ct-KP-aKeyPackage }.
	ctOID, err := asn1.Marshal(oidCTKPAKeyPackage)
	if err != nil {
		return nil, err
	}
	ctValues, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: ctOID})
	if err != nil {
		return nil, err
	}
	ctAttr, err := asn1.Marshal(attribute{Type: oidContentType, Values: asn1.RawValue{FullBytes: ctValues}})
	if err != nil {
		return nil, err
	}

	// messageDigest attribute: values = SET { OCTET STRING(digest) }.
	mdOctet, err := asn1.Marshal(messageDigest) // []byte → OCTET STRING
	if err != nil {
		return nil, err
	}
	mdValues, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: mdOctet})
	if err != nil {
		return nil, err
	}
	mdAttr, err := asn1.Marshal(attribute{Type: oidMessageDigest, Values: asn1.RawValue{FullBytes: mdValues}})
	if err != nil {
		return nil, err
	}

	// IMPLICIT [0] over the concatenated attributes (SET OF Attribute).
	implicit, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        0,
		IsCompound: true,
		Bytes:      append(append([]byte{}, ctAttr...), mdAttr...),
	})
	if err != nil {
		return nil, err
	}
	return implicit, nil
}

// buildCertificatesField builds the SignedData certificates field: an IMPLICIT
// [0] CertificateSet (SET OF CertificateChoices) holding the KGA cert and chain.
func buildCertificatesField(kga *x509.Certificate, chain []*x509.Certificate) ([]byte, error) {
	var content []byte
	content = append(content, kga.Raw...)
	for _, c := range chain {
		if c != nil {
			content = append(content, c.Raw...)
		}
	}
	return asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        0,
		IsCompound: true,
		Bytes:      content,
	})
}

// encryptContent AES-256-CBC-encrypts plaintext under cek and returns the
// EncryptedContentInfo (contentType id-signedData, algorithm AES-256-CBC with
// the IV in parameters, and the ciphertext in the IMPLICIT [0] field).
func encryptContent(cek, plaintext []byte, contentType asn1.ObjectIdentifier) (encryptedContentInfo, error) {
	block, err := aes.NewCipher(cek)
	if err != nil {
		return encryptedContentInfo{}, fmt.Errorf("new AES cipher: %w", err)
	}
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return encryptedContentInfo{}, fmt.Errorf("generate IV: %w", err)
	}
	padded := pkcs7Pad(plaintext, aes.BlockSize)
	ciphertext := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, padded)

	ivParam, err := asn1.Marshal(iv) // AES-CBC parameters ::= OCTET STRING (the IV)
	if err != nil {
		return encryptedContentInfo{}, fmt.Errorf("marshal IV: %w", err)
	}
	return encryptedContentInfo{
		ContentType: contentType,
		ContentEncryptionAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm:  oidAES256CBC,
			Parameters: asn1.RawValue{FullBytes: ivParam},
		},
		EncryptedContent: ciphertext,
	}, nil
}

// pkcs7Pad applies PKCS#7 padding (RFC 5652 §6.3) to a multiple of blockSize.
func pkcs7Pad(data []byte, blockSize int) []byte {
	n := blockSize - (len(data) % blockSize)
	pad := make([]byte, n)
	for i := range pad {
		pad[i] = byte(n)
	}
	return append(data, pad...)
}

// randomBytes returns n cryptographically random bytes.
func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}
