package cms

import (
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
)

// MarshalAsymmetricKeyPackage encodes key as an RFC 5958 AsymmetricKeyPackage
// (SEQUENCE OF OneAsymmetricKey) holding a single OneAsymmetricKey with
// version v2 (=1) and an explicit publicKey [1] field.
//
// Go's x509.MarshalPKCS8PrivateKey only ever emits OneAsymmetricKey version v1
// (=0) without the publicKey, which the RFC 9483 §4.1.6 compliance validator
// rejects ("version must be 1"). We therefore reuse the PKCS#8 encoding for the
// common fields (privateKeyAlgorithm, privateKey, optional attributes), bump
// the version to 1, and append publicKey [1] IMPLICIT BIT STRING taken from the
// SubjectPublicKeyInfo.
func MarshalAsymmetricKeyPackage(key crypto.Signer) ([]byte, error) {
	oneAsym, err := oneAsymmetricKeyV2(key)
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      oneAsym, // single OneAsymmetricKey
	})
}

// ParseAsymmetricKeyPackage parses an RFC 5958 AsymmetricKeyPackage carrying a
// single OneAsymmetricKey and returns the private key as a crypto.Signer. It
// accepts both v1 and v2 encodings (the trailing publicKey field, if present,
// is ignored — x509.ParsePKCS8PrivateKey reads only the fields it needs).
func ParseAsymmetricKeyPackage(der []byte) (crypto.Signer, error) {
	var keyPackage asn1.RawValue
	if rest, err := asn1.Unmarshal(der, &keyPackage); err != nil {
		return nil, fmt.Errorf("decode AsymmetricKeyPackage: %w", err)
	} else if len(rest) != 0 || keyPackage.Tag != asn1.TagSequence {
		return nil, fmt.Errorf("decode AsymmetricKeyPackage: invalid sequence")
	}
	var oneKey asn1.RawValue
	if rest, err := asn1.Unmarshal(keyPackage.Bytes, &oneKey); err != nil {
		return nil, fmt.Errorf("decode OneAsymmetricKey: %w", err)
	} else if len(rest) != 0 {
		return nil, fmt.Errorf("decode OneAsymmetricKey: %d trailing bytes", len(rest))
	}
	privateKey, err := x509.ParsePKCS8PrivateKey(oneKey.FullBytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	signer, ok := privateKey.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("private key type %T is not a crypto.Signer", privateKey)
	}
	return signer, nil
}

// oneAsymmetricKeyV2 encodes signer's private key as an RFC 5958
// OneAsymmetricKey with version v2 (=1) and an explicit publicKey [1] field.
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
