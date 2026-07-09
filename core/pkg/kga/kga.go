// Package kga implements the RFC 9483 §4.1.6 "central key generation" (Key
// Generation Authority) response payload: the CMS structure that delivers a
// server-generated private key to the end-entity, confidentiality-protected.
//
// The delivered blob is an RFC 5652 EnvelopedData whose encrypted content is a
// SignedData (signed by the KGA) wrapping an RFC 5958 AsymmetricKeyPackage that
// carries the generated OneAsymmetricKey:
//
//	EnvelopedData {
//	    recipientInfos       — how the content-encryption key (CEK) reaches the EE:
//	                             ktri (RSA key transport) or kari (ECDH key agreement)
//	    encryptedContentInfo — AES-256-CBC( SignedData ) under the CEK
//	}
//	SignedData {
//	    eContentType   id-ct-KP-aKeyPackage
//	    eContent       AsymmetricKeyPackage( OneAsymmetricKey(genKey) )
//	    signerInfos    signed by the KGA certificate (id-kp-cmKGA EKU, a trust anchor)
//	}
//
// The package is deliberately free of any CMP/DMS coupling so it can be reused
// by any service that needs to hand back a centrally generated key. Callers
// supply the generated key, the recipient credential, and the KGA signer; the
// package returns the DER of the EnvelopedData to place in the protocol
// response (for CMP: CertifiedKeyPair.privateKey [envelopedData]).
package kga

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
)

// Technique is the CMS key-management technique used to deliver the CEK to the
// recipient. It is normally derived from the recipient credential's key type
// via TechniqueFor, not chosen by hand.
type Technique int

const (
	// TechniqueKTRI is RSA key transport (RFC 5652 §6.2.1): the CEK is
	// encrypted directly to the recipient's RSA public key.
	TechniqueKTRI Technique = iota
	// TechniqueKARI is ECDH key agreement (RFC 5652 §6.2.2): a shared secret is
	// derived against the recipient's EC public key, run through the ANSI-X9.63
	// KDF, and used to AES-key-wrap the CEK.
	TechniqueKARI
)

func (t Technique) String() string {
	switch t {
	case TechniqueKTRI:
		return "ktri"
	case TechniqueKARI:
		return "kari"
	default:
		return "unknown"
	}
}

// BuildInput carries everything needed to produce a KGA EnvelopedData.
type BuildInput struct {
	// GeneratedKey is the server-generated end-entity private key being
	// delivered (RSA or ECDSA). Its DER (PKCS#8) becomes the AsymmetricKeyPackage.
	GeneratedKey crypto.Signer

	// RecipientCert is the EE credential the CEK is protected to (in CMP, the
	// request's protection/signer certificate):
	//   - KTRI: the EE's RSA key-transport (keyEncipherment) certificate.
	//   - KARI: the EE's EC key-agreement (keyAgreement) certificate.
	// Its public key encrypts/derives the CEK and its issuerAndSerialNumber
	// identifies the recipient in the RecipientInfo.
	RecipientCert *x509.Certificate

	// KARIOriginatorKey is the KGA/RA static EC key-agreement private key used as
	// the CMS originator for KARI (its certificate is what the recipient runs
	// ECDH against). Required for KARI, ignored for KTRI.
	KARIOriginatorKey *ecdsa.PrivateKey
	// KARIOriginatorCert identifies the originator in the kari RecipientInfo and
	// MUST be the certificate the recipient sees as the response protection cert
	// (extraCerts[0]) so its ECDH derivation matches. Required for KARI.
	KARIOriginatorCert *x509.Certificate

	// KGACert is the KGA signing certificate (must carry the id-kp-cmKGA EKU and
	// chain to a trust anchor). It is embedded in SignedData.certificates and its
	// SubjectKeyId identifies the SignerInfo.
	KGACert *x509.Certificate
	// KGAChain are the intermediate/root certificates completing KGACert's chain;
	// they are included in SignedData.certificates so the recipient can validate
	// the KGA up to a trust anchor. May be empty.
	KGAChain []*x509.Certificate
	// KGASigner is the KGA certificate's private key, used to sign the SignedData.
	KGASigner crypto.Signer
}

// TechniqueFor selects the CMS key-management technique from a recipient public
// key: RSA → KTRI, ECDSA → KARI. Returns an error for unsupported key types.
func TechniqueFor(pub crypto.PublicKey) (Technique, error) {
	switch pub.(type) {
	case *rsa.PublicKey:
		return TechniqueKTRI, nil
	case *ecdsa.PublicKey:
		return TechniqueKARI, nil
	default:
		return 0, fmt.Errorf("kga: unsupported recipient key type %T (only RSA and ECDSA are supported)", pub)
	}
}

// BuildKeyPackage produces the DER of the EnvelopedData delivering in.GeneratedKey
// to the recipient, per RFC 9483 §4.1.6. The technique is derived from
// in.RecipientPublicKey.
func BuildKeyPackage(in BuildInput) ([]byte, error) {
	if in.GeneratedKey == nil {
		return nil, fmt.Errorf("kga: GeneratedKey is required")
	}
	if in.KGACert == nil || in.KGASigner == nil {
		return nil, fmt.Errorf("kga: KGACert and KGASigner are required")
	}
	if in.RecipientCert == nil {
		return nil, fmt.Errorf("kga: RecipientCert is required")
	}

	technique, err := TechniqueFor(in.RecipientCert.PublicKey)
	if err != nil {
		return nil, err
	}

	// 1. SignedData( AsymmetricKeyPackage(generatedKey) ), signed by the KGA.
	signedDataDER, err := buildSignedData(in)
	if err != nil {
		return nil, fmt.Errorf("kga: build SignedData: %w", err)
	}

	// 2. Fresh CEK + AES-256-CBC encryption of the SignedData.
	cek, err := randomBytes(contentEncryptionKeyLen)
	if err != nil {
		return nil, fmt.Errorf("kga: generate CEK: %w", err)
	}
	encContentInfo, err := encryptContent(cek, signedDataDER)
	if err != nil {
		return nil, fmt.Errorf("kga: encrypt content: %w", err)
	}

	// 3. RecipientInfo delivering the CEK.
	var recipInfoDER []byte
	var envVersion int
	switch technique {
	case TechniqueKTRI:
		recipInfoDER, err = buildKTRI(in.RecipientCert, cek)
		// ktri uses subjectKeyIdentifier rid (version 2) for SKI-bearing recipient
		// certs ⇒ EnvelopedData CMSVersion 2 (RFC 5652 §6.1). The RFC 9483 §4.1.6
		// validator also requires ktri version 2.
		envVersion = 2
	case TechniqueKARI:
		recipInfoDER, err = buildKARI(in, cek)
		envVersion = 2 // any kari present → CMSVersion 2
	}
	if err != nil {
		return nil, fmt.Errorf("kga: build %s recipientInfo: %w", technique, err)
	}

	// 4. EnvelopedData { recipientInfos SET OF, encryptedContentInfo }.
	recipInfosSet, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSet,
		IsCompound: true,
		Bytes:      recipInfoDER,
	})
	if err != nil {
		return nil, fmt.Errorf("kga: marshal recipientInfos: %w", err)
	}

	env := envelopedData{
		Version:              envVersion,
		RecipientInfos:       asn1.RawValue{FullBytes: recipInfosSet},
		EncryptedContentInfo: encContentInfo,
	}
	der, err := asn1.Marshal(env)
	if err != nil {
		return nil, fmt.Errorf("kga: marshal EnvelopedData: %w", err)
	}
	return der, nil
}

// signatureAlgorithmFor returns the CMS signature AlgorithmIdentifier matching
// the KGA signer's key type (SHA-256 based, as used for the digest).
func signatureAlgorithmFor(signer crypto.Signer) (pkix.AlgorithmIdentifier, error) {
	switch signer.Public().(type) {
	case *rsa.PublicKey:
		// RSA carries an explicit NULL parameter (RFC 4055 / RFC 3370).
		return pkix.AlgorithmIdentifier{Algorithm: oidSHA256WithRSA, Parameters: asn1.NullRawValue}, nil
	case *ecdsa.PublicKey:
		return pkix.AlgorithmIdentifier{Algorithm: oidECDSAWithSHA256}, nil
	default:
		return pkix.AlgorithmIdentifier{}, fmt.Errorf("kga: unsupported KGA signer key type %T", signer.Public())
	}
}
