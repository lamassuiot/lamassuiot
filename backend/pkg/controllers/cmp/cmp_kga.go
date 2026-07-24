// This file orchestrates the RFC 9483 §4.1.6 "central key generation" (Key
// Generation Authority) response: it assembles the CMS structure that delivers
// a server-generated private key to the end-entity, confidentiality-protected.
//
// The CMS wire format itself — EnvelopedData, SignedData, KTRI/KARI recipient
// info, RFC 3394 key wrap, the ANSI-X9.63 KDF, and the RFC 5958
// AsymmetricKeyPackage — lives in the shared core/pkg/cms package so the server
// (which builds these) and CMP clients (which open them) cannot drift apart.
// This file only maps CMP's KGA inputs onto that package's build API:
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
package cmp

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/asn1"
	"fmt"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/cms"
)

// kgaTechnique is the CMS key-management technique used to deliver the CEK to
// the recipient. It aliases cms.Technique so the backend's KGA policy branching
// (extraCerts ordering, KeyUsage validation) shares one definition with the CMS
// layer that actually implements each technique.
type kgaTechnique = cms.Technique

const (
	kgaTechniqueKTRI = cms.TechniqueKeyTransport
	kgaTechniqueKARI = cms.TechniqueKeyAgreement
)

// kgaTechniqueFor selects the CMS key-management technique from a recipient
// public key: RSA → KTRI, ECDSA → KARI.
func kgaTechniqueFor(pub crypto.PublicKey) (kgaTechnique, error) {
	return cms.TechniqueFor(pub)
}

// issuerAndSerialOverride carries the values for an issuerAndSerialNumber
// RecipientIdentifier CHOICE (RFC 5652 §6.2.1) when kgaBuildInput.RecipientRID
// overrides the default SubjectKeyIdentifier-based identifier. CMP's
// challenge-response proof of possession requires exactly this shape — a
// NULL-DN issuer with the certReqId as serialNumber (RFC 9810 §5.2.8.3.3) —
// because the recipient key is not yet certified, so no real issuer/serial
// exists. It aliases cms.IssuerAndSerial.
type issuerAndSerialOverride = cms.IssuerAndSerial

// kgaBuildInput carries everything needed to produce a KGA EnvelopedData.
type kgaBuildInput struct {
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

	// RecipientRID, when non-nil, overrides the RecipientInfo identifier with an
	// issuerAndSerialNumber CHOICE (see issuerAndSerialOverride).
	RecipientRID *issuerAndSerialOverride

	// KGACert is the KGA signing certificate (must carry the id-kp-cmKGA EKU and
	// chain to a trust anchor). It is embedded in SignedData.certificates and its
	// SubjectKeyId identifies the SignerInfo.
	KGACert *x509.Certificate
	// KGAChain are the intermediate/root certificates completing KGACert's chain.
	KGAChain []*x509.Certificate
	// KGASigner is the KGA certificate's private key, used to sign the SignedData.
	KGASigner crypto.Signer
}

// buildKGAKeyPackage produces the DER of the EnvelopedData delivering
// in.GeneratedKey to the recipient, per RFC 9483 §4.1.6.
func buildKGAKeyPackage(in kgaBuildInput) ([]byte, error) {
	if in.GeneratedKey == nil {
		return nil, fmt.Errorf("kga: GeneratedKey is required")
	}
	if in.KGACert == nil || in.KGASigner == nil {
		return nil, fmt.Errorf("kga: KGACert and KGASigner are required")
	}

	aKeyPackage, err := cms.MarshalAsymmetricKeyPackage(in.GeneratedKey)
	if err != nil {
		return nil, fmt.Errorf("kga: marshal AsymmetricKeyPackage: %w", err)
	}

	// SignedData( AsymmetricKeyPackage(generatedKey) ), signed by the KGA.
	signedDataDER, err := cms.BuildSignedData(cms.SignedDataInput{
		EContentType: cms.OIDKeyPackage(),
		EContent:     aKeyPackage,
		SignerCert:   in.KGACert,
		Chain:        in.KGAChain,
		Signer:       in.KGASigner,
	})
	if err != nil {
		return nil, fmt.Errorf("kga: build SignedData: %w", err)
	}
	return buildEnvelopedData(signedDataDER, cms.OIDSignedData(), in)
}

// buildEnvelopedData wraps content in a CMS EnvelopedData (RFC 5652) delivered
// to in.RecipientCert's public key via KTRI or KARI. It is the confidentiality-
// only primitive buildKGAKeyPackage layers a KGA SignedData atop; callers that
// need EnvelopedData around different content — e.g. a bare certificate for
// CMP's encrCert proof-of-possession (RFC 9483 §4.1.4) or the challenge nonce
// for encryptedRand — call it directly, passing the CMS content type that
// describes the content (id-data for arbitrary bytes; id-signedData for a
// SignedData).
func buildEnvelopedData(content []byte, contentType asn1.ObjectIdentifier, in kgaBuildInput) ([]byte, error) {
	return cms.BuildEnvelopedData(cms.EnvelopedDataInput{
		Content:             content,
		ContentType:         contentType,
		RecipientCert:       in.RecipientCert,
		OriginatorKey:       in.KARIOriginatorKey,
		OriginatorCert:      in.KARIOriginatorCert,
		RecipientIDOverride: in.RecipientRID,
	})
}
