package kga

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
)

// CMS / KGA object identifiers (RFC 5652, RFC 5958, RFC 5480, RFC 9481).
//
// These are the exact OIDs the RFC 9483 §4.1.6 compliance validator checks, so
// they are pinned here rather than pulled from x509 internals.
var (
	// oidSignedData / oidData are the CMS content types (RFC 5652 §3).
	oidSignedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidData       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}

	// oidContentType / oidMessageDigest are the two mandatory CMS signed
	// attributes (RFC 5652 §11.1/§11.2).
	oidContentType   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidMessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}

	// oidCTKPAKeyPackage is id-ct-KP-aKeyPackage (RFC 5958 §3): the eContentType
	// of the SignedData that carries the generated private key.
	oidCTKPAKeyPackage = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 2, 1, 2, 78, 5}

	// Digest and signature algorithms.
	oidSHA256            = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA256WithRSA     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	oidECDSAWithSHA256   = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidRSAEncryption     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidECPublicKey       = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}

	// Content and key-wrap symmetric algorithms.
	oidAES256CBC  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
	oidAES256Wrap = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 45}

	// oidDHSinglePassStdDHSHA256 is dhSinglePass-stdDH-sha256kdf-scheme
	// (RFC 9481 / SEC1): the KARI key-encryption algorithm — ephemeral-static
	// ECDH with the ANSI-X9.63 KDF (SHA-256), wrapping the CEK with AES-256-wrap.
	oidDHSinglePassStdDHSHA256 = asn1.ObjectIdentifier{1, 3, 132, 1, 11, 1}
)

// contentEncryptionKeyLen is the AES-256 CEK size used for the SignedData
// content encryption (RFC 9483 §4.1.6 mandates AES-CBC; we use AES-256).
const contentEncryptionKeyLen = 32

// --- RFC 5652 SignedData ----------------------------------------------------

// contentInfo is the outer CMS ContentInfo. Only used to wrap SignedData when a
// caller wants the full ContentInfo; the KGA envelope embeds the SignedData DER
// directly as the encrypted content, so this is retained for completeness.
type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,tag:0"`
}

type signedData struct {
	Version          int
	DigestAlgorithms []pkix.AlgorithmIdentifier `asn1:"set"`
	EncapContentInfo encapsulatedContentInfo
	Certificates     asn1.RawValue    `asn1:"optional,tag:0"`
	SignerInfos      []signerInfo     `asn1:"set"`
}

type encapsulatedContentInfo struct {
	EContentType asn1.ObjectIdentifier
	EContent     []byte `asn1:"explicit,optional,tag:0"`
}

type signerInfo struct {
	Version            int
	SID                asn1.RawValue // [0] subjectKeyIdentifier (RFC 5652 SignerIdentifier)
	DigestAlgorithm    pkix.AlgorithmIdentifier
	SignedAttrs        asn1.RawValue `asn1:"optional,tag:0"` // IMPLICIT [0] SET OF Attribute
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          []byte
}

// attribute is a CMS Attribute (RFC 5652 §5.3): SEQUENCE { attrType OID,
// attrValues SET OF AttributeValue }.
type attribute struct {
	Type   asn1.ObjectIdentifier
	Values asn1.RawValue // SET OF
}

// --- RFC 5652 EnvelopedData -------------------------------------------------

type envelopedData struct {
	Version              int
	RecipientInfos       asn1.RawValue // SET OF RecipientInfo (built manually to control CHOICE tagging)
	EncryptedContentInfo encryptedContentInfo
}

type encryptedContentInfo struct {
	ContentType                asn1.ObjectIdentifier
	ContentEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedContent           []byte `asn1:"optional,tag:0"` // IMPLICIT [0] OCTET STRING
}

// keyTransRecipientInfo is the ktri CHOICE member (RFC 5652 §6.2.1).
type keyTransRecipientInfo struct {
	Version int
	// RID is the RecipientIdentifier CHOICE, pre-marshalled: subjectKeyIdentifier
	// [0] (with Version 2) when the recipient cert has an SKI, otherwise an
	// issuerAndSerialNumber SEQUENCE (with Version 0). See recipientIdentifier.
	RID                    asn1.RawValue
	KeyEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedKey           []byte
}

// issuerAndSerialNumber (RFC 5652 §10.2.4).
type issuerAndSerialNumber struct {
	Issuer       asn1.RawValue
	SerialNumber *big.Int
}
