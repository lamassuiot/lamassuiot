package cms

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
)

// This file holds the RFC 5652 (CMS) ASN.1 SEQUENCE definitions shared by the
// encoder (build.go) and decoder (decode.go). Keeping one set of struct
// definitions guarantees the two sides agree byte-for-byte on the wire shape.

// contentEncryptionKeyLen is the AES-256 content-encryption-key size. RFC 9483
// §4.1.6 mandates AES-CBC content encryption; this package uses AES-256.
const contentEncryptionKeyLen = 32

// --- RFC 5652 SignedData ----------------------------------------------------

// contentInfo is the outer CMS ContentInfo (RFC 5652 §3). Retained for callers
// that need a full ContentInfo wrapper; the enveloped-data flow embeds the
// SignedData DER directly as the encrypted content.
type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,tag:0"`
}

type signedData struct {
	Version          int
	DigestAlgorithms []pkix.AlgorithmIdentifier `asn1:"set"`
	EncapContentInfo encapsulatedContentInfo
	Certificates     asn1.RawValue `asn1:"optional,tag:0"`
	SignerInfos      []signerInfo  `asn1:"set"`
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
	// issuerAndSerialNumber SEQUENCE (with Version 0).
	RID                    asn1.RawValue
	KeyEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedKey           []byte
}

// keyAgreeRecipientInfo is the kari CHOICE member (RFC 5652 §6.2.2). It is
// marshalled as a plain SEQUENCE and then re-tagged IMPLICIT [1] by the builder.
type keyAgreeRecipientInfo struct {
	Version int
	// Originator is the [0] EXPLICIT OriginatorIdentifierOrKey, pre-wrapped
	// verbatim (a RawValue with FullBytes bypasses struct-tag tagging, so the
	// [0] EXPLICIT wrapper is applied by hand in the builder).
	Originator             asn1.RawValue
	KeyEncryptionAlgorithm pkix.AlgorithmIdentifier
	RecipientEncryptedKeys []recipientEncryptedKey
}

type recipientEncryptedKey struct {
	// RID is the KeyAgreeRecipientIdentifier CHOICE, pre-marshalled.
	RID          asn1.RawValue
	EncryptedKey []byte
}

// issuerAndSerialNumber (RFC 5652 §10.2.4).
type issuerAndSerialNumber struct {
	Issuer       asn1.RawValue
	SerialNumber *big.Int
}

// rsaesOAEPParams is RSAES-OAEP-params (RFC 8017 Appendix A.2.1 / RFC 4055
// §4.1) — the id-RSAES-OAEP AlgorithmIdentifier.parameters payload. hashFunc
// and maskGenFunc are explicit here because SHA-256 (not the SHA-1 defaults
// implied by omitting them) is used; pSourceFunc is left absent to take its
// default (pSpecifiedEmpty, an empty label), matching the empty label passed
// to rsa.EncryptOAEP / rsa.DecryptOAEP.
type rsaesOAEPParams struct {
	HashFunc    pkix.AlgorithmIdentifier `asn1:"explicit,tag:0"`
	MaskGenFunc pkix.AlgorithmIdentifier `asn1:"explicit,tag:1"`
}

// IssuerAndSerial carries the values for an issuerAndSerialNumber
// RecipientIdentifier CHOICE (RFC 5652 §6.2.1) when a caller overrides the
// default SubjectKeyIdentifier-based identifier. IssuerDER is a pre-encoded
// X.501 Name TLV (a NULL-DN is the two-byte empty RDNSequence).
//
// CMP's challenge-response proof of possession requires exactly this shape — a
// NULL-DN issuer with the certReqId as serialNumber (RFC 9810 §5.2.8.3.3) —
// because the recipient key is not yet certified, so no real issuer/serial exists.
type IssuerAndSerial struct {
	IssuerDER []byte
	Serial    *big.Int
}

// reTag rewrites the outer tag of a single DER TLV to (class, tag), preserving
// its content and constructed bit. Used to turn a marshalled SEQUENCE into an
// IMPLICIT context-tagged value.
func reTag(der []byte, class, tag int) ([]byte, error) {
	var rv asn1.RawValue
	if _, err := asn1.Unmarshal(der, &rv); err != nil {
		return nil, err
	}
	return asn1.Marshal(asn1.RawValue{
		Class:      class,
		Tag:        tag,
		IsCompound: rv.IsCompound,
		Bytes:      rv.Bytes,
	})
}
