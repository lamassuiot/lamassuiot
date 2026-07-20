package cmp

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"time"
)

func DecodeRequestHeader(headerDER []byte) (RequestPKIHeader, error) {
	var seq asn1.RawValue
	if _, err := asn1.Unmarshal(headerDER, &seq); err != nil {
		return RequestPKIHeader{}, fmt.Errorf("PKIHeader: %w", err)
	}
	if seq.Class != asn1.ClassUniversal || seq.Tag != asn1.TagSequence {
		return RequestPKIHeader{}, fmt.Errorf("PKIHeader is not a SEQUENCE")
	}

	var header RequestPKIHeader
	remaining := seq.Bytes

	var pvnoRaw asn1.RawValue
	var err error
	remaining, err = asn1.Unmarshal(remaining, &pvnoRaw)
	if err != nil {
		return RequestPKIHeader{}, fmt.Errorf("pvno: %w", err)
	}
	if _, err := asn1.Unmarshal(pvnoRaw.FullBytes, &header.PVNO); err != nil {
		return RequestPKIHeader{}, fmt.Errorf("parse pvno: %w", err)
	}

	remaining, err = asn1.Unmarshal(remaining, &header.Sender)
	if err != nil {
		return RequestPKIHeader{}, fmt.Errorf("sender: %w", err)
	}

	remaining, err = asn1.Unmarshal(remaining, &header.Recipient)
	if err != nil {
		return RequestPKIHeader{}, fmt.Errorf("recipient: %w", err)
	}

	for len(remaining) > 0 {
		var field asn1.RawValue
		remaining, err = asn1.Unmarshal(remaining, &field)
		if err != nil {
			return RequestPKIHeader{}, fmt.Errorf("optional header field: %w", err)
		}
		if field.Class != asn1.ClassContextSpecific {
			continue
		}

		switch field.Tag {
		case 0:
			// messageTime [0] EXPLICIT GeneralizedTime OPTIONAL (RFC 9483 §3.1).
			// field.Bytes is the inner GeneralizedTime TLV.
			var ts time.Time
			if _, e := asn1.Unmarshal(field.Bytes, &ts); e == nil {
				header.MessageTime = ts
			}
		case 1:
			// protectionAlg [1] AlgorithmIdentifier OPTIONAL.
			// Per RFC 4210 IMPLICIT TAGS, the [1] tag replaces the SEQUENCE tag
			// of AlgorithmIdentifier; field.Bytes therefore holds the SEQUENCE
			// content (algorithm OID + optional parameters). For PSS the
			// Parameters carry the hash OID and saltLength, so we capture the
			// full AlgorithmIdentifier rather than just the OID.
			var algOID asn1.ObjectIdentifier
			rest, e := asn1.Unmarshal(field.Bytes, &algOID)
			if e != nil {
				// Fall back to the older "[1] EXPLICIT SEQUENCE" decoding
				// (i.e. an extra SEQUENCE wrapper around AlgorithmIdentifier)
				// for samples produced by OpenSSL-era clients.
				var algSeq asn1.RawValue
				if _, e2 := asn1.Unmarshal(field.Bytes, &algSeq); e2 == nil {
					rest2, e3 := asn1.Unmarshal(algSeq.Bytes, &algOID)
					if e3 == nil {
						header.ProtectionAlg.Algorithm = algOID
						if len(rest2) > 0 {
							var params asn1.RawValue
							if _, e4 := asn1.Unmarshal(rest2, &params); e4 == nil {
								header.ProtectionAlg.Parameters = params
							}
						}
					}
				}
			} else {
				header.ProtectionAlg.Algorithm = algOID
				if len(rest) > 0 {
					var params asn1.RawValue
					if _, e2 := asn1.Unmarshal(rest, &params); e2 == nil {
						header.ProtectionAlg.Parameters = params
					}
				}
			}
		case 2:
			// senderKID [2] OCTET STRING OPTIONAL (RFC 9483 §3.1).
			// The CMP ASN.1 module declares IMPLICIT TAGS, but OpenSSL-derived
			// clients (and this server's own response builder) emit the [2]
			// wrapper EXPLICITLY around the inner OCTET STRING TLV — matching
			// the same convention used for transactionID/senderNonce. We try
			// the EXPLICIT form first and fall back to the literal-IMPLICIT
			// form so we interoperate with both wire conventions.
			var kid []byte
			if _, e := asn1.Unmarshal(field.Bytes, &kid); e == nil {
				header.SenderKID = kid
			} else {
				header.SenderKID = field.Bytes
			}
		case 4:
			header.TransactionID, err = DecodeExplicitOctetString(field.Bytes, "transactionID")
		case 5:
			header.SenderNonce, err = DecodeExplicitOctetString(field.Bytes, "senderNonce")
		case 6:
			header.RecipNonce, err = DecodeExplicitOctetString(field.Bytes, "recipNonce")
		case 8:
			header.GeneralInfo, err = decodeGeneralInfo(field.Bytes)
		}
		if err != nil {
			return RequestPKIHeader{}, err
		}
	}

	return header, nil
}

// decodeGeneralInfo parses the content bytes of a [8] EXPLICIT generalInfo field.
// generalInfo is SEQUENCE SIZE (1..MAX) OF InfoTypeAndValue, where each
// InfoTypeAndValue is SEQUENCE { infoType OID, infoValue ANY OPTIONAL }.
// We return the raw InfoTypeAndValue entries for inspection.
func decodeGeneralInfo(bytes []byte) ([]asn1.RawValue, error) {
	// bytes is the content of [8] EXPLICIT, which is a SEQUENCE OF InfoTypeAndValue.
	var seq asn1.RawValue
	if _, err := asn1.Unmarshal(bytes, &seq); err != nil {
		return nil, fmt.Errorf("generalInfo SEQUENCE: %w", err)
	}
	var items []asn1.RawValue
	rest := seq.Bytes
	for len(rest) > 0 {
		var item asn1.RawValue
		var err error
		rest, err = asn1.Unmarshal(rest, &item)
		if err != nil {
			return nil, fmt.Errorf("generalInfo item: %w", err)
		}
		items = append(items, item)
	}
	return items, nil
}

// hasImplicitConfirmOID reports whether any InfoTypeAndValue in the given
// generalInfo slice carries the id-it-implicitConfirm OID (1.3.6.1.5.5.7.4.13).
func HasImplicitConfirmOID(generalInfo []asn1.RawValue) bool {
	for _, item := range generalInfo {
		// Each item is a SEQUENCE { OID, ... }; we extract just the OID.
		var oid asn1.ObjectIdentifier
		if _, err := asn1.Unmarshal(item.Bytes, &oid); err != nil {
			continue
		}
		if oid.Equal(oidImplicitConfirm) {
			return true
		}
	}
	return false
}

// extractOrigPKIMessage scans generalInfo for id-it-origPKIMessage
// (1.3.6.1.5.5.7.4.15) and, if present, returns the first embedded PKIMessage
// together with the protection AlgorithmIdentifier declared in its header.
//
// RFC 9483 §5.2.3 lets a PKI management entity (RA) forward the EE's original
// message to the CA under this OID. The value is OrigPKIMessageValue ::=
// PKIMessages (SEQUENCE OF PKIMessage); we return the first entry so the CA can
// verify the EE's own protection over what it actually signed. The boolean is
// false when no well-formed origPKIMessage is present.
func ExtractOrigPKIMessage(generalInfo []asn1.RawValue) (*RawPKIMessageFull, pkix.AlgorithmIdentifier, bool) {
	for _, item := range generalInfo {
		// item is InfoTypeAndValue ::= SEQUENCE { infoType OID, infoValue ANY OPTIONAL }.
		var itav struct {
			OID   asn1.ObjectIdentifier
			Value asn1.RawValue `asn1:"optional"`
		}
		if _, err := asn1.Unmarshal(item.FullBytes, &itav); err != nil {
			continue
		}
		if !itav.OID.Equal(oidOrigPKIMessage) || len(itav.Value.Bytes) == 0 {
			continue
		}
		// itav.Value is the PKIMessages SEQUENCE OF; its content bytes begin with
		// the first PKIMessage TLV, which Unmarshal decodes here.
		var orig RawPKIMessageFull
		if _, err := asn1.Unmarshal(itav.Value.Bytes, &orig); err != nil {
			continue
		}
		origHeader, err := DecodeRequestHeader(orig.Header.FullBytes)
		if err != nil {
			continue
		}
		return &orig, origHeader.ProtectionAlg, true
	}
	return nil, pkix.AlgorithmIdentifier{}, false
}

func DecodeExplicitOctetString(der []byte, label string) ([]byte, error) {
	var value []byte
	if _, err := asn1.Unmarshal(der, &value); err != nil {
		return nil, fmt.Errorf("%s: %w", label, err)
	}
	return value, nil
}

func DecodeCertConfStatuses(seqDER []byte) ([]CertStatus, error) {
	var outer asn1.RawValue
	if _, err := asn1.Unmarshal(seqDER, &outer); err != nil {
		return nil, fmt.Errorf("CertConfirmContent: %w", err)
	}
	if outer.Class != asn1.ClassUniversal || outer.Tag != asn1.TagSequence {
		return nil, fmt.Errorf("CertConfirmContent is not a SEQUENCE")
	}

	var statuses []CertStatus
	remaining := outer.Bytes
	for len(remaining) > 0 {
		var certStatusSeq asn1.RawValue
		var err error
		remaining, err = asn1.Unmarshal(remaining, &certStatusSeq)
		if err != nil {
			return nil, fmt.Errorf("CertStatus: %w", err)
		}
		if certStatusSeq.Class != asn1.ClassUniversal || certStatusSeq.Tag != asn1.TagSequence {
			return nil, fmt.Errorf("CertStatus is not a SEQUENCE")
		}

		var status CertStatus
		status.CertHash, err = FindFirstOctetString(certStatusSeq.FullBytes)
		if err != nil {
			return nil, fmt.Errorf("certHash: %w", err)
		}
		if len(status.CertHash) == 0 {
			return nil, fmt.Errorf("certHash missing")
		}

		parseCertStatusFields(certStatusSeq.Bytes, &status)

		statuses = append(statuses, status)
	}

	return statuses, nil
}

// parseCertStatusFields walks the fields of a CertStatus SEQUENCE content and
// fills CertReqID, StatusInfo and HashAlgOID on status.
//
//	CertStatus ::= SEQUENCE {
//	    certHash   OCTET STRING,
//	    certReqId  INTEGER,
//	    statusInfo PKIStatusInfo            OPTIONAL,
//	    hashAlg    [0] AlgorithmIdentifier  OPTIONAL }
func parseCertStatusFields(content []byte, status *CertStatus) {
	rest := content
	seenOctet := false
	for len(rest) > 0 {
		var field asn1.RawValue
		var err error
		rest, err = asn1.Unmarshal(rest, &field)
		if err != nil {
			return
		}
		switch {
		case field.Class == asn1.ClassContextSpecific && field.Tag == 0:
			// hashAlg [0] AlgorithmIdentifier. The CMP ASN.1 module uses
			// EXPLICIT tagging, so [0] wraps a full AlgorithmIdentifier
			// SEQUENCE { algorithm OID, parameters OPTIONAL }. Some encoders
			// emit it IMPLICIT (content starts directly with the OID). Handle
			// both: first try to decode an AlgorithmIdentifier SEQUENCE, then
			// fall back to a bare OID.
			var algID struct {
				Algorithm  asn1.ObjectIdentifier
				Parameters asn1.RawValue `asn1:"optional"`
			}
			if _, e := asn1.Unmarshal(field.Bytes, &algID); e == nil && len(algID.Algorithm) > 0 {
				status.HashAlgOID = algID.Algorithm
			} else {
				var oid asn1.ObjectIdentifier
				if _, e := asn1.Unmarshal(field.Bytes, &oid); e == nil {
					status.HashAlgOID = oid
				}
			}
		case field.Class == asn1.ClassUniversal && field.Tag == asn1.TagOctetString && !seenOctet:

			seenOctet = true
		case field.Class == asn1.ClassUniversal && field.Tag == asn1.TagInteger:
			var n int
			if _, e := asn1.Unmarshal(field.FullBytes, &n); e == nil {
				status.CertReqID = n
			}
		case field.Class == asn1.ClassUniversal && field.Tag == asn1.TagSequence:
			// statusInfo PKIStatusInfo
			var si PKIStatusInfo
			if _, e := asn1.Unmarshal(field.FullBytes, &si); e == nil {
				status.StatusInfo = si
			}
		}
	}
}

// extractHashAlgFromCertStatus scans the inner fields of a CertStatus SEQUENCE
// for the optional hashAlg [0] IMPLICIT AlgorithmIdentifier. Returns the
// algorithm OID if found, or nil when absent (caller should default to SHA-256).
func extractHashAlgFromCertStatus(content []byte) asn1.ObjectIdentifier {
	rest := content
	for len(rest) > 0 {
		var field asn1.RawValue
		var err error
		rest, err = asn1.Unmarshal(rest, &field)
		if err != nil {
			return nil
		}

		if field.Class == asn1.ClassContextSpecific && field.Tag == 0 {
			// Content is AlgorithmIdentifier: SEQUENCE { algorithm OID, ... }
			var oid asn1.ObjectIdentifier
			if _, e := asn1.Unmarshal(field.Bytes, &oid); e == nil {
				return oid
			}
			// Might be wrapped in SEQUENCE
			var inner asn1.RawValue
			if _, e := asn1.Unmarshal(field.Bytes, &inner); e == nil {
				if _, e2 := asn1.Unmarshal(inner.Bytes, &oid); e2 == nil {
					return oid
				}
			}
			return nil
		}
	}
	return nil
}

// maxOctetStringSearchDepth bounds findOctetStringInRaw's recursion. The
// structures this walks (CertStatus, PKIStatusInfo, ...) never legitimately
// nest more than a handful of levels deep; this input is fully attacker-
// controlled (certConf is unauthenticated at this point in parsing), so
// without a limit a pathologically nested SEQUENCE-of-SEQUENCE payload could
// recurse until it hits Go's stack limit and crashes the process with a
// non-recoverable fatal error.
const MaxOctetStringSearchDepth = 32

func FindFirstOctetString(der []byte) ([]byte, error) {
	var root asn1.RawValue
	if _, err := asn1.Unmarshal(der, &root); err != nil {
		return nil, err
	}
	return findOctetStringInRaw(root, 0)
}

func findOctetStringInRaw(rv asn1.RawValue, depth int) ([]byte, error) {
	if depth > MaxOctetStringSearchDepth {
		return nil, fmt.Errorf("ASN.1 structure nested too deeply (> %d levels)", MaxOctetStringSearchDepth)
	}
	if rv.Class == asn1.ClassUniversal && rv.Tag == asn1.TagOctetString {
		var out []byte
		if _, err := asn1.Unmarshal(rv.FullBytes, &out); err != nil {
			return nil, err
		}
		return out, nil
	}
	if !rv.IsCompound {
		return nil, nil
	}

	remaining := rv.Bytes
	for len(remaining) > 0 {
		var child asn1.RawValue
		var err error
		remaining, err = asn1.Unmarshal(remaining, &child)
		if err != nil {
			return nil, err
		}
		found, err := findOctetStringInRaw(child, depth+1)
		if err != nil {
			return nil, err
		}
		if len(found) > 0 {
			return found, nil
		}
	}
	return nil, nil
}

// buildSyntheticCSR constructs a *x509.CertificateRequest from the Subject and
// SubjectPublicKeyInfo carried in a CMP CertTemplate (RFC 4211 §5).
//
// Because POPO is handled at the CMP layer (not inside the CSR), the resulting
// CSR has a dummy 1-byte zero signature. Set VerifyCSRSignature=false in the
// DMS EnrollmentSettings when using CMP to bypass csr.CheckSignature().
func BuildSyntheticCSR(subjectDER, spkiDER []byte, extensions []pkix.Extension) (*x509.CertificateRequest, error) {

	pubKey, err := x509.ParsePKIXPublicKey(spkiDER)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}

	// Select a signature algorithm OID compatible with the key type.
	var sigAlgOID asn1.ObjectIdentifier
	switch pubKey.(type) {
	case *rsa.PublicKey:
		sigAlgOID = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	case *ecdsa.PublicKey:
		sigAlgOID = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	default:
		sigAlgOID = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	}

	attrsContent, err := marshalExtensionRequestAttrs(extensions)
	if err != nil {
		return nil, fmt.Errorf("marshal CSR attributes: %w", err)
	}
	attrsField, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: attrsContent,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal attrs field: %w", err)
	}
	type pkcs10CRI struct {
		Version int
		Subject asn1.RawValue
		SPKInfo asn1.RawValue
		Attrs   asn1.RawValue
	}
	criDER, err := asn1.Marshal(pkcs10CRI{
		Version: 0,
		Subject: asn1.RawValue{FullBytes: subjectDER},
		SPKInfo: asn1.RawValue{FullBytes: spkiDER},
		Attrs:   asn1.RawValue{FullBytes: attrsField},
	})
	if err != nil {
		return nil, fmt.Errorf("marshal CRI: %w", err)
	}

	sigAlgDER, err := asn1.Marshal(pkix.AlgorithmIdentifier{Algorithm: sigAlgOID})
	if err != nil {
		return nil, fmt.Errorf("marshal SigAlg: %w", err)
	}

	type pkcs10CSR struct {
		CRI    asn1.RawValue
		SigAlg asn1.RawValue
		Sig    asn1.BitString
	}
	csrDER, err := asn1.Marshal(pkcs10CSR{
		CRI:    asn1.RawValue{FullBytes: criDER},
		SigAlg: asn1.RawValue{FullBytes: sigAlgDER},
		Sig:    asn1.BitString{Bytes: []byte{0x00}, BitLength: 8},
	})
	if err != nil {
		return nil, fmt.Errorf("marshal CSR DER: %w", err)
	}

	return x509.ParseCertificateRequest(csrDER)
}

// oidExtensionRequest is the PKCS#9 extensionRequest attribute type
// (1.2.840.113549.1.9.14, RFC 2985 §5.4.2) used to carry requested X.509
// extensions inside a PKCS#10 CertificationRequest.
var oidExtensionRequest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 14}

// marshalExtensionRequestAttrs returns the DER content of a CSR's attributes
// SET OF Attribute. When exts is empty it returns nil (an empty attributes
// set). Otherwise it emits a single extensionRequest attribute whose value is
// the SEQUENCE OF Extension, so x509.ParseCertificateRequest surfaces them on
// CertificateRequest.Extensions and they persist through DER re-serialization.
func marshalExtensionRequestAttrs(exts []pkix.Extension) ([]byte, error) {
	if len(exts) == 0 {
		return nil, nil
	}

	extsSeqDER, err := asn1.Marshal(exts)
	if err != nil {
		return nil, fmt.Errorf("marshal extensions sequence: %w", err)
	}

	valuesSetDER, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: extsSeqDER,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal attribute values set: %w", err)
	}
	// Attribute ::= SEQUENCE { type OID, values SET OF AttributeValue }
	type pkcs10Attribute struct {
		Type   asn1.ObjectIdentifier
		Values asn1.RawValue
	}
	return asn1.Marshal(pkcs10Attribute{
		Type:   oidExtensionRequest,
		Values: asn1.RawValue{FullBytes: valuesSetDER},
	})
}
