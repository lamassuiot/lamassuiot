package cmp

import (
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
)

// crlReasonRemoveFromCRL is the RFC 5280 §5.3.1 CRLReason value (8) that the
// CMP revive operation (RFC 9483 §4.2) reuses to request un-revocation.
const CRLReasonRemoveFromCRL = 8

// isKnownCRLReason reports whether code is a value defined by RFC 5280 §5.3.1.
// Value 7 is unused and any value ≥ 11 is out of range. removeFromCRL (8) is
// considered known because CMP uses it for revive requests.
func IsKnownCRLReason(code int) bool {
	switch code {
	case 0, 1, 2, 3, 4, 5, 6, 8, 9, 10:
		return true
	default:
		return false
	}
}

// revDetails holds the parsed fields of a single RevDetails entry (the
// CertTemplate plus its optional crlEntryDetails). The *DER fields are encoded
// so they can be DER-compared directly against the corresponding
// x509.Certificate.Raw* fields of the protection certificate.
type RevDetails struct {
	SerialNumber    []byte // big-endian, leading 0x00 sign byte stripped
	HasSerial       bool
	IssuerDER       []byte // Name TLV, comparable to x509.Certificate.RawIssuer
	HasIssuer       bool
	SubjectDER      []byte // Name TLV, comparable to x509.Certificate.RawSubject
	HasSubject      bool
	PublicKeyDER    []byte // SubjectPublicKeyInfo SEQUENCE TLV, comparable to RawSubjectPublicKeyInfo
	HasPublicKey    bool
	Reasons         []int // decoded CRLReason ENUMERATED values, in encounter order
	ReasonExtCount  int   // number of CRLReason extensions present
	ReasonDecodeErr bool  // at least one CRLReason extension value failed to decode
	Version         int   // X.509 Version enum: v1(0), v2(1), v3(2)
	HasVersion      bool
	Extensions      []pkix.Extension // CertTemplate extensions [9], when present
	HasExtensions   bool
}

// decodeRevDetails parses the first RevDetails entry of an rr body.
// RevReqContent ::= SEQUENCE OF RevDetails
//
//	RevDetails    ::= SEQUENCE {
//	    certDetails     CertTemplate,
//	    crlEntryDetails Extensions OPTIONAL }
//
//	CertTemplate ::= SEQUENCE {
//		    version      [0], serialNumber [1] INTEGER, signingAlg [2],
//		    issuer       [3] Name, validity [4], subject [5] Name,
//		    publicKey    [6] SubjectPublicKeyInfo, ..., extensions [9] }
//
// Per RFC 4211, Name (a CHOICE) is EXPLICITLY tagged so issuer [3] / subject [5]
// wrap a full Name TLV; SubjectPublicKeyInfo [6] is IMPLICITLY tagged so its
// SEQUENCE tag is replaced and must be re-wrapped before comparison.
func DecodeRevDetails(bodyBytes []byte) (*RevDetails, error) {
	rd := &RevDetails{}

	// bodyBytes is the content of [11] IMPLICIT — a SEQUENCE OF RevDetails TLV.
	var revDetailsSeq asn1.RawValue
	if _, err := asn1.Unmarshal(bodyBytes, &revDetailsSeq); err != nil {
		return nil, fmt.Errorf("RevReqContent: %w", err)
	}

	// First element is a RevDetails SEQUENCE.
	var revDet asn1.RawValue
	if _, err := asn1.Unmarshal(revDetailsSeq.Bytes, &revDet); err != nil {
		return nil, fmt.Errorf("RevDetails: %w", err)
	}

	// RevDetails.certDetails is a CertTemplate SEQUENCE; what follows is the
	// optional crlEntryDetails Extensions.
	var certTemplate asn1.RawValue
	crlExtRest, err := asn1.Unmarshal(revDet.Bytes, &certTemplate)
	if err != nil {
		return nil, fmt.Errorf("CertTemplate: %w", err)
	}

	remaining := certTemplate.Bytes
	for len(remaining) > 0 {
		var field asn1.RawValue
		remaining, err = asn1.Unmarshal(remaining, &field)
		if err != nil {
			return nil, fmt.Errorf("CertTemplate field: %w", err)
		}
		if field.Class != asn1.ClassContextSpecific {
			continue
		}
		switch field.Tag {
		case 0:
			verDER, e := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagInteger, Bytes: field.Bytes})
			var version int
			if e == nil {
				if _, e = asn1.Unmarshal(verDER, &version); e == nil {
					rd.Version = version
					rd.HasVersion = true
				}
			}
		case 1:
			sn := field.Bytes
			var inner asn1.RawValue
			if _, e := asn1.Unmarshal(field.Bytes, &inner); e == nil && inner.Tag == asn1.TagInteger {
				sn = inner.Bytes
			}

			if len(sn) > 1 && sn[0] == 0x00 {
				sn = sn[1:]
			}
			rd.SerialNumber = sn
			rd.HasSerial = len(sn) > 0
		case 3:
			rd.IssuerDER = field.Bytes
			rd.HasIssuer = true
		case 5:
			rd.SubjectDER = field.Bytes
			rd.HasSubject = true
		case 6:
			spki, e := asn1.Marshal(asn1.RawValue{
				Class:      asn1.ClassUniversal,
				Tag:        asn1.TagSequence,
				IsCompound: true,
				Bytes:      field.Bytes,
			})
			if e == nil {
				rd.PublicKeyDER = spki
				rd.HasPublicKey = true
			}
		case 9:
			rd.Extensions = parseCertTemplateExtensions(field.Bytes)
			rd.HasExtensions = true
		}
	}

	if len(crlExtRest) > 0 {
		rd.Reasons, rd.ReasonExtCount, rd.ReasonDecodeErr = collectCRLReasons(crlExtRest)
	}
	return rd, nil
}

// collectCRLReasons scans an Extensions SEQUENCE and returns every CRLReason
// (2.5.29.21) ENUMERATED value found, the count of CRLReason extensions, and a
// flag indicating that at least one extension's value could not be decoded.
func collectCRLReasons(der []byte) (reasons []int, count int, decodeErr bool) {
	var extsSeq asn1.RawValue
	if _, err := asn1.Unmarshal(der, &extsSeq); err != nil {
		return nil, 0, false
	}
	remaining := extsSeq.Bytes
	oidCRLReason := asn1.ObjectIdentifier{2, 5, 29, 21}
	for len(remaining) > 0 {
		var ext asn1.RawValue
		var err error
		remaining, err = asn1.Unmarshal(remaining, &ext)
		if err != nil {
			return reasons, count, decodeErr
		}
		var oid asn1.ObjectIdentifier
		extRest, err := asn1.Unmarshal(ext.Bytes, &oid)
		if err != nil || !oid.Equal(oidCRLReason) {
			continue
		}
		count++
		// Skip optional critical BOOLEAN to reach the OCTET STRING extnValue.
		var next asn1.RawValue
		extRest, err = asn1.Unmarshal(extRest, &next)
		if err != nil {
			decodeErr = true
			continue
		}
		var extnValue []byte
		if next.Tag == asn1.TagOctetString {
			extnValue = next.Bytes
		} else {
			var octet asn1.RawValue
			if _, e := asn1.Unmarshal(extRest, &octet); e != nil || octet.Tag != asn1.TagOctetString {
				decodeErr = true
				continue
			}
			extnValue = octet.Bytes
		}
		var reasonCode asn1.Enumerated
		if _, e := asn1.Unmarshal(extnValue, &reasonCode); e == nil {
			reasons = append(reasons, int(reasonCode))
		} else {
			decodeErr = true
		}
	}
	return reasons, count, decodeErr
}

// rewrapBodyAsSequence re-wraps the raw content bytes of an IMPLICIT-tagged
// body CHOICE (where the SEQUENCE outer tag was replaced by the CHOICE tag)
// back into a UNIVERSAL SEQUENCE so it can be decoded as
// []cmp.CertReqMessage.
func RewrapBodyAsSequence(bodyBytes []byte) ([]byte, error) {
	return asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      bodyBytes,
	})
}

// certHashSHA256 returns the SHA-256 digest of certDER.
// This is the default certHash algorithm for RSA/ECDSA certificates
// (RFC 9481 §2 / RFC 9480 §2.10).
func CertHashSHA256(certDER []byte) []byte {
	h := sha256.Sum256(certDER)
	return h[:]
}

// computeCertHash computes the certHash over certDER using the algorithm
// indicated by hashAlgOID. When hashAlgOID is nil/empty, the hash is chosen
// based on the issued certificate's signature algorithm per RFC 9481 §3.3:
//
//   - ECDSA-with-SHA384 / RSA-PSS-SHA384-issued → SHA-384
//   - ECDSA-with-SHA512 / RSA-PSS-SHA512-issued → SHA-512
//   - Ed25519-issued                            → SHA-512 (RFC 9481 §3.3
//     restricts EdDSA to a 512-bit certHash)
//   - everything else                           → SHA-256
//
// Per RFC 9481 §3 SHA-1 is deprecated for digital signatures and is no longer
// accepted, so we omit the id-sha1 OID branch.
//
// Supported hashAlg OIDs:
//   - 2.16.840.1.101.3.4.2.1  SHA-256
//   - 2.16.840.1.101.3.4.2.2  SHA-384
//   - 2.16.840.1.101.3.4.2.3  SHA-512
func ComputeCertHash(certDER []byte, hashAlgOID asn1.ObjectIdentifier) ([]byte, error) {
	if len(hashAlgOID) == 0 {
		return DefaultCertHash(certDER)
	}

	switch hashAlgOID.String() {
	case "2.16.840.1.101.3.4.2.1":
		h := sha256.Sum256(certDER)
		return h[:], nil
	case "2.16.840.1.101.3.4.2.2":
		h := sha512.Sum384(certDER)
		return h[:], nil
	case "2.16.840.1.101.3.4.2.3":
		h := sha512.Sum512(certDER)
		return h[:], nil
	default:
		return nil, fmt.Errorf("unsupported certHash algorithm OID %s", hashAlgOID)
	}
}

// defaultCertHash picks the certHash algorithm per RFC 9481 §3.3 when the
// CertStatus does not include an explicit hashAlg [0] field. The rule keys
// the digest off the certificate's own signatureAlgorithm so an EE that
// follows the defaulting rule for a SHA-384-signed ECDSA cert gets the same
// expected hash as the server.
func DefaultCertHash(certDER []byte) ([]byte, error) {
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {

		h := sha256.Sum256(certDER)
		return h[:], nil
	}

	switch cert.SignatureAlgorithm {
	case x509.ECDSAWithSHA384,
		x509.SHA384WithRSA,
		x509.SHA384WithRSAPSS:
		h := sha512.Sum384(certDER)
		return h[:], nil
	case x509.ECDSAWithSHA512,
		x509.SHA512WithRSA,
		x509.SHA512WithRSAPSS,
		x509.PureEd25519:
		h := sha512.Sum512(certDER)
		return h[:], nil
	default:
		h := sha256.Sum256(certDER)
		return h[:], nil
	}
}
