// Package revocation holds the X.509 codecs and rules that decide whether an OCSP response or a CRL proves that a
// certificate is not revoked (RFC 5280, RFC 6960).
//
// The package performs no I/O and is a leaf: it imports only the standard library and golang.org/x/crypto/ocsp,
// nothing from this repository. Fetching OCSP responses and CRLs and deciding what to do with their verdict belong to
// its callers.
package revocation

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
)

var (
	OIDExtensionDeltaCRLIndicator        = asn1.ObjectIdentifier{2, 5, 29, 27}
	OIDExtensionIssuingDistributionPoint = asn1.ObjectIdentifier{2, 5, 29, 28}
	OIDExtensionCRLDistributionPoints    = asn1.ObjectIdentifier{2, 5, 29, 31}
)

// DistributionPointName mirrors the DistributionPointName CHOICE of RFC 5280 4.2.1.13. Being a struct tagged [0] where
// it is used, it encodes the explicit tagging the CHOICE requires.
type DistributionPointName struct {
	FullName     []asn1.RawValue  `asn1:"optional,tag:0"`
	RelativeName pkix.RDNSequence `asn1:"optional,tag:1"`
}

// IssuingDistributionPoint mirrors the IssuingDistributionPoint extension of RFC 5280 5.2.5. Every field is optional,
// so that the DEFAULT FALSE booleans are left out when false, as DER requires (X.690 11.5).
type IssuingDistributionPoint struct {
	DistributionPoint          DistributionPointName `asn1:"optional,tag:0"`
	OnlyContainsUserCerts      bool                  `asn1:"optional,tag:1"`
	OnlyContainsCACerts        bool                  `asn1:"optional,tag:2"`
	OnlySomeReasons            asn1.BitString        `asn1:"optional,tag:3"`
	IndirectCRL                bool                  `asn1:"optional,tag:4"`
	OnlyContainsAttributeCerts bool                  `asn1:"optional,tag:5"`
}

// DistributionPoint mirrors a DistributionPoint of the CRL distribution points extension of RFC 5280 4.2.1.13.
// crypto/x509 only keeps its URIs, and drops the reasons it is limited to.
type DistributionPoint struct {
	DistributionPoint DistributionPointName `asn1:"optional,tag:0"`
	Reasons           asn1.BitString        `asn1:"optional,tag:1"`
	CRLIssuer         asn1.RawValue         `asn1:"optional,tag:2"`
}

// URIGeneralName returns uri as a GeneralName uniformResourceIdentifier, [6] IA5String.
func URIGeneralName(uri string) asn1.RawValue {
	return asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 6, Bytes: []byte(uri)}
}

// isURIGeneralName tells whether name is a GeneralName uniformResourceIdentifier, [6] IA5String.
func isURIGeneralName(name asn1.RawValue) bool {
	return name.Class == asn1.ClassContextSpecific && name.Tag == 6
}

// ParseIssuingDistributionPoint decodes the value of an IssuingDistributionPoint extension. encoding/asn1 leaves
// OnlySomeReasons.Bytes nil only when the field is absent.
func ParseIssuingDistributionPoint(der []byte) (IssuingDistributionPoint, error) {
	var idp IssuingDistributionPoint
	if rest, err := asn1.Unmarshal(der, &idp); err != nil || len(rest) > 0 {
		return IssuingDistributionPoint{}, fmt.Errorf("malformed issuing distribution point extension")
	}
	return idp, nil
}

// MarshalIssuingDistributionPoint encodes idp as the DER value of an IssuingDistributionPoint extension.
func MarshalIssuingDistributionPoint(idp IssuingDistributionPoint) ([]byte, error) {
	return asn1.Marshal(idp)
}

// ParseCRLDistributionPoints decodes the CRL distribution points extensions of cert.
func ParseCRLDistributionPoints(cert *x509.Certificate) ([]DistributionPoint, error) {
	var all []DistributionPoint
	for _, ext := range cert.Extensions {
		if !ext.Id.Equal(OIDExtensionCRLDistributionPoints) {
			continue
		}

		var dps []DistributionPoint
		if rest, err := asn1.Unmarshal(ext.Value, &dps); err != nil || len(rest) > 0 {
			return nil, fmt.Errorf("malformed CRL distribution points extension")
		}
		all = append(all, dps...)
	}
	return all, nil
}

// AllReasonsDistributionPoints returns the URIs of the CRL distribution points of cert that cover every revocation
// reason, that is, that have no reasons field (RFC 5280 4.2.1.13). A distribution point with one is left out
// whatever its bits, as RFC 5280 recommends against segmenting CRLs by reason.
func AllReasonsDistributionPoints(cert *x509.Certificate) ([]string, error) {
	dps, err := ParseCRLDistributionPoints(cert)
	if err != nil {
		return nil, err
	}

	var uris []string
	for _, dp := range dps {
		if dp.Reasons.Bytes != nil {
			continue
		}
		for _, name := range dp.DistributionPoint.FullName {
			if isURIGeneralName(name) {
				uris = append(uris, string(name.Bytes))
			}
		}
	}
	return uris, nil
}
