package revocation

import (
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"slices"
	"time"
)

const (
	// ClockSkew tolerates small clock differences with OCSP responders and CRL issuers.
	ClockSkew = 5 * time.Minute
	// MaxAgeWithoutNextUpdate bounds the age of an OCSP response or CRL that omits nextUpdate, so an old "not revoked"
	// answer cannot be replayed indefinitely.
	MaxAgeWithoutNextUpdate = 24 * time.Hour
)

// CheckFreshness returns an error unless now falls within the validity window of an OCSP response or CRL. Callers only
// apply it to "not revoked" answers; a "revoked" answer is honored regardless of its age.
func CheckFreshness(thisUpdate, nextUpdate, now time.Time) error {
	if thisUpdate.IsZero() {
		return fmt.Errorf("missing thisUpdate")
	}

	if thisUpdate.After(now.Add(ClockSkew)) {
		return fmt.Errorf("thisUpdate %s is in the future", thisUpdate.UTC().Format(time.RFC3339))
	}

	if nextUpdate.IsZero() {
		if now.Sub(thisUpdate) > MaxAgeWithoutNextUpdate {
			return fmt.Errorf("no nextUpdate and thisUpdate %s is older than %s", thisUpdate.UTC().Format(time.RFC3339), MaxAgeWithoutNextUpdate)
		}
		return nil
	}

	if now.After(nextUpdate.Add(ClockSkew)) {
		return fmt.Errorf("nextUpdate %s has passed", nextUpdate.UTC().Format(time.RFC3339))
	}

	return nil
}

// CheckCRLScope returns an error unless the absence of cert from crl, downloaded from crlDP, proves it is not revoked.
// The caller must have verified the signature of crl against the issuer of cert.
//
// Delta CRLs only list changes since a base CRL, and an IssuingDistributionPoint may limit the CRL to CA or end-entity
// certificates, some revocation reasons, another issuer's certificates or another partition. The distribution point of
// cert may also limit the CRL to some reasons. Without this check, a validly signed CRL of narrower scope from the
// same CA could stand in for the complete one. A CRL must cover every reason on its own: unlike RFC 5280 6.3.3 (d),
// the reasons covered by several CRLs are not added up.
//
// As in RFC 5280 6.3.3 (b)(2)(i), a distribution point named by the CRL must be one of the CRL distribution points of
// cert, not necessarily the one the CRL was downloaded from: a certificate may list mirrors of the same CRL.
func CheckCRLScope(crl *x509.RevocationList, cert *x509.Certificate, crlDP string) error {
	allReasonsDPs, err := AllReasonsDistributionPoints(cert)
	if err != nil {
		return err
	}
	if !slices.Contains(allReasonsDPs, crlDP) {
		return fmt.Errorf("the CRL distribution point of the certificate only covers some revocation reasons")
	}

	for _, ext := range crl.Extensions {
		switch {
		case ext.Id.Equal(OIDExtensionDeltaCRLIndicator):
			return fmt.Errorf("delta CRL")
		case ext.Id.Equal(OIDExtensionIssuingDistributionPoint):
			idp, err := ParseIssuingDistributionPoint(ext.Value)
			if err != nil {
				return err
			}

			// A present onlySomeReasons restricts the CRL whatever its bits: with none set it covers no reason at all
			// (RFC 5280 5.2.5).
			if idp.OnlyContainsAttributeCerts || idp.IndirectCRL || idp.OnlySomeReasons.Bytes != nil {
				return fmt.Errorf("issuing distribution point restricts the CRL scope")
			}

			// RFC 5280 6.3.3 (b)(2)(ii) and (iii). IsCA is only set by a basic constraints extension asserting cA.
			if idp.OnlyContainsUserCerts && cert.IsCA {
				return fmt.Errorf("CRL only covers end-entity certificates and the certificate is a CA")
			}
			if idp.OnlyContainsCACerts && !cert.IsCA {
				return fmt.Errorf("CRL only covers CA certificates and the certificate is not a CA")
			}

			if len(idp.DistributionPoint.FullName) == 0 && len(idp.DistributionPoint.RelativeName) == 0 {
				continue
			}

			matchesURL := slices.ContainsFunc(idp.DistributionPoint.FullName, func(name asn1.RawValue) bool {
				return isURIGeneralName(name) && slices.Contains(allReasonsDPs, string(name.Bytes))
			})
			if !matchesURL {
				return fmt.Errorf("issuing distribution point does not match any CRL distribution point of the certificate covering every reason")
			}
		}
	}

	return nil
}
