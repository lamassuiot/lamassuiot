package revocation

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"slices"
	"time"

	"golang.org/x/crypto/ocsp"
)

// CheckDelegatedResponder enforces RFC 6960 4.2.2.2 on the responder certificate embedded in resp, at now: the response
// must be signed with the key of issuer, or by a responder that issuer delegated to. Such a responder certificate must
// be issued by issuer, carry the id-kp-OCSPSigning EKU and be within its validity period. Being issued by issuer is not
// enough, since any end-entity certificate of that CA satisfies it, expired ones included.
//
// resp must be the result of ocsp.ParseResponse, unmodified. The parser verifies the signature over TBSResponseData
// against the embedded certificate and decodes Status, SerialNumber, ThisUpdate, NextUpdate and the other fields from
// those bytes. They are not decoded again here, so a change to them after parsing goes unnoticed. The signature is
// checked again only to bind resp.Certificate to TBSResponseData: replacing it, for instance by the issuer's
// certificate, cannot skip the checks below. A response without an embedded certificate is rejected: the caller checks
// its signature against issuer instead.
func CheckDelegatedResponder(resp *ocsp.Response, issuer *x509.Certificate, now time.Time) error {
	if resp == nil || issuer == nil {
		return fmt.Errorf("missing OCSP response or issuer")
	}

	responder := resp.Certificate
	if responder == nil {
		return fmt.Errorf("OCSP response embeds no responder certificate")
	}

	if err := resp.CheckSignatureFrom(responder); err != nil {
		return fmt.Errorf("bad OCSP signature: %w", err)
	}

	// Signed with the issuer's own key: the issuer embedded its certificate, no delegation is involved.
	if bytes.Equal(responder.RawSubjectPublicKeyInfo, issuer.RawSubjectPublicKeyInfo) {
		return nil
	}

	if err := issuer.CheckSignature(responder.SignatureAlgorithm, responder.RawTBSCertificate, responder.Signature); err != nil {
		return fmt.Errorf("OCSP response signed by %q, whose certificate was not issued by the issuer: %w", responder.Subject.CommonName, err)
	}

	if !slices.Contains(responder.ExtKeyUsage, x509.ExtKeyUsageOCSPSigning) {
		return fmt.Errorf("OCSP response signed by %q, which is not the issuer and is not authorized for OCSP signing", responder.Subject.CommonName)
	}

	if now.Before(responder.NotBefore) || now.After(responder.NotAfter) {
		return fmt.Errorf("OCSP response signed by %q, whose certificate is not valid at this time (valid from %s to %s)",
			responder.Subject.CommonName, responder.NotBefore.UTC().Format(time.RFC3339), responder.NotAfter.UTC().Format(time.RFC3339))
	}

	return nil
}
