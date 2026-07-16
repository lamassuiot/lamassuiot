package cmp

import (
	"context"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"fmt"

	"github.com/gin-gonic/gin"
	cmpwfx "github.com/lamassuiot/lamassuiot/backend/v3/pkg/integrations/wfx"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/sirupsen/logrus"
)

// This file implements the p10cr (4) operation — enrollment from a PKCS#10
// CertificationRequest (RFC 9483 §4.1.4 / RFC 4210 §5.3.1). It reuses the
// shared issuance pipeline (issueAndStore / deferForApproval) so p10cr gets
// duplicate-transactionID detection, implicit-confirm negotiation, phased
// (admin-gated) workflows, lost-response recovery via pollReq, and WFX state
// tracking exactly like ir/cr/kur. What differs from the CRMF bodies:
//
//   - The body is a real PKCS#10 CSR, not a CertReqMessages SEQUENCE, so it is
//     parsed with x509.ParseCertificateRequest instead of decodeFirstCertReq.
//   - There is no separate ProofOfPossession structure: the CSR's own
//     signature over its CertificationRequestInfo IS the POP, verified with
//     csr.CheckSignature() (mirroring RFC 9483 §4.1.4).
//   - A PKCS#10 request carries no certReqId, so the CertResponse — and the
//     EE's subsequent certConf — use the fixed value -1 (RFC 4210 Errata 8806).
//   - The response body is cp (3), the same as for cr.
//   - Central key generation (§4.1.6) does not apply: a p10cr always carries a
//     real self-signed request.

// p10crCertReqID is the certReqId used in the cp response to a p10cr request
// and expected in the EE's certConf. A PKCS#10 CertificationRequest has no
// certReqId field of its own, so RFC 4210 (Errata 8806) assigns the fixed
// value -1.
const p10crCertReqID = -1

// handleP10CR processes a p10cr (4) body.
func (r *cmpHttpRoutes) handleP10CR(ctx *gin.Context, lFunc *logrus.Entry, header requestPKIHeader, body asn1.RawValue, dmsID string, enrollOpts *models.EnrollmentOptionsLWCRFC9483) {
	const respTag = cmpBodyTagCP

	csrDER, err := p10crCSRDER(body.Bytes)
	if err != nil {
		lFunc.Errorf("p10cr: decode CertificationRequest: %v", err)
		r.rejectWithError(ctx, &header, PKIStatus(pkiStatusRejection),
			"malformed PKCS#10 CertificationRequest", dmsID, pkiFailureInfoBadDataFormat)
		return
	}

	// RSA key-size policy runs on the manually extracted SubjectPublicKeyInfo
	// BEFORE x509.ParseCertificateRequest: modern Go refuses to parse weak RSA
	// keys outright, which would misreport the policy violation as a decode
	// error (badDataFormat) instead of the badCertTemplate the CRMF bodies emit
	// for the same key.
	spkiDER := p10crSubjectPublicKeyInfo(csrDER)
	if rej := rejectWeakOrOversizedRSAKey(spkiDER, "p10cr", p10crCertReqID, lFunc); rej != nil {
		r.rejectCertRequest(ctx, lFunc, header, respTag, dmsID, rej)
		return
	}

	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		lFunc.Errorf("p10cr: parse CertificationRequest: %v", err)
		r.rejectWithError(ctx, &header, PKIStatus(pkiStatusRejection),
			"malformed PKCS#10 CertificationRequest", dmsID, pkiFailureInfoBadDataFormat)
		return
	}

	// A CSR whose signature algorithm the server cannot even identify (e.g. a
	// post-quantum scheme) is rejected with badAlg in an error body (RFC 9483
	// §3.5 / §3.6.4) — POP could not be attempted at all. Known-but-disallowed
	// algorithms (SHA-1 & co.) are POP policy failures instead, reported with
	// badPOP in a cp body by verifyP10CRPOP below.
	if csr.SignatureAlgorithm == x509.UnknownSignatureAlgorithm {
		lFunc.Warnf("p10cr: unrecognized CSR signature algorithm")
		r.rejectWithError(ctx, &header, PKIStatus(pkiStatusRejection),
			"unrecognized PKCS#10 signature algorithm (RFC 9481 §3)", dmsID, pkiFailureInfoBadAlg)
		return
	}

	// Proof of possession: the CSR self-signature (RFC 9483 §4.1.4). Verified
	// unconditionally — a PKCS#10 body without a valid signature is not a valid
	// request regardless of the DMS EnforcePOPO setting, and unlike CRMF there
	// is no "POPO absent" wire shape to tolerate.
	if rej := verifyP10CRPOP(csr); rej != nil {
		lFunc.Warnf("p10cr: POP verification failed: %s", rej.Reason)
		r.rejectCertRequest(ctx, lFunc, header, respTag, dmsID, rej)
		return
	}

	// Present the CSR through the same firstCertReq view the CRMF pipeline
	// uses so the CertTemplate policy checks (end-entity-only issuance) and
	// issueAndStore apply unchanged. x509.ParseCertificateRequest has already
	// lifted the PKCS#9 extensionRequest attribute into csr.Extensions.
	req := &firstCertReq{
		CertReqID:    p10crCertReqID,
		SubjectDER:   csr.RawSubject,
		PublicKeyDER: csr.RawSubjectPublicKeyInfo,
		Extensions:   csr.Extensions,
	}

	// RFC 9483 §4.1.1: a NULL-DN subject is only acceptable when a
	// SubjectAltName extension carries the identity — same rule as for the
	// CRMF CertTemplate subject.
	if isEmptySubjectDER(req.SubjectDER) && !hasSubjectAltNameExtension(req.Extensions) {
		r.rejectCertRequest(ctx, lFunc, header, respTag, dmsID, &certRequestRejection{
			CertReqID:   p10crCertReqID,
			Reason:      "subject is required in the PKCS#10 request unless a SubjectAltName extension is present (RFC 9483 §4.1.1)",
			FailInfoBit: pkiFailureInfoBadCertTemplate,
		})
		return
	}

	if rej := validateCertTemplatePolicy(req); rej != nil {
		lFunc.Warnf("p10cr: cert template policy rejected: %s", rej.Reason)
		r.rejectCertRequest(ctx, lFunc, header, respTag, dmsID, rej)
		return
	}

	wfxJobID := r.reportCMPState(ctx.Request.Context(), lFunc, cmpwfx.CMPTransition{
		TransactionID:     hex.EncodeToString(header.TransactionID),
		DMSID:             dmsID,
		RequestType:       cmpTagToString(cmpBodyTagP10CR),
		SubjectCommonName: csr.Subject.CommonName,
		State:             cmpwfx.CMPStateValidated,
		Metadata: map[string]any{
			"certReqId": p10crCertReqID,
		},
	})

	r.issueAndStore(ctx, lFunc, &header, req, dmsID, enrollOpts, issueParams{
		isReenrollment: false,
		requestTag:     cmpBodyTagP10CR,
		respTag:        respTag,
		wfxJobID:       wfxJobID,
		// Hand the REAL signed CSR to the service layer instead of a synthetic
		// one: the PKCS#10 signature is genuine, so downstream CSR-signature
		// verification (when enabled on the DMS) can succeed.
		presetCSR: csr,
		enroll: func(c context.Context, csr *x509.CertificateRequest) (*x509.Certificate, error) {
			return r.svc.LWCEnroll(c, csr, dmsID)
		},
	})
}

// p10crCSRDER returns the full DER TLV of the CertificationRequest carried in
// a p10cr body. The PKIBody CHOICE uses EXPLICIT tagging (RFC 4210 Appendix F
// module), so bodyBytes normally holds the complete CertificationRequest
// SEQUENCE TLV. An encoder that (incorrectly) tags the alternative IMPLICITly
// replaces the SEQUENCE tag with [4], leaving the bare field list; that case
// is detected by trailing data after the first TLV and repaired by re-wrapping
// the content in a UNIVERSAL SEQUENCE.
func p10crCSRDER(bodyBytes []byte) ([]byte, error) {
	var first asn1.RawValue
	rest, err := asn1.Unmarshal(bodyBytes, &first)
	if err != nil {
		return nil, fmt.Errorf("CertificationRequest: %w", err)
	}
	if first.Class != asn1.ClassUniversal || first.Tag != asn1.TagSequence {
		return nil, fmt.Errorf("CertificationRequest must start with a SEQUENCE, got class=%d tag=%d", first.Class, first.Tag)
	}
	if len(rest) > 0 {
		// IMPLICIT tagging: `first` is the CertificationRequestInfo and the
		// remainder is signatureAlgorithm + signature.
		return rewrapBodyAsSequence(bodyBytes)
	}
	return first.FullBytes, nil
}

// p10crSubjectPublicKeyInfo extracts the SubjectPublicKeyInfo TLV from a raw
// CertificationRequest DER without going through x509.ParseCertificateRequest
// (see the weak-RSA-key note in handleP10CR). Returns nil when the structure
// cannot be walked; the caller falls through to the full parse, which reports
// the malformation.
//
//	CertificationRequest    ::= SEQUENCE { certificationRequestInfo, ... }
//	CertificationRequestInfo ::= SEQUENCE {
//	    version       INTEGER,
//	    subject       Name,
//	    subjectPKInfo SubjectPublicKeyInfo, ... }
func p10crSubjectPublicKeyInfo(csrDER []byte) []byte {
	var outer asn1.RawValue
	if _, err := asn1.Unmarshal(csrDER, &outer); err != nil {
		return nil
	}
	var cri asn1.RawValue
	if _, err := asn1.Unmarshal(outer.Bytes, &cri); err != nil {
		return nil
	}
	rest := cri.Bytes
	var version, subject, spki asn1.RawValue
	var err error
	if rest, err = asn1.Unmarshal(rest, &version); err != nil {
		return nil
	}
	if rest, err = asn1.Unmarshal(rest, &subject); err != nil {
		return nil
	}
	if _, err = asn1.Unmarshal(rest, &spki); err != nil {
		return nil
	}
	return spki.FullBytes
}

// verifyP10CRPOP validates the PKCS#10 proof of possession: the requester's
// signature over the CertificationRequestInfo, verified against the public key
// the request itself carries. The signature algorithm is policy-gated first —
// crypto/x509 would happily verify a SHA-1 signature, but RFC 9481 §3
// (MSG_SIG_ALG) only permits SHA-256/384/512 with RSA/ECDSA and Ed25519.
func verifyP10CRPOP(csr *x509.CertificateRequest) *certRequestRejection {
	if !p10crSignatureAlgorithmAllowed(csr.SignatureAlgorithm) {
		return &certRequestRejection{
			CertReqID:   p10crCertReqID,
			Reason:      fmt.Sprintf("proof of possession verification failed: PKCS#10 signature algorithm %s is not permitted by RFC 9481 §3 (MSG_SIG_ALG)", csr.SignatureAlgorithm),
			FailInfoBit: pkiFailureInfoBadPOP,
		}
	}
	if err := csr.CheckSignature(); err != nil {
		return &certRequestRejection{
			CertReqID:   p10crCertReqID,
			Reason:      fmt.Sprintf("proof of possession verification failed: PKCS#10 self-signature invalid: %v", err),
			FailInfoBit: pkiFailureInfoBadPOP,
		}
	}
	return nil
}

// p10crSignatureAlgorithmAllowed reports whether alg is one of the signature
// algorithms RFC 9481 §3 permits. The set mirrors hashFromSignatureAlgOID /
// hashFromSignatureAlgID used on the CRMF POPO path (SHA-256/384/512 with
// RSA PKCS#1v1.5, RSA-PSS or ECDSA, plus Ed25519); SHA-1/SHA-224, MD5 and DSA
// are rejected.
func p10crSignatureAlgorithmAllowed(alg x509.SignatureAlgorithm) bool {
	switch alg {
	case x509.SHA256WithRSA, x509.SHA384WithRSA, x509.SHA512WithRSA,
		x509.SHA256WithRSAPSS, x509.SHA384WithRSAPSS, x509.SHA512WithRSAPSS,
		x509.ECDSAWithSHA256, x509.ECDSAWithSHA384, x509.ECDSAWithSHA512,
		x509.PureEd25519:
		return true
	default:
		return false
	}
}
