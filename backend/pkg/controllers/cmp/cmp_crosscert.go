package cmp

import (
	"context"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/gin-gonic/gin"
	cmpwfx "github.com/lamassuiot/lamassuiot/backend/v3/pkg/integrations/wfx"
	corecmp "github.com/lamassuiot/lamassuiot/core/v3/pkg/cmp"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/errs"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	"github.com/sirupsen/logrus"
)

// This file implements the CMP cross-certification operation (ccr/ccp,
// RFC 4210bis §5.3.11 / Appendix D.6). A CA sends a ccr — a CertReqMessages body
// (tag 13) — asking the recipient CA to issue a cross-certificate for the key
// and identity described by the request CertTemplate. The response is a ccp body
// (tag 14), a CertRepMessage identical in shape to cp/ip/kup.
//
// Authorization: a ccr may only be sent by a CA (RFC 4210bis §5.3.11), so the
// message-protection (signer) certificate MUST be a CA certificate; an
// end-entity certificate is rejected as notAuthorized.

// crossCertTemplateInfo records which fields the ccr CertTemplate carried and
// the requested X.509 version, so the handler can enforce the RFC 4210bis
// Appendix D.6 presence and version requirements before issuance.
type crossCertTemplateInfo struct {
	hasVersion    bool
	version       int // X.509 version value: v1=0, v2=1, v3=2
	hasSigningAlg bool
	hasIssuer     bool
	hasValidity   bool
	hasSubject    bool
	hasPublicKey  bool
	// notBefore / notAfter carry the requested validity bounds parsed from the
	// CertTemplate validity field (nil when absent or unparseable).
	notBefore *time.Time
	notAfter  *time.Time
}

// handleCrossCertification processes a ccr (13) body and answers with a ccp (14).
func (r *cmpHttpRoutes) handleCrossCertification(ctx *gin.Context, lFunc *logrus.Entry, header corecmp.RequestPKIHeader, body asn1.RawValue, dmsID string, enrollOpts *models.CMPEnrollmentSettings, signerCert *x509.Certificate) {
	lFunc = lFunc.WithField("op", "ccr")
	const respTag = corecmp.BodyTagCCP

	// RFC 4210bis §5.3.11: cross-certification requests are exchanged between
	// CAs. The requester authenticates via message-protection, so a signer
	// certificate is always required. Whether that signer MUST additionally be a
	// CA certificate is governed by CCR.RequireCACertificate (RFC011); it
	// defaults on. The error is delivered in an error body (the suite expects
	// `error` here).
	signer := signerCert
	if signer == nil {
		lFunc.Warnf("ccr rejected: requester presented no signer certificate")
		r.rejectWithError(ctx, &header, corecmp.PKIStatus(corecmp.PKIStatusRejection),
			"cross-certification requests must be signature-protected (RFC 4210bis §5.3.11)",
			dmsID, corecmp.PKIFailureInfoNotAuthorized)
		return
	}
	if enrollOpts.CCR.RequireCACertificate && !signer.IsCA {
		lFunc.Warnf("ccr rejected: requester is not a CA")
		r.rejectWithError(ctx, &header, corecmp.PKIStatus(corecmp.PKIStatusRejection),
			"cross-certification requests may only be sent by a CA (RFC 4210bis §5.3.11)",
			dmsID, corecmp.PKIFailureInfoNotAuthorized)
		return
	}
	// RFC011 CCR.TrustedRequesterCAIDs: an empty list is unrestricted (any CA
	// satisfying the check above may request); a non-empty list additionally
	// requires the signer to chain to one of the listed CAs.
	if validator, ok := r.svc.(services.LightweightCMPCrossCertRequesterValidator); ok {
		if vErr := validator.LWCValidateCCRRequester(ctx.Request.Context(), dmsID, signer); vErr != nil {
			lFunc.Warnf("ccr rejected: requester is not a trusted CA for this DMS: %v", vErr)
			r.rejectWithError(ctx, &header, corecmp.PKIStatus(corecmp.PKIStatusRejection),
				"requester is not a trusted CA for cross-certification with this DMS",
				dmsID, corecmp.PKIFailureInfoNotAuthorized)
			return
		}
	}

	req, err := corecmp.DecodeFirstCertReq(body.Bytes)
	if err != nil {
		var certRej *corecmp.CertRequestRejection
		if ok := asErrCertRequestRejection(err, &certRej); ok {
			r.rejectCertRequest(ctx, lFunc, header, respTag, dmsID, certRej)
		} else {
			lFunc.Errorf("ccr decode: %v", err)
			r.rejectWithError(ctx, &header, corecmp.PKIStatus(corecmp.PKIStatusRejection), "malformed ccr", dmsID, corecmp.PKIFailureInfoBadDataFormat)
		}
		return
	}

	// A ccr that omits the public key (asking the CA to generate the key) is not
	// permitted: the requesting CA's private key MUST NOT be disclosed
	// (RFC 4210bis §5.3.11). This is a proof-of-possession failure combined with
	// a malformed request → badPOP + badRequest, delivered as an error body.
	if req.ForKGA {
		lFunc.Warnf("ccr rejected: central key generation is not allowed for cross-certification")
		r.rejectWithError(ctx, &header, corecmp.PKIStatus(corecmp.PKIStatusRejection),
			"cross-certification must not request central key generation (RFC 4210bis §5.3.11)",
			dmsID, corecmp.PKIFailureInfoBadPOP, corecmp.PKIFailureInfoBadRequest)
		return
	}

	// An EncryptedKey POPO ([2] keyEncipherment / [3] keyAgreement) carries the
	// requester's private key to the CA — the same MUST NOT as the ForKGA case
	// above (RFC 4210bis §5.3.11). Screened BEFORE CertTemplate validation so a
	// request that violates both rules surfaces the graver key-disclosure error
	// rather than a template-completeness nit.
	if req.POPORaw.Class == asn1.ClassContextSpecific && (req.POPORaw.Tag == 2 || req.POPORaw.Tag == 3) {
		lFunc.Warnf("ccr rejected: EncryptedKey POPO discloses a private key")
		r.rejectCertRequest(ctx, lFunc, header, respTag, dmsID, &corecmp.CertRequestRejection{
			CertReqID:   req.CertReqID,
			Reason:      "cross-certification must not disclose a private key (RFC 4210bis §5.3.11)",
			FailInfoBit: corecmp.PKIFailureInfoBadRequest,
		})
		return
	}

	// CertTemplate presence/version checks (RFC 4210bis Appendix D.6).
	tmpl := parseCrossCertTemplate(body.Bytes)
	if rej := validateCrossCertTemplate(req.CertReqID, tmpl); rej != nil {
		lFunc.Warnf("ccr template rejected: %s", rej.Reason)
		r.rejectCertRequest(ctx, lFunc, header, respTag, dmsID, rej)
		return
	}

	// The template key MUST be usable for signing: a cross-certificate certifies
	// another CA, whose key signs certificates. A key-agreement-only algorithm
	// (X25519 / X448) cannot sign and also cannot furnish a POPOSigningKey, so it
	// is rejected as badCertTemplate + badAlg (RFC 4210bis §5.3.11).
	if isNonSigningKeyAlgorithm(req.PublicKeyDER) {
		lFunc.Warnf("ccr rejected: CertTemplate key algorithm cannot sign")
		r.rejectWithError(ctx, &header, corecmp.PKIStatus(corecmp.PKIStatusRejection),
			"cross-certification requires a signing-capable key in the CertTemplate (RFC 4210bis §5.3.11)",
			dmsID, corecmp.PKIFailureInfoBadCertTemplate, corecmp.PKIFailureInfoBadAlg)
		return
	}

	// Proof of possession. When CCR.RequireProofOfPossession is set (the
	// default, RFC011) the requester MUST prove control of the template key with
	// a POPOSigningKey; an absent POPO is badPOP. (EncryptedKey POPOs were
	// already screened out before template validation above, unconditionally,
	// since they disclose a private key.)
	if enrollOpts.CCR.RequireProofOfPossession {
		switch req.POPORaw.Tag {
		case 1: // signature (POPOSigningKey) — the only acceptable form.
		default: // absent or raVerified — no proof of possession.
			lFunc.Warnf("ccr rejected: missing POPOSigningKey")
			r.rejectWithError(ctx, &header, corecmp.PKIStatus(corecmp.PKIStatusRejection),
				"cross-certification requires a POPOSigningKey proof of possession (RFC 4210bis §5.3.11)",
				dmsID, corecmp.PKIFailureInfoBadPOP)
			return
		}
	}

	// The tag check above establishes only that a POPOSigningKey is *present* —
	// it says nothing about whether the signature inside it is valid. Verify it
	// cryptographically against the CertTemplate's declared public key, exactly
	// as the ir/cr path does (cmp_enrollment.go) — otherwise a requester could
	// cross-certify a key it does not control by sending a POPOSigningKey with
	// garbage signature bytes. BuildSyntheticCSR below fills the CSR signature
	// with a dummy value, so no downstream check would catch it either.
	//
	// Deliberately NOT gated on RequireProofOfPossession: that setting governs
	// whether an ABSENT POPO is tolerated, not whether a supplied one may be
	// ignored (same rationale as verifyPOPO's default branch). A present-but-
	// invalid signature is always badPOP. Passing enforce=false keeps the
	// absent-POPO decision with the check above, whose error text and RFC
	// citation are CCR-specific.
	if req.POPORaw.Class == asn1.ClassContextSpecific && req.POPORaw.Tag == 1 {
		if err := verifyPOPO(req.CertReqDER, req.POPORaw, req.PublicKeyDER, false); err != nil {
			lFunc.Warnf("ccr rejected: POPO verification failed: %v", err)
			r.rejectWithError(ctx, &header, corecmp.PKIStatus(corecmp.PKIStatusRejection),
				fmt.Sprintf("cross-certification proof of possession verification failed: %v", err),
				dmsID, corecmp.PKIFailureInfoBadPOP)
			return
		}
	}

	crossCertifier, ok := r.svc.(services.LightweightCMPCrossCertifier)
	if !ok {
		lFunc.Errorf("ccr: service does not implement LightweightCMPCrossCertifier")
		r.rejectWithError(ctx, &header, corecmp.PKIStatus(2), "cross-certification not supported", dmsID, corecmp.PKIFailureInfoSystemFailure)
		return
	}

	csr, err := corecmp.BuildSyntheticCSR(req.SubjectDER, req.PublicKeyDER, req.Extensions)
	if err != nil {
		lFunc.Errorf("ccr: build synthetic CSR: %v", err)
		r.rejectCertRequest(ctx, lFunc, header, respTag, dmsID, &corecmp.CertRequestRejection{
			CertReqID:   req.CertReqID,
			Reason:      "cannot build CSR from CertTemplate",
			FailInfoBit: corecmp.PKIFailureInfoBadCertTemplate,
		})
		return
	}

	// RFC011: CCR.Workflow=administrator_approval treats cross-certification —
	// one CA vouching for another — as a privileged operation requiring a human
	// in the loop, mirroring ir/cr's phased workflow (deferForApproval) but
	// keyed on this operation's own setting rather than the general
	// CMPEnrollmentSettings.Workflow.
	if enrollOpts.CCR.Workflow == models.CMPCCRWorkflowAdministratorApproval {
		r.deferCCRForApproval(ctx, lFunc, &header, req, csr, dmsID, enrollOpts, respTag)
		return
	}

	issuanceCtx := context.WithoutCancel(ctx.Request.Context())
	crossCert, _, err := crossCertifier.LWCIssueCrossCertificate(issuanceCtx, dmsID, csr, tmpl.notBefore, tmpl.notAfter)
	if err != nil {
		lFunc.Errorf("ccr: issue cross certificate: %v", err)
		r.rejectCertRequest(ctx, lFunc, header, respTag, dmsID, &corecmp.CertRequestRejection{
			CertReqID:   req.CertReqID,
			Reason:      err.Error(),
			FailInfoBit: corecmp.PKIFailureInfoSystemFailure,
		})
		return
	}

	bodyDER, err := corecmp.MarshalCertRepBodyWithStatus(respTag, req.CertReqID, int(corecmp.PKIStatus(0)), crossCert.Raw)
	if err != nil {
		lFunc.Errorf("ccr: marshal ccp body: %v", err)
		r.rejectWithError(ctx, &header, corecmp.PKIStatus(2), "cannot build response", dmsID, corecmp.PKIFailureInfoSystemFailure)
		return
	}
	lFunc.Infof("ccr: issued cross certificate SN=%s for subject CN=%s",
		hex.EncodeToString(crossCert.SerialNumber.Bytes()), csr.Subject.CommonName)
	r.sendRawBody(ctx, lFunc, header, respTag, bodyDER, dmsID)
}

// deferCCRForApproval implements CCR.Workflow=administrator_approval: it
// persists the request as a PENDING transaction (RequestType "ccr") and
// returns a CMP "waiting" ccp response, mirroring cmp_enrollment.go's
// deferForApproval for ir/cr/kur. An administrator later calls
// ApproveCMPTransaction, which issues the cross-certificate via
// LWCIssueCrossCertificate; the requesting CA retrieves it via pollReq.
//
// The requested validity window (tmpl.notBefore/notAfter) is NOT persisted —
// admin-approved ccr issuance falls back to the DMS's configured
// CCR.MaximumValidity/profile default, since CMPTransaction has no field for
// it and administrator review is expected to re-derive validity from policy
// rather than trust the pre-approval request verbatim.
func (r *cmpHttpRoutes) deferCCRForApproval(
	ctx *gin.Context,
	lFunc *logrus.Entry,
	header *corecmp.RequestPKIHeader,
	req *corecmp.CertRequest,
	csr *x509.CertificateRequest,
	dmsID string,
	enrollOpts *models.CMPEnrollmentSettings,
	respTag int,
) {
	header.ResponseImplicitConfirm = false

	txHex := hex.EncodeToString(header.TransactionID)
	storeCtx := context.WithoutCancel(ctx.Request.Context())
	if storeErr := r.store.Insert(storeCtx, models.CMPTransaction{
		TransactionID:     txHex,
		DMSID:             dmsID,
		State:             models.CMPTransactionStatePending,
		CSR:               (*models.X509CertificateRequest)(csr),
		RequestType:       cmpTagToString(corecmp.BodyTagCCR),
		SubjectCommonName: csr.Subject.CommonName,
		ReceivedNonce:     hex.EncodeToString(header.SenderNonce),
		ExpiresAt:         time.Now().Add(approvalTimeoutOrDefault(enrollOpts.ApprovalTimeout)),
		CreatedAt:         time.Now(),
	}); storeErr != nil {
		if errors.Is(storeErr, errs.ErrCMPTransactionAlreadyExists) {
			lFunc.Warnf("ccr: duplicate transactionID %s", txHex)
			r.rejectWithError(ctx, header, corecmp.PKIStatus(2), "transactionID already in use", dmsID, corecmp.PKIFailureInfoTransactionIDInUse)
			return
		}
		lFunc.Errorf("ccr: store PENDING transaction: %v", storeErr)
		r.rejectWithError(ctx, header, corecmp.PKIStatus(2), "internal error", dmsID, corecmp.PKIFailureInfoSystemFailure)
		return
	}

	waitingDER, err := corecmp.MarshalCertRepWaitingBody(req.CertReqID)
	if err != nil {
		lFunc.Errorf("ccr: build waiting cert rep body: %v", err)
		r.rejectWithError(ctx, header, corecmp.PKIStatus(2), "cannot build response", dmsID, corecmp.PKIFailureInfoSystemFailure)
		return
	}
	responseDER := r.sendRawBody(ctx, lFunc, *header, respTag, waitingDER, dmsID)
	if len(responseDER) == 0 {
		return
	}
	lFunc.Infof("ccr: administrator_approval workflow: tx %s parked awaiting admin approval, returned waiting response", txHex)
	r.reportCMPState(ctx.Request.Context(), lFunc, cmpwfx.CMPTransition{
		TransactionID:     txHex,
		DMSID:             dmsID,
		RequestType:       cmpTagToString(corecmp.BodyTagCCR),
		SubjectCommonName: csr.Subject.CommonName,
		State:             cmpwfx.CMPStateAwaitingApproval,
		Metadata: withCMPMessageB64(map[string]any{
			"certReqId":    req.CertReqID,
			"responseType": cmpTagToString(respTag),
		}, cmpMetadataResponseB64, responseDER),
	})
}

// validateCrossCertTemplate enforces the RFC 4210bis Appendix D.6 CertTemplate
// requirements for a ccr: version, signingAlg, issuer, validity, subject and
// publicKey MUST all be present, and the version MUST be v3 or v1 (v2 rejected).
// Returns a badCertTemplate rejection describing the first problem, or nil.
func validateCrossCertTemplate(certReqID int, t crossCertTemplateInfo) *corecmp.CertRequestRejection {
	bad := func(reason string) *corecmp.CertRequestRejection {
		return &corecmp.CertRequestRejection{CertReqID: certReqID, Reason: reason, FailInfoBit: corecmp.PKIFailureInfoBadCertTemplate}
	}
	switch {
	case !t.hasVersion:
		return bad("CertTemplate version field is required for cross-certification (RFC 4210bis App. D.6)")
	case t.version == 1: // v2
		return bad("CertTemplate version must be v3 or v1, not v2 (RFC 4210bis App. D.6)")
	case !t.hasSigningAlg:
		return bad("CertTemplate signingAlg field is required for cross-certification (RFC 4210bis App. D.6)")
	case !t.hasIssuer:
		return bad("CertTemplate issuer field is required for cross-certification (RFC 4210bis App. D.6)")
	case !t.hasValidity:
		return bad("CertTemplate validity field is required for cross-certification (RFC 4210bis App. D.6)")
	case !t.hasSubject:
		return bad("CertTemplate subject field is required for cross-certification (RFC 4210bis App. D.6)")
	case !t.hasPublicKey:
		return bad("CertTemplate publicKey field is required for cross-certification (RFC 4210bis App. D.6)")
	}
	return nil
}

// parseCrossCertTemplate peels the first CertReqMsg's CertTemplate and records
// which optional fields are present plus the requested version. It mirrors the
// manual peeling in decodeFirstCertReq; a parse failure yields a zero-value
// (all-absent) result so the presence checks reject the request rather than
// aborting. CertTemplate field tags (RFC 4211 §5): version [0], signingAlg [2],
// issuer [3], validity [4], subject [5], publicKey [6].
func parseCrossCertTemplate(bodyBytes []byte) crossCertTemplateInfo {
	var info crossCertTemplateInfo

	var crMsgs asn1.RawValue
	if _, err := asn1.Unmarshal(bodyBytes, &crMsgs); err != nil {
		return info
	}
	var crMsg asn1.RawValue
	if _, err := asn1.Unmarshal(crMsgs.Bytes, &crMsg); err != nil {
		return info
	}
	var certReq asn1.RawValue
	if _, err := asn1.Unmarshal(crMsg.Bytes, &certReq); err != nil {
		return info
	}
	// CertRequest ::= SEQUENCE { certReqId INTEGER, certTemplate CertTemplate, ... }
	var certReqID asn1.RawValue
	rest, err := asn1.Unmarshal(certReq.Bytes, &certReqID)
	if err != nil {
		return info
	}
	var certTemplate asn1.RawValue
	if _, err := asn1.Unmarshal(rest, &certTemplate); err != nil {
		return info
	}

	remaining := certTemplate.Bytes
	for len(remaining) > 0 {
		var field asn1.RawValue
		var err error
		remaining, err = asn1.Unmarshal(remaining, &field)
		if err != nil {
			break
		}
		if field.Class != asn1.ClassContextSpecific {
			continue
		}
		switch field.Tag {
		case 0: // version [0] Version (INTEGER)
			info.hasVersion = true
			var v int
			if _, err := asn1.Unmarshal(field.Bytes, &v); err == nil {
				info.version = v
			} else {
				// IMPLICIT [0] over an INTEGER: the content bytes are the integer.
				info.version = intFromBytes(field.Bytes)
			}
		case 2:
			info.hasSigningAlg = true
		case 3:
			info.hasIssuer = true
		case 4:
			info.hasValidity = true
			// validity [4] OptionalValidity (IMPLICIT SEQUENCE): field.Bytes is the
			// SEQUENCE content, i.e. the notBefore/notAfter elements directly.
			parseOptionalValidity(field.Bytes, &info)
		case 5:
			info.hasSubject = true
		case 6:
			info.hasPublicKey = true
		}
	}
	return info
}

// parseOptionalValidity parses the content of an OptionalValidity SEQUENCE
// (RFC 4211 §5): notBefore [0] Time OPTIONAL, notAfter [1] Time OPTIONAL. Time is
// a CHOICE (utcTime / generalTime), so each field is EXPLICITLY tagged and its
// content bytes are the inner Time TLV. Unparseable values are left as nil so
// issuance falls back to the profile default.
func parseOptionalValidity(seqContent []byte, info *crossCertTemplateInfo) {
	remaining := seqContent
	for len(remaining) > 0 {
		var field asn1.RawValue
		var err error
		remaining, err = asn1.Unmarshal(remaining, &field)
		if err != nil {
			break
		}
		if field.Class != asn1.ClassContextSpecific {
			continue
		}
		t, ok := parseASN1Time(field.Bytes)
		if !ok {
			continue
		}
		switch field.Tag {
		case 0:
			tb := t
			info.notBefore = &tb
		case 1:
			ta := t
			info.notAfter = &ta
		}
	}
}

// parseASN1Time decodes a UTCTime or GeneralizedTime TLV into a time.Time.
func parseASN1Time(timeTLV []byte) (time.Time, bool) {
	var t time.Time
	if _, err := asn1.Unmarshal(timeTLV, &t); err == nil {
		return t, true
	}
	return time.Time{}, false
}

// oidX25519 / oidX448 are the RFC 8410 key-agreement algorithms. Certificates
// with these keys cannot produce signatures, so they cannot be cross-certified
// (a cross-certified CA must be able to sign).
var (
	oidX25519 = asn1.ObjectIdentifier{1, 3, 101, 110}
	oidX448   = asn1.ObjectIdentifier{1, 3, 101, 111}
)

// isNonSigningKeyAlgorithm reports whether the SubjectPublicKeyInfo in spkiDER
// names a key-agreement-only algorithm (X25519 / X448) that cannot sign. A
// parse failure returns false (let downstream handling decide).
func isNonSigningKeyAlgorithm(spkiDER []byte) bool {
	var spki struct {
		Algorithm struct {
			Algorithm  asn1.ObjectIdentifier
			Parameters asn1.RawValue `asn1:"optional"`
		}
		SubjectPublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(spkiDER, &spki); err != nil {
		return false
	}
	return spki.Algorithm.Algorithm.Equal(oidX25519) || spki.Algorithm.Algorithm.Equal(oidX448)
}

// intFromBytes interprets up to a few big-endian bytes as an int (used for the
// IMPLICIT-tagged CertTemplate version, a tiny non-negative value).
func intFromBytes(b []byte) int {
	n := 0
	for _, x := range b {
		n = n<<8 | int(x)
	}
	return n
}

// asErrCertRequestRejection is a thin wrapper over errors.As kept local to avoid
// importing errors in multiple spots; returns true when err is a
// *certRequestRejection and assigns it to target.
func asErrCertRequestRejection(err error, target **corecmp.CertRequestRejection) bool {
	rej, ok := err.(*corecmp.CertRequestRejection)
	if ok {
		*target = rej
	}
	return ok
}
