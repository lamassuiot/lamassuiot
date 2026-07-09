package cmp

import (
	"context"
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	cmpwfx "github.com/lamassuiot/lamassuiot/backend/v3/pkg/integrations/wfx"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/errs"
	chelpers "github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/kga"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	software "github.com/lamassuiot/lamassuiot/engines/crypto/software/v3"
	"github.com/sirupsen/logrus"
)

// This file owns the enrollment pipeline shared by ir/cr/kur:
//
//   handleEnrollment(variant) → issueAndStore | deferForApproval
//
// It is split out of cmp.go so the HTTP dispatcher (cmp.go) stays a
// dispatcher: tag → service → response. All policy (workflow selection,
// duplicate-tx detection, supersession, implicit-confirm negotiation,
// WFX state emission for the enrollment lifecycle) lives here (audit A2).

// handleEnrollment is the merged ir/cr/kur dispatcher (audit A3). The three
// enrollment bodies share the same skeleton — decode CertReqMessage, validate
// the proof of possession, emit the Validated WFX transition, hand off to
// issueAndStore — but differ in how POPO is established and in the response
// body tag. Those differences are captured in enrollmentVariant rather than
// duplicated across two handlers.
func (r *cmpHttpRoutes) handleEnrollment(ctx *gin.Context, lFunc *logrus.Entry, header requestPKIHeader, body asn1.RawValue, dmsID string, enrollOpts *models.EnrollmentOptionsLWCRFC9483, variant enrollmentVariant) {
	// KUR-only pre-check: RFC 9483 §4.1.3 ties POPO to the message-level
	// protection because the EE must sign with the cert being updated. For
	// ir/cr the inner POPO is checked below; for kur an absent protection
	// algorithm is itself a POPO failure.
	if variant.requireMessageProtectionForPOPO && enrollOpts.EnforcePOPO {
		if len(header.ProtectionAlg.Algorithm) == 0 {
			lFunc.Warnf("kur: POPO enforcement requires message-level protection (RFC 9483 §4.1.3)")
			r.rejectWithError(ctx, &header, PKIStatus(2),
				"KUR requires message-level signature protection as proof of possession (RFC 9483 §4.1.3)",
				dmsID, pkiFailureInfoBadPOP)
			return
		}
	}

	respTag := variant.respTagFor(body.Tag)

	req, err := decodeFirstCertReq(body.Bytes)
	if err != nil {
		var certRej *certRequestRejection
		if errors.As(err, &certRej) {
			// Cert-request-level rejection: respond with ip/cp body per RFC 9483 §4.1.
			lFunc.Warnf("%s: cert request rejected: %v", variant.logPrefix, err)
			r.rejectCertRequest(ctx, lFunc, header, respTag, dmsID, certRej)
		} else {
			lFunc.Errorf("%s: decode CertReqMessage: %v", variant.logPrefix, err)
			r.rejectWithError(ctx, &header, PKIStatus(2), "malformed CertReqMessage", dmsID, pkiFailureInfoBadDataFormat)
		}
		return
	}

	// RFC 9483 §4.1.6 central key generation: the request carries no usable
	// public key and no POPO, so the server generates the key pair and returns it
	// encrypted in the response. This diverges from the normal issue-from-CSR
	// pipeline (no client key ⇒ no POPO, key/template checks below don't apply),
	// so it is handled entirely by handleKGAEnrollment.
	if req.ForKGA {
		r.handleKGAEnrollment(ctx, lFunc, header, req, dmsID, respTag, body.Tag, variant.enrollFn(r, dmsID))
		return
	}

	// Reject a weak RSA key up front: it is a defective CertTemplate
	// (badCertTemplate), not a proof-of-possession failure. This must run before
	// POPO verification because Go refuses to even verify a 512-bit RSA POPO
	// signature ("512-bit keys are insecure"), which would otherwise surface as a
	// misleading badPOP. Applies to ir/cr/kur alike (kur skips inner POPO).
	if bits := rsaKeyBits(req.PublicKeyDER); bits > 0 && bits < minRSAKeyBits {
		lFunc.Warnf("%s: RSA public key too short: %d-bit (minimum %d)", variant.logPrefix, bits, minRSAKeyBits)
		r.rejectCertRequest(ctx, lFunc, header, respTag, dmsID, &certRequestRejection{
			CertReqID:   req.CertReqID,
			Reason:      fmt.Sprintf("RSA public key too short: %d-bit key is below the %d-bit minimum (NIST SP 800-57)", bits, minRSAKeyBits),
			FailInfoBit: pkiFailureInfoBadCertTemplate,
		})
		return
	}

	// Reject an oversized RSA key symmetrically: a modulus far above any
	// practical size (e.g. 18000-bit) is a defective CertTemplate and a
	// resource-exhaustion vector, so it is rejected with badCertTemplate before
	// POPO verification (verifying such a signature is itself expensive).
	if bits := rsaKeyBits(req.PublicKeyDER); bits > maxRSAKeyBits {
		lFunc.Warnf("%s: RSA public key too large: %d-bit (maximum %d)", variant.logPrefix, bits, maxRSAKeyBits)
		r.rejectCertRequest(ctx, lFunc, header, respTag, dmsID, &certRequestRejection{
			CertReqID:   req.CertReqID,
			Reason:      fmt.Sprintf("RSA public key too large: %d-bit key exceeds the %d-bit maximum", bits, maxRSAKeyBits),
			FailInfoBit: pkiFailureInfoBadCertTemplate,
		})
		return
	}

	// Inner-POPO verification is meaningful for ir/cr (RFC 9483 §4.1 /
	// RFC 4211 §4.1 clause 3). For kur, the protection certificate proves
	// possession of the key being updated, so a separate inner-POPO check
	// would be redundant (and is omitted by RFC 9483 §4.1.3).
	if variant.verifyInnerPOPO {
		// RFC 9483 §5.2.3.2: a trusted RA that modified the CertTemplate verifies
		// the EE's proof-of-possession itself and sets popo = raVerified. lamassu
		// honours that only when the message-protection signer is a designated RA
		// (carries id-kp-cmcRA) — otherwise raVerified from an end entity vouching
		// for itself is notAuthorized. The signer is also chain-validated against
		// the DMS ValidationCAs by LWCEnroll, so an untrusted "RA" cannot use this.
		signer := cmpSignerCertFromGin(ctx)
		isRAVerified := req.POPORaw.Class == asn1.ClassContextSpecific && req.POPORaw.Tag == 0 && len(req.POPORaw.FullBytes) > 0
		trustedRA := isRAVerified && chelpers.CertHasExtKeyUsageOID(signer, chelpers.OidExtKeyUsageCMCRA)

		if trustedRA {
			lFunc.Infof("%s: accepting raVerified POPO from trusted RA (id-kp-cmcRA) CN=%s", variant.logPrefix, signer.Subject.CommonName)
		} else if err := verifyPOPO(req.CertReqDER, req.POPORaw, req.PublicKeyDER, enrollOpts.EnforcePOPO); err != nil {
			// An EE asserting raVerified is notAuthorized (RFC 9483 §4.1); every
			// other POPO failure is badPOP.
			failBit := pkiFailureInfoBadPOP
			if errors.Is(err, errPOPORAVerifiedFromEE) {
				failBit = pkiFailureInfoNotAuthorized
			}
			lFunc.Warnf("%s: POPO verification failed: %v", variant.logPrefix, err)
			r.rejectCertRequest(ctx, lFunc, header, respTag, dmsID, &certRequestRejection{
				CertReqID:   req.CertReqID,
				Reason:      fmt.Sprintf("proof of possession verification failed: %v", err),
				FailInfoBit: failBit,
			})
			return
		}
	}

	// RFC 9483 §4.1.3 / RFC 4211 §6.2: when a KUR carries the optional
	// id-regCtrl-oldCertID control, it MUST reference the certificate being
	// updated. We validate it against the protection (signer) certificate — the
	// EE's current cert — and reject with badCertId in a kup CertRepMessage on
	// mismatch, before the service-layer signer binding runs.
	if variant.isReenrollment && req.OldCertID != nil {
		if signer := cmpSignerCertFromGin(ctx); signer != nil {
			if rej := validateOldCertID(req, signer); rej != nil {
				lFunc.Warnf("kur: oldCertId mismatch: %s", rej.Reason)
				r.rejectCertRequest(ctx, lFunc, header, respTag, dmsID, rej)
				return
			}
		}
	}

	// CertTemplate policy enforcement (RFC 9483 §5 / RFC 5280 §4.2.1.9). Lamassu
	// only issues end-entity certificates over CMP, so a request for a CA
	// certificate (BasicConstraints cA=TRUE or the keyCertSign KeyUsage) or a
	// malformed BasicConstraints (pathLenConstraint present without cA=TRUE) is
	// rejected here — before issuance — with the appropriate failInfo bit.
	if rej := validateCertTemplatePolicy(req); rej != nil {
		lFunc.Warnf("%s: cert template policy rejected: %s", variant.logPrefix, rej.Reason)
		r.rejectCertRequest(ctx, lFunc, header, respTag, dmsID, rej)
		return
	}

	// RFC 4211 registration-control validation. Structurally-invalid
	// id-regCtrl-pkiPublicationInfo controls (§6.3) and an id-regInfo-certReq
	// alternate CertRequest whose public key differs from the primary request
	// (§7.2) are rejected in an ip/cp body before issuance. Other controls
	// (oldCertID, regToken, authenticator) are intentionally left untouched.
	if rej := validatePKIPublicationInfoControls(req.CertReqID, req.ControlsDER); rej != nil {
		lFunc.Warnf("%s: pkiPublicationInfo control rejected: %s", variant.logPrefix, rej.Reason)
		r.rejectCertRequest(ctx, lFunc, header, respTag, dmsID, rej)
		return
	}
	if rej := validateAltCertReqPublicKey(req.CertReqID, req.RegInfoDER, req.PublicKeyDER); rej != nil {
		lFunc.Warnf("%s: alt CertReq rejected: %s", variant.logPrefix, rej.Reason)
		r.rejectCertRequest(ctx, lFunc, header, respTag, dmsID, rej)
		return
	}

	deviceCN := extractCNFromSubjectDER(req.SubjectDER)
	wfxJobID := r.reportCMPState(ctx.Request.Context(), lFunc, cmpwfx.CMPTransition{
		TransactionID:     hex.EncodeToString(header.TransactionID),
		DMSID:             dmsID,
		RequestType:       cmpTagToString(body.Tag),
		SubjectCommonName: deviceCN,
		State:             cmpwfx.CMPStateValidated,
		Metadata: map[string]any{
			"certReqId": req.CertReqID,
		},
	})

	r.issueAndStore(ctx, lFunc, &header, req, dmsID, enrollOpts, issueParams{
		isReenrollment: variant.isReenrollment,
		requestTag:     body.Tag,
		respTag:        respTag,
		wfxJobID:       wfxJobID,
		enroll:         variant.enrollFn(r, dmsID),
	})
}

// isRevokedCertError reports whether an enroll/reenroll error is the service's
// "certificate is revoked" rejection. The service returns these as plain
// fmt.Errorf strings (no sentinel), so we match on the substring; used to map
// the failure to PKIFailureInfo certRevoked instead of systemFailure.
func isRevokedCertError(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "revoked")
}

// commitReenrollment invokes the service's deferred key-update commit: bind the
// confirmed certificate as the device's active identity and supersede the
// previous one (RFC 9483 §4.1.3). It is best-effort — a failure is logged but
// does not change the CMP protocol outcome, because the certificate has already
// been issued and delivered to the EE. The service is expected to implement
// services.LightweightCMPConfirmer; if it does not, the commit is skipped.
func (r *cmpHttpRoutes) commitReenrollment(ctx context.Context, lFunc *logrus.Entry, dmsID, certSerial string) {
	confirmer, ok := r.svc.(services.LightweightCMPConfirmer)
	if !ok {
		lFunc.Warnf("service does not implement LightweightCMPConfirmer; skipping key-update commit for cert %s", certSerial)
		return
	}
	if err := confirmer.LWCConfirmReenrollment(ctx, dmsID, certSerial); err != nil {
		lFunc.Errorf("could not commit confirmed key-update for cert %s: %v", certSerial, err)
	}
}

// enrollmentVariant captures the per-body-tag differences between ir/cr and
// kur so handleEnrollment can stay a single code path.
type enrollmentVariant struct {
	logPrefix                       string
	isReenrollment                  bool
	verifyInnerPOPO                 bool
	requireMessageProtectionForPOPO bool
	respTagFor                      func(requestTag int) int
	enrollFn                        func(r *cmpHttpRoutes, dmsID string) func(ctx context.Context, csr *x509.CertificateRequest) (*x509.Certificate, error)
}

// enrollmentVariantInitial is the variant used for ir (0) and cr (2). The
// response tag depends on the request: ir → ip (1), cr → cp (3).
var enrollmentVariantInitial = enrollmentVariant{
	logPrefix:                       "ir/cr",
	isReenrollment:                  false,
	verifyInnerPOPO:                 true,
	requireMessageProtectionForPOPO: false,
	respTagFor: func(requestTag int) int {
		if requestTag == cmpBodyTagIR {
			return cmpBodyTagIP
		}
		return cmpBodyTagCP
	},
	enrollFn: func(r *cmpHttpRoutes, dmsID string) func(ctx context.Context, csr *x509.CertificateRequest) (*x509.Certificate, error) {
		return func(ctx context.Context, csr *x509.CertificateRequest) (*x509.Certificate, error) {
			return r.svc.LWCEnroll(ctx, csr, dmsID)
		}
	},
}

// enrollmentVariantUpdate is the variant used for kur (7). Inner POPO is
// skipped because the message-level protection IS the POPO under RFC 9483
// §4.1.3; the response is always kup (8).
var enrollmentVariantUpdate = enrollmentVariant{
	logPrefix:                       "kur",
	isReenrollment:                  true,
	verifyInnerPOPO:                 false,
	requireMessageProtectionForPOPO: true,
	respTagFor: func(int) int {
		return cmpBodyTagKUP
	},
	enrollFn: func(r *cmpHttpRoutes, dmsID string) func(ctx context.Context, csr *x509.CertificateRequest) (*x509.Certificate, error) {
		return func(ctx context.Context, csr *x509.CertificateRequest) (*x509.Certificate, error) {
			return r.svc.LWCReenroll(ctx, csr, dmsID)
		}
	},
}

// issueParams holds the per-operation differences between ir/cr and kur
// flows that the enrollment pipeline needs once decoding is done. Kept here
// alongside the only function that constructs it (handleEnrollment) and the
// only function that consumes it (issueAndStore).
type issueParams struct {
	isReenrollment bool
	requestTag     int
	respTag        int
	// wfxJobID is the WFX job UUID resolved at the Validated emit (the
	// first state emission that knows the device CN). Persisted onto the
	// cmp_transactions row so the management UI can deep-link directly to
	// the corresponding WFX workflow without a clientId-based round-trip.
	wfxJobID string
	// supersededCertSerial is set by issueAndStore for re-enrollments: the hex
	// serial of the kur's protection cert (the certificate being updated).
	// Persisted onto the transaction row so the pending-update check can lock
	// exactly that certificate until certConf or timeout (RFC 9483 §4.1.3).
	supersededCertSerial string
	enroll               func(ctx context.Context, csr *x509.CertificateRequest) (*x509.Certificate, error)
}

// issueAndStore is the shared enrollment pipeline: build CSR, check duplicate
// transactionID, call the CA, persist the ISSUED row for lost-response
// recovery, and respond with the cert.
func (r *cmpHttpRoutes) issueAndStore(
	ctx *gin.Context,
	lFunc *logrus.Entry,
	header *requestPKIHeader,
	req *firstCertReq,
	dmsID string,
	enrollOpts *models.EnrollmentOptionsLWCRFC9483,
	params issueParams,
) {
	csr, err := buildSyntheticCSR(req.SubjectDER, req.PublicKeyDER, req.Extensions)
	if err != nil {
		lFunc.Errorf("synthesize CSR: %v", err)
		r.rejectWithError(ctx, header, PKIStatus(2), "cannot build CSR from CertTemplate", dmsID, pkiFailureInfoBadCertTemplate)
		return
	}
	lFunc = lFunc.WithField("cn", csr.Subject.CommonName)
	lFunc.Infof("enrollment request CN=%s (reenroll=%v)", csr.Subject.CommonName, params.isReenrollment)

	implicitConfirm := r.isImplicitConfirm(ctx.Request.Context(), *header, dmsID)
	header.ResponseImplicitConfirm = implicitConfirm

	// Early duplicate-transactionID check before calling the CA. The store is
	// guaranteed non-nil by NewCMPHttpRoutes.
	txHex := hex.EncodeToString(header.TransactionID)
	if exists, err := r.store.Exists(ctx.Request.Context(), txHex); err != nil {
		lFunc.Errorf("check existing txID: %v", err)
		r.rejectWithError(ctx, header, PKIStatus(2), "internal error", dmsID, pkiFailureInfoSystemFailure)
		return
	} else if exists {
		lFunc.Warnf("duplicate transactionID %s (pre-enroll check)", txHex)
		r.rejectWithError(ctx, header, PKIStatus(2), "transactionID already in use", dmsID, pkiFailureInfoTransactionIDInUse)
		return
	}

	// RFC 9483 §4.1.3: a certificate MUST NOT start a second key-update while
	// its previous one is still awaiting certConf. The first KUR issues the new
	// certificate but defers the identity swap until confirmation, so a second
	// KUR protected with the same certificate in that window is rejected with
	// badRequest. Keyed on the protection (signer) cert's serial — the
	// certificate being updated — NOT the subject CN: a subject may legitimately
	// hold several certificates over time, and only the one under update is
	// locked. Once the prior KUR is confirmed (CONFIRMED) or rolled back on
	// timeout (REVOKED/expired) this check passes again.
	if signer := cmpSignerCertFromGin(ctx); signer != nil && params.isReenrollment {
		params.supersededCertSerial = hex.EncodeToString(signer.SerialNumber.Bytes())
	}
	if params.supersededCertSerial != "" {
		inProgress, ipErr := r.store.HasUnconfirmedReenrollment(ctx.Request.Context(), dmsID, params.supersededCertSerial)
		if ipErr != nil {
			lFunc.Errorf("check in-progress reenrollment: %v", ipErr)
			r.rejectWithError(ctx, header, PKIStatus(2), "internal error", dmsID, pkiFailureInfoSystemFailure)
			return
		}
		if inProgress {
			lFunc.Warnf("second KUR for cert %s while its previous key-update is unconfirmed", params.supersededCertSerial)
			r.rejectWithError(ctx, header, PKIStatus(2),
				"a previous key-update for this certificate is still awaiting confirmation (RFC 9483 §4.1.3)",
				dmsID, pkiFailureInfoBadRequest)
			return
		}
	}

	// Phased (admin-gated) workflow: do NOT issue now. Park the request in a
	// PENDING row carrying the synthesized CSR and reply with a "waiting"
	// response (RFC 9483 §4.4 / RFC 4210 §5.3.22). An administrator later
	// approves the transaction, which issues the cert and flips the row to
	// ISSUED; the EE retrieves it via pollReq.
	if enrollOpts.Workflow == models.CMPWorkflowPhased {
		r.deferForApproval(ctx, lFunc, header, req, csr, dmsID, enrollOpts, params, txHex)
		return
	}

	// Detach from the HTTP connection so issuance completes even if the EE
	// drops the TCP connection mid-request.
	issuanceCtx := context.WithoutCancel(ctx.Request.Context())
	cert, err := params.enroll(issuanceCtx, csr)
	if err != nil {
		lFunc.Errorf("enroll failed: %v", err)
		// Map the few categories the service distinguishes to their RFC 9483
		// §3.5 failInfo bits; everything else is systemFailure (the broadest
		// "server-side inability to complete the request" bit, RFC 9810 §5.1.3).
		failBit := pkiFailureInfoSystemFailure
		switch {
		case errors.Is(err, errs.ErrDMSEnrollInvalidCert):
			// Protection signer cert did not chain to any of the DMS's
			// ValidationCAs → the requester is not trusted.
			failBit = pkiFailureInfoSignerNotTrusted
		case errors.Is(err, errs.ErrCMPPendingUpdate):
			// Device has a key-update awaiting certConf: the open transaction
			// must complete or time out before new operations (RFC 9483 §4.1.3).
			failBit = pkiFailureInfoBadRequest
		case errors.Is(err, errs.ErrCMPCertSuperseded):
			// Signer cert was replaced by a confirmed key-update — per
			// RFC 9483 §4.1.3 it can no longer authenticate operations.
			failBit = pkiFailureInfoCertRevoked
		case errors.Is(err, errs.ErrCMPSignerNotActive):
			// kur signer binding failed: not the device's active cert and not
			// a recognised superseded one.
			failBit = pkiFailureInfoBadRequest
		case errors.Is(err, errs.ErrCMPAbandonedUpdate):
			// ir/cr from a device that abandoned a key-update: it must recover
			// via kur, not initialization (RFC 9483 §4.1.3, sec-awareness).
			failBit = pkiFailureInfoBadRequest
		case isRevokedCertError(err):
			failBit = pkiFailureInfoCertRevoked
		}
		r.rejectWithError(ctx, header, PKIStatus(2), err.Error(), dmsID, failBit)
		return
	}
	certSerial := hex.EncodeToString(cert.SerialNumber.Bytes())

	// Persist ISSUED row for lost-response recovery via pollReq.
	senderNonce, nonceErr := newNonce()
	if nonceErr != nil {
		lFunc.Errorf("nonce generation: %v", nonceErr)
		r.rejectWithError(ctx, header, PKIStatus(2), "internal error: nonce generation failed", dmsID, pkiFailureInfoSystemFailure)
		return
	}
	if !implicitConfirm {
		header.ResponseSenderNonce = senderNonce
	}
	// When implicit confirmation is granted, RFC 4210 §5.2.8 considers the
	// transaction successfully completed at IP delivery — no certConf will
	// follow. Persist the row directly as CONFIRMED so the confirmation
	// monitor does not revoke the cert at expires_at. The previous behaviour
	// was to insert ISSUED with a 5-minute window and never transition it,
	// which silently revoked every implicit-confirm enrollment.
	initialState := storage.CMPTransactionStateIssued
	var confirmedAt time.Time
	if implicitConfirm {
		initialState = storage.CMPTransactionStateConfirmed
		confirmedAt = time.Now()
	}
	if storeErr := r.store.Insert(issuanceCtx, storage.CMPTransaction{
		TransactionID:     txHex,
		DMSID:             dmsID,
		State:             initialState,
		CertSerialNumber:  certSerial,
		Certificate:       (*models.X509Certificate)(cert),
		IsReenrollment:    params.isReenrollment,
		RequestType:       cmpTagToString(params.requestTag),
		SubjectCommonName: csr.Subject.CommonName,
		WFXJobID:          params.wfxJobID,
		SentNonce:         hex.EncodeToString(senderNonce),
		ReceivedNonce:     hex.EncodeToString(header.SenderNonce),
		// For a kur, the protection cert is the certificate being updated
		// (RFC 9483 §4.1.3); recording its serial lets the pending-update check
		// lock exactly that certificate until certConf or timeout. Empty for
		// ir/cr and for unprotected updates.
		SupersededCertSerial: params.supersededCertSerial,
		ConfirmedAt:          confirmedAt,
		ExpiresAt:         time.Now().Add(confirmationTimeoutOrDefault(enrollOpts.ConfirmationTimeout)),
		CreatedAt:         time.Now(),
	}); storeErr != nil {
		if errors.Is(storeErr, errs.ErrCMPTransactionAlreadyExists) {
			lFunc.Warnf("duplicate transactionID %s", txHex)
			r.rejectWithError(ctx, header, PKIStatus(2), "transactionID already in use", dmsID, pkiFailureInfoTransactionIDInUse)
			return
		}
		lFunc.Errorf("store transaction: %v", storeErr)
		lFunc.Warnf("failed to persist ISSUED row (cert delivered inline): %v", storeErr)
	}

	// Implicit confirmation: RFC 4210 §5.2.8 treats the transaction as complete
	// at KUP delivery — no certConf will follow — so commit the deferred
	// key-update now (bind the new cert as the device's active identity and
	// supersede the previous one). Explicit-confirm KURs commit in handleCertConf.
	if implicitConfirm && params.isReenrollment {
		r.commitReenrollment(issuanceCtx, lFunc, dmsID, certSerial)
	}

	// RFC 4210 §5.2.3 / RFC 9483 §5: if issuance dropped a critical extension
	// the CertTemplate requested (e.g. an unrecognized/invalid critical
	// extension our relaxed policy strips rather than rejects), the issued
	// certificate differs from the request, so the success status is
	// grantedWithMods (1) instead of accepted (0).
	statusCode := int(PKIStatus(0))
	if requestedCriticalExtensionDropped(req.Extensions, cert) {
		lFunc.Infof("issued cert omits a requested critical extension; responding grantedWithMods")
		statusCode = 1
	}
	certRepDER, err := marshalCertRepBodyWithStatus(params.respTag, req.CertReqID, statusCode, cert.Raw)
	if err != nil {
		lFunc.Errorf("build cert rep body: %v", err)
		r.rejectWithError(ctx, header, PKIStatus(2), "cannot build response", dmsID, pkiFailureInfoSystemFailure)
		return
	}
	responseDER := r.sendRawBody(ctx, lFunc, *header, params.respTag, certRepDER, dmsID)
	if len(responseDER) == 0 {
		return
	}
	r.reportCMPState(ctx.Request.Context(), lFunc, cmpwfx.CMPTransition{
		TransactionID:     txHex,
		DMSID:             dmsID,
		RequestType:       cmpTagToString(params.requestTag),
		SubjectCommonName: csr.Subject.CommonName,
		CertSerialNumber:  certSerial,
		State:             cmpwfx.CMPStateResponded,
		Metadata: withCMPMessageB64(map[string]any{
			"certReqId":      req.CertReqID,
			"isReenrollment": params.isReenrollment,
			"responseType":   cmpTagToString(params.respTag),
		}, cmpMetadataResponseB64, responseDER),
	})
	finalState := cmpwfx.CMPStateAwaitingCertConf
	if implicitConfirm {
		finalState = cmpwfx.CMPStateLogicallyComplete
	}
	r.reportCMPState(ctx.Request.Context(), lFunc, cmpwfx.CMPTransition{
		TransactionID:     txHex,
		DMSID:             dmsID,
		RequestType:       cmpTagToString(params.requestTag),
		SubjectCommonName: csr.Subject.CommonName,
		CertSerialNumber:  certSerial,
		State:             finalState,
		Metadata: map[string]any{
			"responseType":    cmpTagToString(params.respTag),
			"implicitConfirm": implicitConfirm,
		},
	})
}

// handleKGAEnrollment implements RFC 9483 §4.1.6 central key generation. The
// server generates the end-entity key pair, has the enrollment CA issue a
// certificate for it, wraps the private key in a CMS EnvelopedData(SignedData)
// (built by core/pkg/kga), and returns both in the CertifiedKeyPair.
//
// The CMS recipient is the request's protection (signer) certificate: for KTRI
// the CEK is RSA-encrypted to its key; for KARI a fresh EC originator is used
// for ECDH against it. The compliance validator matches the CMS recipient /
// originator identifiers against the response's extraCerts[0] by SKI, so this
// handler places the correct certificate there (the EE cert for KTRI, the
// originator for KARI) while signing the response protection with a key it owns.
func (r *cmpHttpRoutes) handleKGAEnrollment(
	ctx *gin.Context,
	lFunc *logrus.Entry,
	header requestPKIHeader,
	req *firstCertReq,
	dmsID string,
	respTag, requestTag int,
	enroll func(ctx context.Context, csr *x509.CertificateRequest) (*x509.Certificate, error),
) {
	lFunc = lFunc.WithField("mode", "kga")

	// Central key generation needs a signature-protected request: the protection
	// signer certificate is the CMS recipient and carries the key usage that
	// selects (and authorises) the key-management technique.
	recipient := cmpSignerCertFromGin(ctx)
	if recipient == nil {
		r.rejectCertRequest(ctx, lFunc, header, respTag, dmsID, &certRequestRejection{
			CertReqID:   req.CertReqID,
			Reason:      "central key generation requires a signature-protected request (RFC 9483 §4.1.6)",
			FailInfoBit: pkiFailureInfoBadRequest,
		})
		return
	}

	technique, err := kga.TechniqueFor(recipient.PublicKey)
	if err != nil {
		r.rejectCertRequest(ctx, lFunc, header, respTag, dmsID, &certRequestRejection{
			CertReqID:   req.CertReqID,
			Reason:      fmt.Sprintf("central key generation: %v", err),
			FailInfoBit: pkiFailureInfoBadCertTemplate,
		})
		return
	}
	// RFC 9483 §4.1.6.1/§4.1.6.2: the recipient certificate MUST allow the chosen
	// technique — keyEncipherment for KTRI, keyAgreement for KARI. Missing it is
	// notAuthorized.
	if rej := validateKGARecipientKeyUsage(req.CertReqID, technique, recipient); rej != nil {
		lFunc.Warnf("kga: recipient cert key usage rejects %s: %s", technique, rej.Reason)
		r.rejectCertRequest(ctx, lFunc, header, respTag, dmsID, rej)
		return
	}

	keyGen, ok := r.svc.(services.LightweightCMPKeyGenerator)
	if !ok {
		lFunc.Errorf("kga: service does not implement LightweightCMPKeyGenerator")
		r.rejectWithError(ctx, &header, PKIStatus(2), "central key generation not supported", dmsID, pkiFailureInfoSystemFailure)
		return
	}

	issuanceCtx := context.WithoutCancel(ctx.Request.Context())
	sw := software.NewSoftwareCryptoEngine(lFunc)

	// 1. Generate the end-entity key pair the server will hand back.
	generated, err := generateKGAKey(issuanceCtx, sw, req.KGAKeyAlgorithm)
	if err != nil {
		lFunc.Errorf("kga: generate end-entity key: %v", err)
		r.rejectWithError(ctx, &header, PKIStatus(2), "could not generate key", dmsID, pkiFailureInfoSystemFailure)
		return
	}

	// 2. Issue a certificate for the generated public key via the normal
	// enrollment path (a synthetic CSR carrying the requested subject/extensions).
	spkiDER, err := x509.MarshalPKIXPublicKey(generated.Public())
	if err != nil {
		lFunc.Errorf("kga: marshal generated public key: %v", err)
		r.rejectWithError(ctx, &header, PKIStatus(2), "internal error", dmsID, pkiFailureInfoSystemFailure)
		return
	}
	csr, err := buildSyntheticCSR(req.SubjectDER, spkiDER, req.Extensions)
	if err != nil {
		lFunc.Errorf("kga: build synthetic CSR: %v", err)
		r.rejectWithError(ctx, &header, PKIStatus(2), "cannot build CSR", dmsID, pkiFailureInfoBadCertTemplate)
		return
	}
	cert, err := enroll(issuanceCtx, csr)
	if err != nil {
		lFunc.Errorf("kga: issue certificate: %v", err)
		failBit := pkiFailureInfoSystemFailure
		if errors.Is(err, errs.ErrDMSEnrollInvalidCert) {
			failBit = pkiFailureInfoSignerNotTrusted
		}
		r.rejectWithError(ctx, &header, PKIStatus(2), err.Error(), dmsID, failBit)
		return
	}

	// 3. Ephemeral KGA signer (id-kp-cmKGA) that signs the CMS SignedData.
	_, signerKey, err := sw.CreateECDSAPrivateKey(issuanceCtx, elliptic.P256())
	if err != nil {
		lFunc.Errorf("kga: generate KGA signer key: %v", err)
		r.rejectWithError(ctx, &header, PKIStatus(2), "internal error", dmsID, pkiFailureInfoSystemFailure)
		return
	}
	signerCSR, err := selfSignedCSR("Lamassu CMP KGA Signer", signerKey)
	if err != nil {
		lFunc.Errorf("kga: build KGA signer CSR: %v", err)
		r.rejectWithError(ctx, &header, PKIStatus(2), "internal error", dmsID, pkiFailureInfoSystemFailure)
		return
	}
	kgaCert, kgaChain, err := keyGen.LWCIssueKGAHelperCertificate(issuanceCtx, dmsID, signerCSR, services.KGAHelperSigner)
	if err != nil {
		lFunc.Errorf("kga: issue KGA signer certificate: %v", err)
		r.rejectWithError(ctx, &header, PKIStatus(2), "could not issue KGA signer certificate", dmsID, pkiFailureInfoSystemFailure)
		return
	}

	buildIn := kga.BuildInput{
		GeneratedKey:  generated,
		RecipientCert: recipient,
		KGACert:       kgaCert,
		KGAChain:      kgaChain,
		KGASigner:     signerKey,
	}

	// extraCerts[0] MUST be the certificate the validator matches CMS identifiers
	// against; the response protection is signed with a key we own (which need
	// not be extraCerts[0] — the recipient locates it via senderKID).
	var extraCerts []*x509.Certificate
	var protectionSignerCert *x509.Certificate
	var protectionSigner crypto.Signer

	if technique == kga.TechniqueKARI {
		// 4. Ephemeral EC originator: it is the ECDH peer AND signs the response
		// protection so it lands at extraCerts[0] (matching the CMS originator).
		_, origKey, err := sw.CreateECDSAPrivateKey(issuanceCtx, elliptic.P256())
		if err != nil {
			lFunc.Errorf("kga: generate KARI originator key: %v", err)
			r.rejectWithError(ctx, &header, PKIStatus(2), "internal error", dmsID, pkiFailureInfoSystemFailure)
			return
		}
		origCSR, err := selfSignedCSR("Lamassu CMP KARI Originator", origKey)
		if err != nil {
			lFunc.Errorf("kga: build KARI originator CSR: %v", err)
			r.rejectWithError(ctx, &header, PKIStatus(2), "internal error", dmsID, pkiFailureInfoSystemFailure)
			return
		}
		origCert, origChain, err := keyGen.LWCIssueKGAHelperCertificate(issuanceCtx, dmsID, origCSR, services.KGAHelperKARIOriginator)
		if err != nil {
			lFunc.Errorf("kga: issue KARI originator certificate: %v", err)
			r.rejectWithError(ctx, &header, PKIStatus(2), "could not issue KARI originator certificate", dmsID, pkiFailureInfoSystemFailure)
			return
		}
		buildIn.KARIOriginatorKey = origKey
		buildIn.KARIOriginatorCert = origCert

		extraCerts = append(extraCerts, origCert)
		extraCerts = append(extraCerts, origChain...)
		extraCerts = append(extraCerts, kgaCert)
		extraCerts = append(extraCerts, kgaChain...)
		protectionSignerCert = origCert
		protectionSigner = origKey
	} else {
		// KTRI: the EE recipient cert must be extraCerts[0]; sign the response
		// with the KGA signer key (its cert is also carried in extraCerts).
		extraCerts = append(extraCerts, recipient)
		extraCerts = append(extraCerts, kgaCert)
		extraCerts = append(extraCerts, kgaChain...)
		protectionSignerCert = kgaCert
		protectionSigner = signerKey
	}

	// 5. Build the EnvelopedData(SignedData(AsymmetricKeyPackage)).
	envelopedDataDER, err := kga.BuildKeyPackage(buildIn)
	if err != nil {
		lFunc.Errorf("kga: build key package: %v", err)
		r.rejectWithError(ctx, &header, PKIStatus(2), "could not build key package", dmsID, pkiFailureInfoSystemFailure)
		return
	}

	// 6. Assemble the ip/cp/kup body carrying the issued cert + enveloped key.
	bodyDER, err := marshalKGACertRepBody(req.CertReqID, int(PKIStatus(0)), cert.Raw, envelopedDataDER)
	if err != nil {
		lFunc.Errorf("kga: marshal cert rep body: %v", err)
		r.rejectWithError(ctx, &header, PKIStatus(2), "cannot build response", dmsID, pkiFailureInfoSystemFailure)
		return
	}

	// 7. Sign and send. The request carried pvno=3, which buildResponseHeader
	// echoes, satisfying the §4.1.6 requirement that the response be cmp2021(3).
	respDER, err := marshalProtectedResponseWithSigner(header, respTag, bodyDER, extraCerts, protectionSignerCert, protectionSigner)
	if err != nil {
		lFunc.Errorf("kga: marshal protected response: %v", err)
		r.rejectWithError(ctx, &header, PKIStatus(2), "cannot build response", dmsID, pkiFailureInfoSystemFailure)
		return
	}
	lFunc.Infof("kga: issued cert SN=%s and delivered %s-wrapped generated key (CN=%s)",
		hex.EncodeToString(cert.SerialNumber.Bytes()), technique, csr.Subject.CommonName)
	ctx.Data(http.StatusOK, "application/pkixcmp", respDER)
}

// validateKGARecipientKeyUsage checks that the recipient (request protection)
// certificate carries the KeyUsage required by the selected KGA technique.
// Returns a notAuthorized rejection when it does not (RFC 9483 §4.1.6).
func validateKGARecipientKeyUsage(certReqID int, technique kga.Technique, recipient *x509.Certificate) *certRequestRejection {
	switch technique {
	case kga.TechniqueKTRI:
		if recipient.KeyUsage&x509.KeyUsageKeyEncipherment == 0 {
			return &certRequestRejection{
				CertReqID:   certReqID,
				Reason:      "recipient certificate lacks the keyEncipherment KeyUsage required for key transport (RFC 9483 §4.1.6.1)",
				FailInfoBit: pkiFailureInfoNotAuthorized,
			}
		}
	case kga.TechniqueKARI:
		if recipient.KeyUsage&x509.KeyUsageKeyAgreement == 0 {
			return &certRequestRejection{
				CertReqID:   certReqID,
				Reason:      "recipient certificate lacks the keyAgreement KeyUsage required for key agreement (RFC 9483 §4.1.6.2)",
				FailInfoBit: pkiFailureInfoNotAuthorized,
			}
		}
	}
	return nil
}

// generateKGAKey generates the end-entity key pair to be delivered, choosing the
// algorithm from the CertTemplate hint (RSA or ECDSA). When the request omitted
// the publicKey field entirely (no hint), it defaults to RSA-2048.
func generateKGAKey(ctx context.Context, sw *software.SoftwareCryptoEngine, alg x509.PublicKeyAlgorithm) (crypto.Signer, error) {
	switch alg {
	case x509.ECDSA:
		_, key, err := sw.CreateECDSAPrivateKey(ctx, elliptic.P256())
		return key, err
	case x509.RSA, x509.UnknownPublicKeyAlgorithm:
		_, key, err := sw.CreateRSAPrivateKey(ctx, 2048)
		return key, err
	default:
		return nil, fmt.Errorf("unsupported key algorithm hint %v", alg)
	}
}

// selfSignedCSR builds and parses a PKCS#10 CSR for cn signed by key. Used for
// the ephemeral KGA helper certificates, whose keys the controller owns.
func selfSignedCSR(cn string, key crypto.Signer) (*x509.CertificateRequest, error) {
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: cn},
	}, key)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificateRequest(der)
}

// deferForApproval implements the phased-workflow enrollment path: it persists
// the request as a PENDING transaction (storing the synthesized CSR so the
// approval step can issue later) and returns a CMP "waiting" response. The EE
// then polls with pollReq until an administrator approves the transaction and
// the cert becomes available.
func (r *cmpHttpRoutes) deferForApproval(
	ctx *gin.Context,
	lFunc *logrus.Entry,
	header *requestPKIHeader,
	req *firstCertReq,
	csr *x509.CertificateRequest,
	dmsID string,
	enrollOpts *models.EnrollmentOptionsLWCRFC9483,
	params issueParams,
	txHex string,
) {
	// The waiting response carries no certificate, so it must not advertise
	// implicit confirmation; that is negotiated when the cert is finally
	// delivered via pollReq.
	header.ResponseImplicitConfirm = false

	storeCtx := context.WithoutCancel(ctx.Request.Context())
	if storeErr := r.store.Insert(storeCtx, storage.CMPTransaction{
		TransactionID:     txHex,
		DMSID:             dmsID,
		State:             storage.CMPTransactionStatePending,
		CSR:               (*models.X509CertificateRequest)(csr),
		IsReenrollment:    params.isReenrollment,
		RequestType:       cmpTagToString(params.requestTag),
		SubjectCommonName: csr.Subject.CommonName,
		WFXJobID:          params.wfxJobID,
		ReceivedNonce:     hex.EncodeToString(header.SenderNonce),
		// kur only: hex serial of the certificate being updated, so the
		// pending-update lock (RFC 9483 §4.1.3) applies to phased key-updates
		// exactly as it does to direct ones.
		SupersededCertSerial: params.supersededCertSerial,
		// Approval is a human action: give it a generous window so the request
		// isn't swept before an operator can act on it (RFC 4210 §5.3.22 leaves
		// the polling/approval window to server policy). Per-DMS via
		// EnrollmentOptionsLWCRFC9483.ApprovalTimeout; cmpApprovalTTL is the
		// fallback when the DMS leaves it at zero.
		ExpiresAt: time.Now().Add(approvalTimeoutOrDefault(enrollOpts.ApprovalTimeout)),
		CreatedAt: time.Now(),
	}); storeErr != nil {
		if errors.Is(storeErr, errs.ErrCMPTransactionAlreadyExists) {
			lFunc.Warnf("duplicate transactionID %s", txHex)
			r.rejectWithError(ctx, header, PKIStatus(2), "transactionID already in use", dmsID, pkiFailureInfoTransactionIDInUse)
			return
		}
		lFunc.Errorf("store PENDING transaction: %v", storeErr)
		r.rejectWithError(ctx, header, PKIStatus(2), "internal error", dmsID, pkiFailureInfoSystemFailure)
		return
	}

	waitingDER, err := marshalCertRepWaitingBody(req.CertReqID)
	if err != nil {
		lFunc.Errorf("build waiting cert rep body: %v", err)
		r.rejectWithError(ctx, header, PKIStatus(2), "cannot build response", dmsID, pkiFailureInfoSystemFailure)
		return
	}
	responseDER := r.sendRawBody(ctx, lFunc, *header, params.respTag, waitingDER, dmsID)
	if len(responseDER) == 0 {
		return
	}
	lFunc.Infof("phased workflow: tx %s parked awaiting admin approval, returned waiting response", txHex)
	r.reportCMPState(ctx.Request.Context(), lFunc, cmpwfx.CMPTransition{
		TransactionID:     txHex,
		DMSID:             dmsID,
		RequestType:       cmpTagToString(params.requestTag),
		SubjectCommonName: csr.Subject.CommonName,
		State:             cmpwfx.CMPStateAwaitingApproval,
		Metadata: withCMPMessageB64(map[string]any{
			"certReqId":      req.CertReqID,
			"isReenrollment": params.isReenrollment,
			"responseType":   cmpTagToString(params.respTag),
		}, cmpMetadataResponseB64, responseDER),
	})
}
