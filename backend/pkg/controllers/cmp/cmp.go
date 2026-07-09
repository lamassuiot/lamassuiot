package cmp

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	cmpwfx "github.com/lamassuiot/lamassuiot/backend/v3/pkg/integrations/wfx"
	identityextractors "github.com/lamassuiot/lamassuiot/backend/v3/pkg/routes/middlewares/identity-extractors"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/errs"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	"github.com/sirupsen/logrus"
)

// cmpTxTTL is the fallback lifetime of a pending CMP transaction waiting for
// certConf, used when the DMS does not configure ConfirmationTimeout.
const cmpTxTTL = 5 * time.Minute

// cmpApprovalTTL is how long a phased-workflow transaction waits in PENDING for
// an administrator to approve issuance before it is swept by DeleteExpired.
// It is far longer than the certConf window (cmpTxTTL) because approval is a
// human action, not an automated device round-trip — a 5-minute window would
// delete the request before an operator could ever act on it.
const cmpApprovalTTL = 7 * 24 * time.Hour

// cmpCtxKey is the type for context keys set by the CMP handler, avoiding
// collisions with other packages' context values.
type cmpCtxKey string

// cmpWorkflowCtxKey carries the resolved WFX workflow name for the current
// request so reportCMPState can route every transition to the right workflow.
const cmpWorkflowCtxKey cmpCtxKey = "cmp-workflow-name"

// confirmationTimeoutOrDefault returns the configured DMS confirmation timeout
// when positive, falling back to cmpTxTTL otherwise. RFC 4210 §5.2.8 specifies
// that the server controls how long it waits for certConf; the per-DMS setting
// is the source of truth.
func confirmationTimeoutOrDefault(t models.TimeDuration) time.Duration {
	if d := time.Duration(t); d > 0 {
		return d
	}
	return cmpTxTTL
}

// approvalTimeoutOrDefault returns the configured DMS approval timeout when
// positive, falling back to cmpApprovalTTL otherwise. Used only on the phased
// workflow PENDING insertion.
func approvalTimeoutOrDefault(t models.TimeDuration) time.Duration {
	if d := time.Duration(t); d > 0 {
		return d
	}
	return cmpApprovalTTL
}

// cmpTransactionStorer is implemented by DMSManagerServiceBackend and lets
// the CMP controller access the persistent transaction store without receiving
// it as an explicit parameter through every HTTP route function.
type cmpTransactionStorer interface {
	GetCMPTransactionRepo() storage.CMPTransactionRepo
}

type cmpWFXReporterProvider interface {
	GetCMPWFXReporter() cmpwfx.CMPReporter
}

// cmpHttpRoutes is the Gin handler for /.well-known/cmp/p/:id.
type cmpHttpRoutes struct {
	svc    services.LightweightCMPService
	logger *logrus.Entry
	store  storage.CMPTransactionRepo
	wfx    cmpwfx.CMPReporter
}

// NewCMPHttpRoutes creates and initialises the CMP HTTP handler.
//
// The persistent transaction store is REQUIRED: every CMP transaction needs
// idempotency (RFC 9810 §3.1 transactionIdInUse) and lost-response recovery
// (RFC 4210 §5.3.22 pollReq), neither of which can be honoured without it.
// The constructor extracts the store via the cmpTransactionStorer interface
// and returns an error if the service does not expose one — silently running
// without a store (the previous behaviour) would have let production traffic
// bypass duplicate-tx detection entirely.
func NewCMPHttpRoutes(logger *logrus.Entry, svc services.LightweightCMPService) (*cmpHttpRoutes, error) {
	storer, ok := svc.(cmpTransactionStorer)
	if !ok {
		return nil, fmt.Errorf("CMP: service %T does not implement cmpTransactionStorer; a persistent transaction store is required", svc)
	}
	repo := storer.GetCMPTransactionRepo()
	if repo == nil {
		return nil, fmt.Errorf("CMP: service %T returned a nil CMPTransactionRepo; a persistent transaction store is required", svc)
	}
	var reporter cmpwfx.CMPReporter
	if provider, ok := svc.(cmpWFXReporterProvider); ok {
		reporter = provider.GetCMPWFXReporter()
	}
	return &cmpHttpRoutes{svc: svc, logger: logger, store: repo, wfx: reporter}, nil
}

// HandleCMP handles all inbound CMP messages posted to /.well-known/cmp/p/:id.
//
// It reads a DER-encoded PKIMessage, dispatches on the body CHOICE tag, calls
// the appropriate LightweightCMPService operation, and returns a DER-encoded
// response.
func (r *cmpHttpRoutes) HandleCMP(ctx *gin.Context) {
	lFunc := r.logger.WithField("component", "cmp-handler")

	// Identify DMS from path /:id
	dmsID := ctx.Param("id")
	if dmsID == "" {
		r.rejectWithError(ctx, nil, PKIStatus(2), "missing DMS id", "", pkiFailureInfoBadRequest)
		return
	}

	// Read DER body
	bodyBytes, err := io.ReadAll(ctx.Request.Body)
	if err != nil || len(bodyBytes) == 0 {
		r.rejectWithError(ctx, nil, PKIStatus(2), "cannot read request body", dmsID, pkiFailureInfoBadDataFormat)
		return
	}

	// Decode PKIMessage fully (including Protection and ExtraCerts for verification).
	var fullMsg rawPKIMessageFull
	if _, err := asn1.Unmarshal(bodyBytes, &fullMsg); err != nil {
		// RFC 6712 §3.3: a body that cannot be parsed as a PKIMessage at all is a
		// client-side input error. There is no valid PKIHeader to echo back, so a
		// signed CMP error body cannot be constructed — respond with a bare
		// HTTP 400 ("Client Error 4xx") rather than a 200 carrying an error body.
		lFunc.Warnf("failed to unmarshal PKIMessage: %v", err)
		ctx.Status(http.StatusBadRequest)
		return
	}

	header := fullMsg.Header
	body := fullMsg.Body

	reqHeader, err := decodeRequestHeader(header.FullBytes)
	if err != nil {
		lFunc.Warnf("failed to decode PKIHeader: %v", err)
		r.rejectWithError(ctx, nil, PKIStatus(2), "malformed PKIHeader", dmsID, pkiFailureInfoBadDataFormat)
		return
	}

	// Run wire-level envelope validation (pvno, transactionID, senderNonce,
	// messageTime drift). See cmp_validator.go — extracted so the controller
	// stays a dispatcher and each rule is unit-testable in isolation.
	if rej := validateRequestEnvelope(reqHeader, time.Now(), body.Tag); rej != nil {
		lFunc.Warnf("envelope validation: %s", rej.reason)
		r.rejectWithError(ctx, &reqHeader, PKIStatus(2), rej.reason, dmsID, rej.failInfo)
		return
	}

	// RFC 9483 §3.1: recipNonce MUST be absent in the initial request of a
	// transaction (ir/cr). If the EE set it, reject per §3.5 badRecipientNonce.
	if (body.Tag == cmpBodyTagIR || body.Tag == cmpBodyTagCR) && len(reqHeader.RecipNonce) > 0 {
		lFunc.Warnf("recipNonce present on initial %s message", cmpTagToString(body.Tag))
		r.rejectWithError(ctx, &reqHeader, PKIStatus(2),
			"recipNonce must be absent in the initial request (RFC 9483 §3.1)",
			dmsID, pkiFailureInfoBadRecipientNonce)
		return
	}

	lFunc = lFunc.
		WithField("dms", dmsID).
		WithField("bodyTag", body.Tag).
		WithField("bodyTagStr", cmpTagToString(body.Tag)).
		WithField("txid", hex.EncodeToString(reqHeader.TransactionID))
	lFunc.Debugf("received CMP message body tag=%d", body.Tag)
	txHex := hex.EncodeToString(reqHeader.TransactionID)

	// WFX jobs are keyed by clientId = device CN, so we need the CN
	// before the very first state emission. For enrollment requests
	// (ir/cr/kur) the CN lives inside the CertReqMessage's CertTemplate;
	// for follow-up requests (pollReq/certConf/rr) the CN comes from the
	// already-persisted transaction row. Failure to extract is non-fatal:
	// the Emit call drops the transition silently when CN is empty, which
	// is the right behaviour for malformed bodies that we'll reject below.
	deviceCN := r.resolveDeviceCN(ctx.Request.Context(), body, txHex)

	// Fetch DMS enrollment options so we can make per-request decisions
	// (request-protection enforcement, implicit-confirm mode, workflow
	// selection, etc.). Loaded before the first WFX emission so the device's
	// job is created in the DMS's chosen workflow (direct vs phased).
	enrollOpts, err := r.svc.LWCGetEnrollmentOptions(ctx.Request.Context(), dmsID)
	if err != nil {
		lFunc.Errorf("could not load enrollment options for DMS '%s': %v", dmsID, err)
		r.rejectWithError(ctx, &reqHeader, PKIStatus(2), "could not load DMS configuration", dmsID, pkiFailureInfoSystemFailure)
		return
	}

	// Stash the resolved WFX workflow name on the request context so every
	// reportCMPState call for this request lands in (and only transitions
	// within) the DMS's selected workflow.
	workflowName := cmpwfx.WorkflowNameFor(enrollOpts.Workflow)
	ctx.Request = ctx.Request.WithContext(context.WithValue(ctx.Request.Context(), cmpWorkflowCtxKey, workflowName))

	// Received is only meaningful for enrollment-initiating messages
	// (IR/CR/KUR). Follow-up messages (certConf, pollReq, rr) reference an
	// already-created WFX job that is well past Received; emitting it on such
	// jobs would attempt an invalid backward transition (e.g. AwaitingCertConf
	// → Received) which either gets rejected by WFX or silently resets the job
	// to the wrong state.
	if body.Tag == cmpBodyTagIR || body.Tag == cmpBodyTagCR || body.Tag == cmpBodyTagKUR {
		r.reportCMPState(ctx.Request.Context(), lFunc, cmpwfx.CMPTransition{
			TransactionID:     txHex,
			DMSID:             dmsID,
			RequestType:       cmpTagToString(body.Tag),
			SubjectCommonName: deviceCN,
			State:             cmpwfx.CMPStateReceived,
			Metadata: withCMPMessageB64(map[string]any{
				"bodyTag": body.Tag,
			}, cmpMetadataRequestB64, bodyBytes),
		})
	}

	// Verify signature-based protection on the incoming request. When the
	// request is protected, the parsed EE signer cert (extraCerts[0]) is
	// returned and stashed on the request context so downstream service
	// methods (LWCEnroll, LWCReenroll) can apply ValidationCAs, RFC 9483
	// §4.1.3 signer binding, and revocation checks — mirroring the EST
	// mTLS auth path.
	//
	// Whether an *unprotected* message is rejected at the wire layer is
	// derived from the DMS's auth_mode: CLIENT_CERTIFICATE and the combined
	// mode require a signer cert (and therefore protection); the other modes
	// (NO_AUTH, EXTERNAL_WEBHOOK) accept unsigned messages. auth_mode is the
	// single source of truth for the protection requirement — there is no
	// separate enforce_request_protection knob.
	requireProtection := enrollOpts.AuthMode == models.EnrollmentAuthModeClientCertificate || enrollOpts.AuthMode == models.EnrollmentAuthModeClientCertificateAndWebhook
	signerCert, err := verifyRequestProtection(fullMsg, reqHeader.ProtectionAlg, requireProtection)
	if err != nil {
		lFunc.Warnf("protection verification failed: %v", err)
		// Map error category to PKIFailureInfo per RFC 9810 §5.1.3 / RFC 9483
		// §3.6.4: a rejected protection AlgorithmIdentifier carries its own bit
		// (badAlg for an unknown/unsupported algorithm, wrongIntegrity for a
		// MAC-based protection where a signature was required); anything else
		// (signature mismatch, missing extraCerts, malformed protection field)
		// maps to badMessageCheck.
		failBit := pkiFailureInfoBadMessageCheck
		if algBit, ok := protectionAlgFailInfo(err); ok {
			failBit = algBit
		}
		r.rejectRequest(ctx, lFunc, reqHeader, body.Tag,
			fmt.Sprintf("protection verification failed: %v", err), failBit, dmsID)
		return
	}
	if signerCert != nil {
		// genm support messages (RFC 9483 §4.3) are informational queries whose
		// response does not depend on the EE's identity. The compliance suite
		// deliberately sends several of them with sender/senderKID omitted, so we
		// keep the signature-integrity check above but skip the sender-DN and
		// senderKID binding checks that are meaningful only for issuance/
		// revocation requests bound to a specific certificate.
		if body.Tag != cmpBodyTagGenMsg {
			// RFC 9483 §3.5: with signature-based protection, the sender field MUST
			// match the subject of the protection cert. Without this check, a
			// captured & forwarded message with a tampered sender field would pass
			// validation despite naming an identity other than the protection
			// cert's subject (badMessageCheck per the RFC's failInfo mapping).
			if rej := verifySenderMatchesProtectionCert(reqHeader.Sender, signerCert); rej != nil {
				lFunc.Warnf("sender/subject mismatch: %s", rej.reason)
				r.rejectRequest(ctx, lFunc, reqHeader, body.Tag, rej.reason, rej.failInfo, dmsID)
				return
			}
			// RFC 9483 §3.1: signature-based protection MUST carry senderKID equal to
			// the protection cert's SubjectKeyIdentifier. Missing/mismatched senderKID
			// is badMessageCheck.
			if rej := verifySenderKIDMatchesProtectionCert(reqHeader.SenderKID, signerCert); rej != nil {
				lFunc.Warnf("senderKID validation: %s", rej.reason)
				r.rejectRequest(ctx, lFunc, reqHeader, body.Tag, rej.reason, rej.failInfo, dmsID)
				return
			}
		}
		reqCtx := context.WithValue(ctx.Request.Context(), string(identityextractors.IdentityExtractorCMPSignerCertificate), signerCert)
		ctx.Request = ctx.Request.WithContext(reqCtx)
	}

	// RFC 9483 §5.2.3: when a PKI management entity forwards the EE's original
	// message inside generalInfo (id-it-origPKIMessage), the CA MUST verify that
	// original message's own protection. The RA is vouching (e.g. via
	// raVerified) for a message the EE signed; a broken original protection
	// means that assertion cannot be trusted, so the request is rejected with
	// badMessageCheck (RFC 9483 §3.5) regardless of the outer RA protection
	// being valid.
	if origFull, origAlg, ok := extractOrigPKIMessage(reqHeader.GeneralInfo); ok {
		if _, err := verifyRequestProtection(*origFull, origAlg, true); err != nil {
			lFunc.Warnf("origPKIMessage protection verification failed: %v", err)
			r.rejectRequest(ctx, lFunc, reqHeader, body.Tag,
				fmt.Sprintf("original PKIMessage (generalInfo) protection verification failed: %v", err),
				pkiFailureInfoBadMessageCheck, dmsID)
			return
		}
	}

	// Dispatch on body CHOICE tag
	switch body.Tag {
	case cmpBodyTagIR, cmpBodyTagCR:
		r.handleEnrollment(ctx, lFunc, reqHeader, body, dmsID, enrollOpts, enrollmentVariantInitial)
	case cmpBodyTagKUR:
		r.handleEnrollment(ctx, lFunc, reqHeader, body, dmsID, enrollOpts, enrollmentVariantUpdate)
	case cmpBodyTagRR:
		r.handleRevoke(ctx, lFunc, reqHeader, body, dmsID)
	case cmpBodyTagCCR:
		r.handleCrossCertification(ctx, lFunc, reqHeader, body, dmsID)
	case cmpBodyTagNested:
		r.handleNested(ctx, lFunc, reqHeader, body, dmsID)
	case cmpBodyTagCertConf:
		r.handleCertConf(ctx, lFunc, reqHeader, body, bodyBytes, dmsID)
	case cmpBodyTagPollReq:
		r.handlePoll(ctx, lFunc, reqHeader, body, dmsID, enrollOpts)
	case cmpBodyTagGenMsg:
		r.handleGeneralMessage(ctx, lFunc, reqHeader, body, dmsID)
	default:
		lFunc.Warnf("unsupported CMP body tag %d", body.Tag)
		r.rejectWithError(ctx, &reqHeader, PKIStatus(2),
			fmt.Sprintf("unsupported body tag %d", body.Tag), dmsID, pkiFailureInfoBadRequest)
	}
}

// The enrollment pipeline lives in cmp_enrollment.go (audit A2 extraction):
// handleEnrollment, issueAndStore, deferForApproval, enrollmentVariantInitial,
// enrollmentVariantUpdate, issueParams. Methods on *cmpHttpRoutes from that
// file are part of the same package so HandleCMP can dispatch to them
// directly.

// handleRevoke processes an rr (11) body.
//
// It validates the RevDetails against the protection (signer) certificate — the
// certificate being revoked signs its own rr (RFC 9483 §4.2) — and against the
// CRLReason rules, then calls LWCRevokeCertificate. A single removeFromCRL (8)
// CRLReason is treated as a revive request. Every failure is reported via an rp
// body's PKIStatusInfo (RFC 9483 §4.2), never a generic error body.
func (r *cmpHttpRoutes) handleRevoke(ctx *gin.Context, lFunc *logrus.Entry, header requestPKIHeader, body asn1.RawValue, dmsID string) {
	rd, err := decodeRevDetails(body.Bytes)
	if err != nil {
		lFunc.Errorf("rr: decode RevDetails: %v", err)
		r.rejectRevocation(ctx, lFunc, header, "malformed RevReqContent", pkiFailureInfoBadDataFormat, dmsID)
		return
	}

	// --- CRLReason validation (RFC 9483 §4.2 / RFC 5280 §5.3.1) ---
	// More than one CRLReason extension (including a revoke+revive mix) is a
	// malformed request → badRequest.
	if rd.ReasonExtCount > 1 {
		lFunc.Warnf("rr: %d CRLReason extensions present", rd.ReasonExtCount)
		r.rejectRevocation(ctx, lFunc, header, "more than one CRLReason extension", pkiFailureInfoBadRequest, dmsID)
		return
	}
	if rd.ReasonDecodeErr {
		r.rejectRevocation(ctx, lFunc, header, "malformed CRLReason value", pkiFailureInfoBadDataFormat, dmsID)
		return
	}
	for _, rc := range rd.Reasons {
		if !isKnownCRLReason(rc) {
			lFunc.Warnf("rr: unknown CRLReason %d", rc)
			r.rejectRevocation(ctx, lFunc, header, fmt.Sprintf("unknown CRLReason %d", rc), pkiFailureInfoBadDataFormat, dmsID)
			return
		}
	}
	reason := 0
	if len(rd.Reasons) == 1 {
		reason = rd.Reasons[0]
	}
	revive := reason == crlReasonRemoveFromCRL

	// --- CertTemplate validation against the protection certificate ---
	// The cert being revoked signs its own rr, so its CertTemplate fields MUST
	// match the signer cert. This is only enforced for protected requests; an
	// unprotected request (NO_AUTH DMS, no signer cert) revokes by serial alone.
	signer := cmpSignerCertFromGin(ctx)
	if signer != nil {
		if !rd.HasIssuer {
			r.rejectRevocation(ctx, lFunc, header, "missing issuer in CertTemplate", pkiFailureInfoAddInfoNotAvailable, dmsID)
			return
		}
		if !rd.HasSerial {
			r.rejectRevocation(ctx, lFunc, header, "missing serialNumber in CertTemplate", pkiFailureInfoAddInfoNotAvailable, dmsID)
			return
		}
		if signer.SerialNumber != nil &&
			new(big.Int).SetBytes(rd.SerialNumber).Cmp(signer.SerialNumber) != 0 {
			r.rejectRevocation(ctx, lFunc, header, "serialNumber does not match certificate", pkiFailureInfoBadCertId, dmsID)
			return
		}
		// Compare the issuer/subject Names semantically rather than by raw DER:
		// CMP clients re-encode the Name from the parsed certificate, so the
		// byte encoding (string types, etc.) can legitimately differ from the
		// certificate's original RawIssuer/RawSubject even when the names are
		// equal. A raw bytes.Equal here would reject every valid revocation.
		if !certTemplateNameMatches(rd.IssuerDER, signer.Issuer) {
			r.rejectRevocation(ctx, lFunc, header, "issuer does not match certificate", pkiFailureInfoBadCertId, dmsID)
			return
		}
		if rd.HasSubject && !certTemplateNameMatches(rd.SubjectDER, signer.Subject) {
			r.rejectRevocation(ctx, lFunc, header, "subject does not match certificate", pkiFailureInfoBadCertId, dmsID)
			return
		}
		if rd.HasPublicKey && !bytes.Equal(rd.PublicKeyDER, signer.RawSubjectPublicKeyInfo) {
			r.rejectRevocation(ctx, lFunc, header, "publicKey does not match certificate", pkiFailureInfoBadCertId, dmsID)
			return
		}
	} else if !rd.HasSerial {
		r.rejectRevocation(ctx, lFunc, header, "missing serialNumber in CertTemplate", pkiFailureInfoBadDataFormat, dmsID)
		return
	}

	serialHex := hex.EncodeToString(rd.SerialNumber)
	lFunc = lFunc.WithField("serial", serialHex)
	lFunc.Infof("revocation request serial=%s reason=%d revive=%t", serialHex, reason, revive)

	if err := r.svc.LWCRevokeCertificate(ctx.Request.Context(), services.RevokeCertificateInput{
		APS:          dmsID,
		SerialNumber: serialHex,
		Reason:       models.RevocationReason(reason),
	}); err != nil {
		lFunc.Errorf("rr: revoke failed: %v", err)
		// Map the service-layer error to the appropriate PKIFailureInfo bit
		// (RFC 9810 §5.1.3 / RFC 9483 §3.6.4) and deliver it in an rp body:
		//   - certificate not found / bad serial                  → badCertId
		//   - illegal status transition on a revoke (already
		//     revoked)                                            → certRevoked
		//   - illegal status transition on a revive (target is
		//     not revoked / cannot be revived)                    → badCertId
		//   - anything else                                       → systemFailure
		failBit := pkiFailureInfoSystemFailure
		switch {
		case errors.Is(err, errs.ErrCertificateNotFound):
			failBit = pkiFailureInfoBadCertId
		case errors.Is(err, errs.ErrCMPPendingUpdate):
			// The device has a key-update awaiting certConf; its certificates'
			// revocation state must not change until the open transaction
			// completes or times out (RFC 9483 §4.1.3).
			failBit = pkiFailureInfoBadRequest
		case errors.Is(err, errs.ErrCertificateStatusTransitionNotAllowed):
			if revive {
				failBit = pkiFailureInfoBadCertId
			} else {
				failBit = pkiFailureInfoCertRevoked
			}
		}
		r.rejectRevocation(ctx, lFunc, header, err.Error(), failBit, dmsID)
		return
	}

	// Transition the CMP transaction to REVOKED for audit visibility.
	if markErr := r.store.MarkRevokedByCertSerial(ctx.Request.Context(), serialHex); markErr != nil {
		lFunc.Warnf("rr: failed to mark transaction as revoked: %v", markErr)
	}

	statusText := "Certificate revoked"
	if revive {
		statusText = "Certificate revived"
	}
	rpDER, err := marshalRevRepBody(PKIStatus(0), statusText)
	if err != nil {
		lFunc.Errorf("rr: build rp body: %v", err)
		r.rejectRevocation(ctx, lFunc, header, "cannot build rp response", pkiFailureInfoSystemFailure, dmsID)
		return
	}
	r.sendRawBody(ctx, lFunc, header, cmpBodyTagRP, rpDER, dmsID)
}

// handleCertConf processes a certConf (24) body.
// It verifies the SHA-256 certHash and responds with pkiConf (19).
func (r *cmpHttpRoutes) handleCertConf(ctx *gin.Context, lFunc *logrus.Entry, header requestPKIHeader, body asn1.RawValue, requestDER []byte, dmsID string) {
	// The PKIBody CHOICE uses EXPLICIT tagging (RFC 4210 Appendix F module),
	// so certConf [24] EXPLICIT CertConfirmContent means body.Bytes already
	// holds the complete CertConfirmContent SEQUENCE TLV. Decode it directly —
	// do NOT re-wrap it in another SEQUENCE, otherwise the decoder would see a
	// single element (the inner SEQUENCE) and silently collapse a multi-status
	// / wrong-certReqId body into one accepted entry.
	statuses, err := decodeCertConfStatuses(body.Bytes)
	if err != nil {
		lFunc.Errorf("certConf: decode: %v", err)
		r.rejectWithError(ctx, &header, PKIStatus(2), "malformed certConf", dmsID, pkiFailureInfoBadDataFormat)
		return
	}

	// --- Structural validation of the CertConfirmContent (RFC 9483 §4.1.1) ---
	// These checks are independent of the transaction state, so they run before
	// the transaction lookup.
	//
	// The LwCMP profile issues exactly one certificate per ir/cr/kur, so the
	// confirmation MUST carry exactly one CertStatus.
	if len(statuses) != 1 {
		lFunc.Warnf("certConf: expected exactly one CertStatus, got %d", len(statuses))
		r.rejectWithError(ctx, &header, PKIStatus(2),
			fmt.Sprintf("certConf must carry exactly one CertStatus, got %d", len(statuses)),
			dmsID, pkiFailureInfoBadRequest)
		return
	}
	// The certReqId of the first (and only) issued certificate is 0
	// (RFC 9483 §4.1.1). A negative or non-zero value is malformed; p10cr's
	// special -1 value is out of scope for this profile.
	if statuses[0].CertReqID != 0 {
		lFunc.Warnf("certConf: invalid certReqId %d (must be 0)", statuses[0].CertReqID)
		r.rejectWithError(ctx, &header, PKIStatus(2),
			fmt.Sprintf("certConf certReqId must be 0, got %d", statuses[0].CertReqID),
			dmsID, pkiFailureInfoBadRequest)
		return
	}
	// A CertStatus declaring status "accepted" MUST NOT also carry a failInfo —
	// the two are mutually inconsistent (RFC 9483 §4.1.1 / RFC 4210 §5.2.3).
	if statuses[0].StatusInfo.Status == PKIStatus(pkiStatusAccepted) && statuses[0].StatusInfo.FailInfo.BitLength > 0 {
		lFunc.Warnf("certConf: status 'accepted' carries a failInfo (inconsistent)")
		r.rejectWithError(ctx, &header, PKIStatus(2),
			"certConf status 'accepted' must not include a failInfo",
			dmsID, pkiFailureInfoBadRequest)
		return
	}
	// id-it-implicitConfirm is only permitted in the generalInfo of an
	// ir/cr/kur/p10cr request or an ip/cp/kup response (RFC 9483 §3.1); it is
	// prohibited on every other body, including certConf. An EE that sets it on
	// a certConf sent a malformed header → badRequest (RFC 9483 §3.5).
	if hasImplicitConfirmOID(header.GeneralInfo) {
		lFunc.Warnf("certConf: implicitConfirm present in generalInfo (prohibited outside ir/cr/kur/ip/cp/kup, RFC 9483 §3.1)")
		r.rejectWithError(ctx, &header, PKIStatus(2),
			"implicitConfirm is not permitted in a certConf message (RFC 9483 §3.1)",
			dmsID, pkiFailureInfoBadRequest)
		return
	}

	txHex := hex.EncodeToString(header.TransactionID)
	tx, ok, err := r.store.Select(ctx.Request.Context(), txHex)
	if err != nil {
		lFunc.Errorf("certConf: lookup transaction: %v", err)
		r.rejectWithError(ctx, &header, PKIStatus(2), "internal error", dmsID, pkiFailureInfoSystemFailure)
		return
	}
	if !ok {
		// Distinguish "row never existed" from "row past ExpiresAt but not yet
		// swept by the confirmation monitor". Both are rejections, but the EE
		// gets actionable information (and the correct PKIFailureInfo bit) only
		// when we surface the expired case explicitly per RFC 9483 §3.6.4.
		if expiredTx, found, exErr := r.store.SelectIncludingExpired(ctx.Request.Context(), txHex); exErr == nil && found {
			lFunc.Warnf("certConf: transaction %s expired at %s (state=%s)",
				txHex, expiredTx.ExpiresAt.Format(time.RFC3339), expiredTx.State)
			// The transaction once existed but its confirmation window has
			// elapsed — RFC 9810 §5.1.3 incorrectData is "for notary services"
			// and does not apply. badRequest is the closest fit: the request
			// is no longer permitted at the current state of the transaction.
			r.rejectWithError(ctx, &header, PKIStatus(2),
				"transaction expired: confirmation_timeout exceeded", dmsID,
				pkiFailureInfoBadRequest)
			return
		}
		lFunc.Warnf("certConf: unknown transactionID %s", txHex)
		r.rejectWithError(ctx, &header, PKIStatus(2), "unknown transactionID", dmsID, pkiFailureInfoBadRequest)
		return
	}

	// RFC 9810 §5.1.1 / RFC 9483 §3.1 line 753: the EE's recipNonce on a
	// follow-up message MUST equal the server's previous senderNonce. The
	// dedicated PKIFailureInfo bit for this is badRecipientNonce (13).
	sentNonce, _ := hex.DecodeString(tx.SentNonce)
	if len(sentNonce) > 0 && !bytes.Equal(header.RecipNonce, sentNonce) {
		lFunc.Errorf("certConf: recipNonce mismatch: got %x want %x", header.RecipNonce, sentNonce)
		r.rejectWithError(ctx, &header, PKIStatus(2), "recipNonce mismatch", dmsID, pkiFailureInfoBadRecipientNonce)
		return
	}

	// RFC 9483 §3.1: every message carries a *fresh* senderNonce. A certConf that
	// reuses the senderNonce from the initiating request (ir/cr/kur) defeats the
	// replay protection, so reject it with badSenderNonce.
	recvNonce, _ := hex.DecodeString(tx.ReceivedNonce)
	if len(recvNonce) > 0 && bytes.Equal(header.SenderNonce, recvNonce) {
		lFunc.Errorf("certConf: senderNonce reuses the initiating request's senderNonce")
		r.rejectWithError(ctx, &header, PKIStatus(2),
			"certConf senderNonce must be fresh, not reused from the initial request (RFC 9483 §3.1)",
			dmsID, pkiFailureInfoBadSenderNonce)
		return
	}

	// RFC 9483 §4.1.1: the certConf MUST be protected with the same credential
	// as the original request, not the newly issued certificate. The EE cannot
	// use the just-issued cert to confirm itself — it hasn't been confirmed yet,
	// so it is not a valid protection credential for this transaction. Detect
	// this by comparing the certConf signer against the issued cert: if they are
	// the same certificate, the confirmation used the wrong authority.
	if signer := cmpSignerCertFromGin(ctx); signer != nil && tx.CertSerialNumber != "" {
		signerSerial := hex.EncodeToString(signer.SerialNumber.Bytes())
		if signerSerial == tx.CertSerialNumber {
			lFunc.Errorf("certConf: protected with the newly issued cert (SN=%s) instead of the request credential", signerSerial)
			r.rejectWithError(ctx, &header, PKIStatus(2),
				"certConf must be protected with the original request credential, not the newly issued certificate (RFC 9483 §4.1.1)",
				dmsID, pkiFailureInfoBadRequest)
			return
		}
	}

	for i, s := range statuses {
		// RFC 9810 §5.3.18: "If hashAlg is used, the CMP version indicated by
		// the certConf message header must be cmp2021(3)." When the EE declares
		// pvno=2 yet includes hashAlg, the payload's data format is inconsistent
		// with the declared version. We use badDataFormat — not unsupportedVersion
		// — because the server DOES support pvno=2; the EE simply put cmp2021-only
		// syntax in a cmp2000-declared message. (RFC 9810 §7 reserves
		// unsupportedVersion for the case where the server doesn't support the
		// declared version at all.)
		if len(s.HashAlgOID) > 0 && header.PVNO != pvnoCMP2021 {
			lFunc.Warnf("certConf: entry %d carries hashAlg %v but pvno=%d (RFC 9810 §5.3.18 requires cmp2021)",
				i, s.HashAlgOID, header.PVNO)
			r.rejectWithError(ctx, &header, PKIStatus(2),
				"CertStatus.hashAlg requires cmp2021(3) (RFC 9810 §5.3.18)",
				dmsID, pkiFailureInfoBadDataFormat)
			return
		}
		expected, hashErr := computeCertHash(tx.Certificate.Raw, s.HashAlgOID)
		if hashErr != nil {
			lFunc.Errorf("certConf: entry %d unsupported hashAlg %v: %v", i, s.HashAlgOID, hashErr)
			r.rejectWithError(ctx, &header, PKIStatus(2),
				fmt.Sprintf("unsupported certConf hashAlg OID %v", s.HashAlgOID), dmsID, pkiFailureInfoBadAlg)
			return
		}
		if !hashesEqual(s.CertHash, expected) {
			lFunc.Errorf("certConf: entry %d certHash mismatch", i)
			// The EE's claimed certHash does not match the issued cert — they
			// are confirming a different certificate. badCertId (4) says
			// "no certificate could be found matching the provided criteria"
			// which fits more precisely than the generic badRequest.
			r.rejectWithError(ctx, &header, PKIStatus(2), "certHash mismatch", dmsID, pkiFailureInfoBadCertId)
			return
		}
		lFunc.Debugf("certConf: entry %d certReqId=%d hash OK", i, s.CertReqID)
	}

	lFunc.Infof("certConf verified, transitioning to CONFIRMED")
	_, prior, updated, confirmErr := r.store.Confirm(ctx.Request.Context(), txHex)
	if confirmErr != nil {
		lFunc.Errorf("certConf: confirm storage error: %v", confirmErr)
		r.rejectWithError(ctx, &header, PKIStatus(2), "internal error: storage", dmsID, pkiFailureInfoSystemFailure)
		return
	}
	if !updated {
		switch prior {
		case storage.CMPTransactionStateRevoked:
			// Race we MUST surface (audit S1): between this handler's Select
			// and Confirm, the confirmation monitor revoked the cert at the
			// CA. The EE believes enrollment succeeded but the cert is gone.
			// Reject so the EE re-enrolls instead of acting on a dead cert.
			lFunc.Warnf("certConf: tx %s already REVOKED — race with confirmation monitor", txHex)
			r.rejectWithError(ctx, &header, PKIStatus(2),
				"certificate was revoked before confirmation was processed", dmsID, pkiFailureInfoBadRequest)
			return
		case storage.CMPTransactionStateConfirmed:
			// Idempotent replay: certConf is allowed to be re-delivered if
			// the original pkiConf was lost in flight. Fall through to send
			// a fresh pkiConf without re-emitting the WFX Confirmed state.
			lFunc.Infof("certConf: tx %s already CONFIRMED — treating as idempotent replay", txHex)
		default:
			lFunc.Errorf("certConf: tx %s in unexpected prior state %q for confirmation", txHex, prior)
			r.rejectWithError(ctx, &header, PKIStatus(2),
				fmt.Sprintf("transaction in unexpected state %q for confirmation", prior), dmsID, pkiFailureInfoBadRequest)
			return
		}
	}

	pkiConfDER, err := marshalPKIConfBody()
	if err != nil {
		lFunc.Errorf("certConf: build pkiConf: %v", err)
		r.rejectWithError(ctx, &header, PKIStatus(2), "cannot build pkiConf", dmsID, pkiFailureInfoSystemFailure)
		return
	}
	// Commit the deferred key-update now that the EE has confirmed (RFC 9483
	// §4.1.3): bind the new cert as the device's active identity and supersede
	// the previous one. Only on a real transition (not an idempotent replay)
	// and only for re-enrollments — ir/cr bind their identity at issuance.
	if updated && tx.IsReenrollment {
		r.commitReenrollment(ctx.Request.Context(), lFunc, dmsID, tx.CertSerialNumber)
	}
	responseDER := r.sendRawBody(ctx, lFunc, header, cmpBodyTagPKIConf, pkiConfDER, dmsID)
	if len(responseDER) == 0 {
		return
	}
	// Only emit the WFX Confirmed transition when this call actually performed
	// the state change. An idempotent replay (prior was already CONFIRMED) has
	// already produced this transition once; re-emitting it would create a
	// spurious entry in the workflow timeline.
	if updated {
		r.reportCMPState(ctx.Request.Context(), lFunc, cmpwfx.CMPTransition{
			TransactionID:     txHex,
			DMSID:             dmsID,
			RequestType:       tx.RequestType,
			SubjectCommonName: tx.SubjectCommonName,
			CertSerialNumber:  tx.CertSerialNumber,
			State:             cmpwfx.CMPStateConfirmed,
			Metadata: withCMPMessageB64(
				withCMPMessageB64(nil, cmpMetadataCertConfB64, requestDER),
				cmpMetadataPKIConfB64,
				responseDER,
			),
		})
	}
}

// defaultPollIntervalSeconds is the checkAfter hint sent in pollRep messages.
// 60 seconds is the conventional minimum used by most CMP clients (incl.
// openssl cmp) and avoids tight polling loops.
const defaultPollIntervalSeconds = 60

const (
	cmpMetadataRequestB64  = "cmpRequestB64"
	cmpMetadataResponseB64 = "cmpResponseB64"
	cmpMetadataCertConfB64 = "certConfB64"
	cmpMetadataPKIConfB64  = "pkiConfB64"
)

// handlePoll processes a pollReq (25) body per RFC 4210 §5.3.22 / RFC 9483 §4.4.
// It looks up the transaction by transactionID (from the PKIHeader, not the
// certReqId — certReqId is just echoed back) and chooses a response based on
// the row's state:
//
//   - PENDING       → pollRep(checkAfter)         (dead path in sync-only mode)
//   - ISSUED        → ip/cp(cert)                 (deliver the cert; non-destructive)
//   - ISSUE_FAILED  → error PKIMessage(reason)    (dead path in sync-only mode)
//   - not found     → error PKIMessage("unknown transactionID")
//
// In the current sync-only mode, an ISSUED row is always present after the
// initial ip(cert), letting an EE recover when the original response was lost
// in transit (per RFC 4210 §5.3.22).
func (r *cmpHttpRoutes) handlePoll(ctx *gin.Context, lFunc *logrus.Entry, header requestPKIHeader, body asn1.RawValue, dmsID string, enrollOpts *models.EnrollmentOptionsLWCRFC9483) {
	certReqID, err := decodePollReqContent(body.Bytes)
	if err != nil {
		lFunc.Errorf("pollReq: decode: %v", err)
		r.rejectWithError(ctx, &header, PKIStatus(2), "malformed pollReq", dmsID, pkiFailureInfoBadDataFormat)
		return
	}
	lFunc = lFunc.WithField("certReqId", certReqID)

	txHex := hex.EncodeToString(header.TransactionID)
	tx, ok, err := r.store.Select(ctx.Request.Context(), txHex)
	if err != nil {
		lFunc.Errorf("pollReq: lookup transaction: %v", err)
		r.rejectWithError(ctx, &header, PKIStatus(2), "internal error", dmsID, pkiFailureInfoSystemFailure)
		return
	}
	if !ok {
		lFunc.Warnf("pollReq: unknown transactionID %s", txHex)
		r.rejectWithError(ctx, &header, PKIStatus(2), "unknown transactionID", dmsID, pkiFailureInfoBadRequest)
		return
	}

	switch tx.State {
	case storage.CMPTransactionStatePending:
		// Dead path in sync-only mode (no PENDING rows are created), but kept
		// for forward-compatibility if async issuance is reintroduced.
		checkAfter := defaultPollIntervalSeconds
		repDER, err := marshalPollRepBody(certReqID, checkAfter)
		if err != nil {
			lFunc.Errorf("pollReq: build pollRep: %v", err)
			r.rejectWithError(ctx, &header, PKIStatus(2), "cannot build pollRep", dmsID, pkiFailureInfoSystemFailure)
			return
		}
		lFunc.Infof("pollReq: tx %s still PENDING, replying pollRep(checkAfter=%ds)", txHex, checkAfter)
		r.sendRawBody(ctx, lFunc, header, cmpBodyTagPollRep, repDER, dmsID)

	case storage.CMPTransactionStateIssued:
		// Determine whether implicit confirm applies for this pollReq delivery.
		// When implicit, no certConf will follow and the row is transitioned to
		// CONFIRMED below. When explicit, the row stays in ISSUED awaiting certConf.
		implicitConfirm := r.isImplicitConfirm(ctx.Request.Context(), header, dmsID)
		header.ResponseImplicitConfirm = implicitConfirm

		if !implicitConfirm {
			// Explicit confirm: echo back the SenderNonce that was used in the
			// original IR/CR/KUR response — the same one persisted in
			// tx.SentNonce. handleCertConf will compare the EE's recipNonce
			// against this value, so the nonce on the wire and the nonce in DB
			// MUST match. In a clean IR → IP → certConf flow this happens
			// naturally because the EE echoes what it just received; in the
			// drop-and-recover flow (IR delivered but response lost, then
			// pollReq) the EE only ever sees the nonce we send here, so it has
			// to be the IR-time nonce or the certConf check fails. Generating a
			// fresh nonce per pollRep would also work but only if we persisted
			// it — UpdateState (cert_der + state + error_message) does not
			// touch sent_nonce, so refreshing here would silently desync DB
			// from wire and reject every subsequent certConf.
			header.ResponseSenderNonce, _ = hex.DecodeString(tx.SentNonce)
		}

		// Decide whether this delivery is an IP (ir-derived) or CP (cr/kur).
		// PENDING rows store IsReenrollment; for sync-stored ISSUED rows
		// (lost-response recovery) the original body tag is lost, so we default
		// to CP — both IP and CP carry the same CertRepMessage structure and
		// any modern CMP client accepts either as the cert-bearing response.
		respTag := cmpBodyTagCP
		if !tx.IsReenrollment {
			respTag = cmpBodyTagIP
		}
		var txCertRaw []byte
		if tx.Certificate != nil {
			txCertRaw = tx.Certificate.Raw
		}
		certRepDER, err := marshalCertRepBody(respTag, certReqID, txCertRaw)
		if err != nil {
			lFunc.Errorf("pollReq: build cert rep body: %v", err)
			r.rejectWithError(ctx, &header, PKIStatus(2), "cannot build response", dmsID, pkiFailureInfoSystemFailure)
			return
		}

		// When implicit confirm, transition the transaction to CONFIRMED —
		// no certConf message will arrive to do it later.
		// RFC 4210 §5.2.8: once the server grants implicit confirmation the
		// transaction is complete upon cert delivery.
		//
		// We MUST inspect the prior state: between our Select above and this
		// Confirm, the confirmation monitor could have revoked the row, and
		// silently dropping that race lets the EE walk away with a cert that
		// Lamassu and the CA both consider invalid (audit S2).
		if implicitConfirm {
			_, prior, updated, confirmErr := r.store.Confirm(ctx.Request.Context(), txHex)
			if confirmErr != nil {
				lFunc.Errorf("pollReq: confirm storage error: %v", confirmErr)
				r.rejectWithError(ctx, &header, PKIStatus(2), "internal error: storage", dmsID, pkiFailureInfoSystemFailure)
				return
			}
			if !updated {
				if prior == storage.CMPTransactionStateRevoked {
					lFunc.Warnf("pollReq: tx %s already REVOKED — race with confirmation monitor", txHex)
					r.rejectWithError(ctx, &header, PKIStatus(2),
						"certificate was revoked before implicit confirmation could be processed", dmsID, pkiFailureInfoBadRequest)
					return
				}
				// prior == CONFIRMED is fine (idempotent pollReq replay); any
				// other state should be impossible here because we entered
				// this branch via tx.State == ISSUED above.
				lFunc.Debugf("pollReq: tx %s already in state %q (idempotent replay)", txHex, prior)
			}
			// Commit the deferred key-update on the real transition, mirroring
			// handleCertConf: with implicit confirmation the transaction is
			// complete at delivery, so this is the moment the new cert becomes
			// the device's active identity (RFC 9483 §4.1.3). Covers the
			// phased-workflow and lost-response recovery paths, where the cert
			// is delivered via pollReq rather than the original KUP.
			if updated && tx.IsReenrollment {
				r.commitReenrollment(ctx.Request.Context(), lFunc, dmsID, tx.CertSerialNumber)
			}
		}

		lFunc.Infof("pollReq: tx %s ISSUED, delivering cert via %s (implicitConfirm=%v)", txHex, cmpTagToString(respTag), implicitConfirm)
		r.sendRawBody(ctx, lFunc, header, respTag, certRepDER, dmsID)

	case storage.CMPTransactionStateConfirmed:
		// Lost-response recovery for implicit-confirm enrollments: the IR
		// already drove the row to CONFIRMED at IP delivery (RFC 4210 §5.2.8),
		// but the EE never received the IP. The pollReq retries; we re-deliver
		// the cert and leave the row in CONFIRMED. No certConf will follow and
		// no nonce echo is needed.
		respTag := cmpBodyTagCP
		if !tx.IsReenrollment {
			respTag = cmpBodyTagIP
		}
		var txCertRaw []byte
		if tx.Certificate != nil {
			txCertRaw = tx.Certificate.Raw
		}
		certRepDER, err := marshalCertRepBody(respTag, certReqID, txCertRaw)
		if err != nil {
			lFunc.Errorf("pollReq: build cert rep body for CONFIRMED row: %v", err)
			r.rejectWithError(ctx, &header, PKIStatus(2), "cannot build response", dmsID, pkiFailureInfoSystemFailure)
			return
		}
		// Echo the implicit-confirm OID so the EE sees the same negotiation it
		// originally received on the lost IP — keeps the protocol view consistent.
		header.ResponseImplicitConfirm = true
		lFunc.Infof("pollReq: tx %s CONFIRMED (implicit), re-delivering cert via %s", txHex, cmpTagToString(respTag))
		r.sendRawBody(ctx, lFunc, header, respTag, certRepDER, dmsID)

	case storage.CMPTransactionStateIssueFailed:
		reason := tx.ErrorMessage
		if reason == "" {
			reason = "issuance failed"
		}
		lFunc.Warnf("pollReq: tx %s ISSUE_FAILED, returning CMP error: %s", txHex, reason)
		// CA-layer issuance failure surfaced via pollReq — same rationale as
		// the inline enroll-error path above (systemFailure until structured
		// service-layer error categories exist).
		r.rejectWithError(ctx, &header, PKIStatus(pkiStatusRejection), reason, dmsID, pkiFailureInfoSystemFailure)

	default:
		lFunc.Errorf("pollReq: tx %s has unknown state %q", txHex, tx.State)
		r.rejectWithError(ctx, &header, PKIStatus(2), "internal error: unknown transaction state", dmsID, pkiFailureInfoSystemFailure)
	}
}

// isImplicitConfirm reports whether the current request should be treated as
// implicitly confirmed — i.e. the DMS is configured to accept implicit
// confirmation AND the EE included the id-it-implicitConfirm OID in the
// request's generalInfo header.
func (r *cmpHttpRoutes) isImplicitConfirm(ctx context.Context, header requestPKIHeader, dmsID string) bool {
	if !hasImplicitConfirmOID(header.GeneralInfo) {
		return false
	}
	opts, err := r.svc.LWCGetEnrollmentOptions(ctx, dmsID)
	if err != nil || opts == nil {
		return false
	}
	return opts.AcceptImplicit
}

// reportCMPState fans the given transition out to WFX and returns the
// resolved WFX job ID, which is "" when the integration is disabled, when
// the transition was dropped (e.g. no SubjectCommonName yet), or when the
// WFX call itself failed. Callers that need to persist the job ID (e.g.
// issueAndStore) should capture the return value; others can ignore it.
func (r *cmpHttpRoutes) reportCMPState(ctx context.Context, lFunc *logrus.Entry, transition cmpwfx.CMPTransition) string {
	if r.wfx == nil || transition.TransactionID == "" {
		return ""
	}

	// Route the transition to the DMS's selected workflow (stashed on the
	// context at the top of HandleCMP). Leaving Workflow empty would fall back
	// to the reporter's default workflow, which is wrong for phased DMSs.
	if transition.Workflow == "" {
		if wf, ok := ctx.Value(cmpWorkflowCtxKey).(string); ok {
			transition.Workflow = wf
		}
	}

	if transition.Metadata == nil {
		transition.Metadata = map[string]any{}
	}
	jobID, err := r.wfx.Emit(ctx, transition)
	if err != nil {
		lFunc.WithField("cmpState", transition.State).Warnf("WFX CMP transition export failed: %v", err)
		return ""
	}
	return jobID
}

func withCMPMessageB64(metadata map[string]any, key string, der []byte) map[string]any {
	if key == "" || len(der) == 0 {
		return metadata
	}
	if metadata == nil {
		metadata = map[string]any{}
	}
	metadata[key] = base64.StdEncoding.EncodeToString(der)
	return metadata
}

// hashesEqual compares two byte slices in constant time.
func hashesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

//	sends a CMP Error PKIMessage response.
//
// header may be nil if the incoming PKIMessage header could not be parsed.
// rejectCertRequest sends an ip/cp/kup body with a single CertResponse whose
// status is rejection. Use this for cert-request-level failures (bad POP,
// missing subject, invalid certReqId, etc.) where RFC 9483 §4.1 requires the
// CertRepMessage body type rather than the error body type.
func (r *cmpHttpRoutes) rejectCertRequest(ctx *gin.Context, lFunc *logrus.Entry, header requestPKIHeader, respTag int, dmsID string, rej *certRequestRejection) {
	body, err := marshalCertRepRejectionBody(rej.CertReqID, rej.Reason, rej.FailInfoBit)
	if err != nil {
		lFunc.Errorf("build cert rep rejection body: %v", err)
		r.rejectWithError(ctx, &header, PKIStatus(pkiStatusRejection), rej.Reason, dmsID, rej.FailInfoBit)
		return
	}
	// A rejection carries no issued certificate, so implicit confirmation is
	// meaningless: RFC 9483 §4.1.1 only allows id-it-implicitConfirm in the
	// generalInfo of a positive ip/cp/kup. Clear any flag carried over from the
	// enrollment attempt so the negative response never advertises it.
	header.ResponseImplicitConfirm = false
	r.sendRawBody(ctx, lFunc, header, respTag, body, dmsID)
}

// rejectRevocation sends an rp (RevRepContent) body carrying a rejection
// status. RFC 9483 §4.2 mandates that the response to an rr message is always
// an rp body — even on failure the rejection is conveyed via the rp's
// PKIStatusInfo (status=rejection, failInfo bit, statusString), never via a
// generic error body. failInfoBit selects the PKIFailureInfo bit so the
// response carries a populated BIT STRING.
func (r *cmpHttpRoutes) rejectRevocation(ctx *gin.Context, lFunc *logrus.Entry, header requestPKIHeader, reason string, failInfoBit int, dmsID string) {
	body, err := marshalRevRepBody(PKIStatus(pkiStatusRejection), reason, failInfoBit)
	if err != nil {
		lFunc.Errorf("build rp rejection body: %v", err)
		r.rejectWithError(ctx, &header, PKIStatus(pkiStatusRejection), reason, dmsID, failInfoBit)
		return
	}
	header.ResponseImplicitConfirm = false
	r.sendRawBody(ctx, lFunc, header, cmpBodyTagRP, body, dmsID)
}

// rejectRequest routes a pre-dispatch rejection (protection / sender / senderKID
// failures) to the body type appropriate for the inbound request. For rr the
// response MUST be an rp body (RFC 9483 §4.2); all other request types fall
// back to the generic error body.
func (r *cmpHttpRoutes) rejectRequest(ctx *gin.Context, lFunc *logrus.Entry, header requestPKIHeader, bodyTag int, reason string, failInfoBit int, dmsID string) {
	if bodyTag == cmpBodyTagRR {
		r.rejectRevocation(ctx, lFunc, header, reason, failInfoBit, dmsID)
		return
	}
	r.rejectWithError(ctx, &header, PKIStatus(pkiStatusRejection), reason, dmsID, failInfoBit)
}

func (r *cmpHttpRoutes) rejectWithError(ctx *gin.Context, header *requestPKIHeader, status PKIStatus, reason string, aps string, failInfoBits ...int) {
	errBody, err := marshalErrorBody(status, reason, failInfoBits...)
	if err != nil {
		ctx.Status(http.StatusInternalServerError)
		return
	}
	var h requestPKIHeader
	if header != nil {
		h = *header
		// An error PKIBody must never advertise implicit confirmation:
		// id-it-implicitConfirm is only valid on a positive ip/cp/kup
		// (RFC 9483 §4.1.1). The flag may have been set on the request header
		// before enrollment failed, so clear it here to avoid leaking it into
		// the error response generalInfo.
		h.ResponseImplicitConfirm = false
		// Best-effort CN lookup: if a transaction row already exists for
		// this txID we can route the Rejected transition to the matching
		// WFX job. For brand-new requests rejected before the row is
		// written there is no CN to find — Emit drops it silently, which
		// is the correct behaviour (no useful WFX job to attach to).
		txHex := hex.EncodeToString(header.TransactionID)
		var deviceCN string
		if tx, ok, err := r.store.Select(ctx.Request.Context(), txHex); err == nil && ok {
			deviceCN = tx.SubjectCommonName
		}
		r.reportCMPState(ctx.Request.Context(), r.logger, cmpwfx.CMPTransition{
			TransactionID:     txHex,
			DMSID:             aps,
			SubjectCommonName: deviceCN,
			State:             cmpwfx.CMPStateRejected,
			Reason:            reason,
		})
	}
	r.sendRawBody(ctx, r.logger, h, cmpBodyTagError, errBody, aps)
}

// sendRawBody assembles a PKIMessage from a pre-encoded body CHOICE DER and
// writes the result as application/pkixcmp to the Gin context.
func (r *cmpHttpRoutes) sendRawBody(ctx *gin.Context, lFunc *logrus.Entry, reqHeader requestPKIHeader, bodyTag int, bodyDER []byte, aps string) []byte {
	sendResponse := func(respDER []byte) {
		lFunc.Infof("CMP response (tag=%d) PEM:\n%s", bodyTag,
			pem.EncodeToMemory(&pem.Block{Type: "CMP MESSAGE", Bytes: respDER}))
		ctx.Data(http.StatusOK, "application/pkixcmp", respDER)
	}

	if aps != "" {
		if provider, ok := r.svc.(services.LightweightCMPProtectionProvider); ok {
			certChain, signer, credErr := provider.LWCProtectionCredentials(ctx.Request.Context(), aps)
			if credErr != nil {
				lFunc.Errorf("load cmp protection credentials: %v", credErr)
				ctx.Status(http.StatusInternalServerError)
				return nil
			}
			// (nil chain, nil signer, nil err) means the DMS opted out of response
			// signing (no protection_certificate configured) — fall through to the
			// unprotected response path below. Otherwise sign with the chain.
			if len(certChain) > 0 && signer != nil {
				respDER, err := marshalProtectedResponse(reqHeader, bodyTag, bodyDER, certChain, signer)
				if err != nil {
					lFunc.Errorf("marshal protected response PKIMessage: %v", err)
					ctx.Status(http.StatusInternalServerError)
					return nil
				}
				sendResponse(respDER)
				return respDER
			}
		}
	}

	respDER, err := marshalUnprotectedResponse(reqHeader, bodyTag, bodyDER)
	if err != nil {
		lFunc.Errorf("marshal response PKIMessage: %v", err)
		ctx.Status(http.StatusInternalServerError)
		return nil
	}
	sendResponse(respDER)
	return respDER
}

// buildResponseHeader constructs a response PKIHeader mirroring the
// transactionID from the request and echoing senderNonce as recipNonce.
//
// Per RFC 9810 §7 line 3754 the response pvno MUST equal the request pvno when
// the server supports it (we support both cmp2000(2) and cmp2021(3)). Per RFC
// 9483 §3.1 line 725 messageTime SHOULD be present on responses for time-sync
// purposes — we always emit it.
func buildResponseHeader(req requestPKIHeader) (responsePKIHeader, error) {
	sender := defaultSenderGeneralName()
	if len(req.Recipient.FullBytes) > 0 {
		sender = asn1.RawValue{FullBytes: req.Recipient.FullBytes}
	}

	recipient := defaultRecipientGeneralName()
	if len(req.Sender.FullBytes) > 0 {
		recipient = asn1.RawValue{FullBytes: req.Sender.FullBytes}
	}

	respSenderNonce := req.ResponseSenderNonce
	if len(respSenderNonce) == 0 {
		var err error
		respSenderNonce, err = newNonce()
		if err != nil {
			return responsePKIHeader{}, err
		}
	}

	// RFC 9810 §7: echo the received pvno when supported. Fall back to cmp2000
	// for malformed/legacy requests that never set a valid version.
	respPVNO := pvnoCMP2000
	if req.PVNO == pvnoCMP2021 {
		respPVNO = pvnoCMP2021
	}

	var generalInfo []infoTypeAndValueResp
	if req.ResponseImplicitConfirm {
		generalInfo = []infoTypeAndValueResp{
			{InfoType: oidImplicitConfirm, InfoValue: asn1.NullRawValue},
		}
	}

	return responsePKIHeader{
		PVNO:          respPVNO,
		Sender:        sender,
		Recipient:     recipient,
		MessageTime:   time.Now().UTC().Round(time.Second),
		TransactionID: req.TransactionID,
		RecipNonce:    req.SenderNonce,
		SenderNonce:   respSenderNonce,
		GeneralInfo:   generalInfo,
	}, nil
}

// newNonce generates a 16-byte cryptographically random nonce. Returns an
// error if the CSPRNG fails — callers MUST surface the failure rather than
// substitute a deterministic value, because a non-random nonce breaks the
// RFC 4210 §5.1.1 freshness property (replayable transactions).
func newNonce() ([]byte, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("CMP nonce CSPRNG read: %w", err)
	}
	return b, nil
}

// resolveDeviceCN returns the device CommonName associated with an incoming
// CMP message. Used at the very start of HandleCMP — before any state is
// emitted to WFX — to populate `clientId` on the WFX side. The lookup
// strategy depends on the body type:
//
//   - ir/cr/kur: the CertReqMessage carries a CertTemplate whose Subject DER
//     contains the CN; we decode only as much as needed to pull it out.
//   - pollReq/certConf/rr: these reference an existing transaction, so we
//     fall back to the persisted SubjectCommonName on the cmp_transactions
//     row keyed by the request's transactionID.
//
// Returns "" on any error or unknown body tag — the caller must accept that
// some malformed early-rejection paths won't appear in WFX (acceptable: a
// malformed body has no useful device identity to track).
func (r *cmpHttpRoutes) resolveDeviceCN(ctx context.Context, body asn1.RawValue, txHex string) string {
	switch body.Tag {
	case cmpBodyTagIR, cmpBodyTagCR, cmpBodyTagKUR:
		req, err := decodeFirstCertReq(body.Bytes)
		if err != nil {
			return ""
		}
		return extractCNFromSubjectDER(req.SubjectDER)
	case cmpBodyTagPollReq, cmpBodyTagCertConf, cmpBodyTagRR:
		if txHex == "" {
			return ""
		}
		tx, ok, err := r.store.Select(ctx, txHex)
		if err != nil || !ok {
			return ""
		}
		return tx.SubjectCommonName
	}
	return ""
}

// extractCNFromSubjectDER pulls the CommonName attribute out of a DER-encoded
// X.501 Name. CMP CertTemplates carry the Subject this way; full CSR parsing
// would require synthesising the SPKI and signature too, which is unnecessary
// just to read one attribute.
func extractCNFromSubjectDER(subjectDER []byte) string {
	if len(subjectDER) == 0 {
		return ""
	}
	var rdn pkix.RDNSequence
	if _, err := asn1.Unmarshal(subjectDER, &rdn); err != nil {
		return ""
	}
	var name pkix.Name
	name.FillFromRDNSequence(&rdn)
	return name.CommonName
}

type firstCertReq struct {
	CertReqID    int
	SubjectDER   []byte
	PublicKeyDER []byte
	// CertReqDER is the DER encoding of the CertRequest SEQUENCE.
	// The POPO signature (RFC 4211 §4.1 clause 3) is computed over this value.
	CertReqDER []byte
	// POPORaw is the raw ASN.1 value of the ProofOfPossession CHOICE,
	// as decoded from the CertReqMsg following the CertRequest.
	POPORaw asn1.RawValue
	// OldCertID carries the RFC 4211 §6.2 id-regCtrl-oldCertID control from the
	// CertRequest's optional `controls` field, when present. For a KUR it names
	// the certificate being updated (CertId = issuer + serialNumber). nil when no
	// such control was supplied.
	OldCertID *oldCertID
	// Extensions holds the requested X.509 extensions from the CertTemplate
	// `extensions [9]` field (KeyUsage/ExtKeyUsage/SubjectAltName). Empty when
	// the template requested none. Carried into the synthesized CSR so the
	// issuance profile can honor them (RFC 4211 §5 / RFC 9483 §4.1).
	Extensions []pkix.Extension
	// ControlsDER is the raw DER of the CertRequest optional `controls` field
	// (RFC 4211 §5), i.e. everything following the CertTemplate inside the
	// CertRequest SEQUENCE. Empty when no controls were supplied. Used to
	// validate registration controls such as id-regCtrl-pkiPublicationInfo.
	ControlsDER []byte
	// RegInfoDER is the raw DER of the CertReqMsg optional `regInfo` field
	// (RFC 4211 §6 / §7): a SEQUENCE OF AttributeTypeAndValue carrying, e.g.,
	// id-regInfo-certReq (an RA-supplied alternate CertRequest). Empty when the
	// message carried no regInfo.
	RegInfoDER []byte
	// ForKGA marks an RFC 9483 §4.1.6 central key generation request: the
	// CertTemplate carries no usable public key (the publicKey field is either
	// absent, or present with a zero-length subjectPublicKey) and no POPO, so the
	// server generates the end-entity key pair and returns it in the response.
	ForKGA bool
	// KGAKeyAlgorithm is the public key algorithm hint from the CertTemplate's
	// publicKey.algorithm when a for_kga request supplied one (RSA or ECDSA); it
	// tells the server which key type to generate. UnknownPublicKeyAlgorithm when
	// the request omitted the publicKey field entirely.
	KGAKeyAlgorithm x509.PublicKeyAlgorithm
}

// oldCertID is the decoded RFC 4211 CertId { issuer GeneralName, serialNumber }
// from the id-regCtrl-oldCertID control. IssuerNameDER is the DER of the issuer
// directoryName ([4]) RDNSequence, directly comparable to x509.Certificate.RawIssuer.
type oldCertID struct {
	IssuerNameDER []byte
	SerialNumber  *big.Int
}

// oidSubjectAltNameExt is the X.509 SubjectAltName extension OID (RFC 5280
// §4.2.1.6).
var oidSubjectAltNameExt = asn1.ObjectIdentifier{2, 5, 29, 17}

// emptyRDNSequenceDER returns the DER of an empty RDNSequence (a zero-length
// SEQUENCE, 0x30 0x00) — the canonical NULL-DN subject used when a CMP
// CertTemplate omits the subject but supplies a SubjectAltName.
func emptyRDNSequenceDER() []byte {
	return []byte{0x30, 0x00}
}

// isEmptySubjectDER reports whether a decoded CertTemplate subject is absent or
// a NULL-DN: either no bytes at all, or an empty RDNSequence (0x30 0x00).
func isEmptySubjectDER(subjectDER []byte) bool {
	if len(subjectDER) == 0 {
		return true
	}
	if len(subjectDER) == 2 && subjectDER[0] == 0x30 && subjectDER[1] == 0x00 {
		return true
	}
	return false
}

// hasSubjectAltNameExtension reports whether the requested CertTemplate
// extensions include a SubjectAltName (RFC 5280 §4.2.1.6).
func hasSubjectAltNameExtension(exts []pkix.Extension) bool {
	for _, e := range exts {
		if e.Id.Equal(oidSubjectAltNameExt) {
			return true
		}
	}
	return false
}

// requestedCriticalExtensionDropped reports whether the issuance dropped a
// CRITICAL extension that the CertTemplate asked for. RFC 9483 §5 lets a CA
// with a relaxed policy accept a request carrying an unrecognized/invalid
// extension by issuing a certificate WITHOUT that extension — but it must then
// signal the modification via PKIStatus grantedWithMods (1) rather than
// accepted (0) (RFC 4210 §5.2.3). Detection is deliberately narrow: only a
// requested extension marked critical that is absent (by OID) from the issued
// certificate counts, so honored/added extensions and dropped non-critical
// hints never flip an otherwise-accepted response.
func requestedCriticalExtensionDropped(requested []pkix.Extension, issued *x509.Certificate) bool {
	if issued == nil || len(requested) == 0 {
		return false
	}
	present := make(map[string]bool, len(issued.Extensions))
	for _, e := range issued.Extensions {
		present[e.Id.String()] = true
	}
	for _, e := range requested {
		if e.Critical && !present[e.Id.String()] {
			return true
		}
	}
	return false
}

type responsePKIHeader struct {
	PVNO          int                      `asn1:"default:2"`
	Sender        interface{}              // GeneralName
	Recipient     interface{}              // GeneralName
	MessageTime   time.Time                `asn1:"generalized,explicit,optional,tag:0,omitempty"`
	ProtectionAlg pkix.AlgorithmIdentifier `asn1:"explicit,optional,tag:1,omitempty"`
	SenderKID     []byte                   `asn1:"optional,explicit,tag:2,omitempty"` // RFC 9483 §3.1: SubjectKeyIdentifier of the protection cert
	TransactionID []byte                   `asn1:"optional,explicit,tag:4,omitempty"`
	SenderNonce   []byte                   `asn1:"optional,explicit,tag:5,omitempty"`
	RecipNonce    []byte                   `asn1:"optional,explicit,tag:6,omitempty"`
	GeneralInfo   []infoTypeAndValueResp   `asn1:"optional,explicit,tag:8,omitempty"`
}

// infoTypeAndValueResp is the encoded form of an InfoTypeAndValue used in a
// response PKIHeader generalInfo. InfoValue carries the NULL value required by
// RFC 4210 §5.3.2 (ImplicitConfirmValue ::= NULL) for id-it-implicitConfirm.
type infoTypeAndValueResp struct {
	InfoType  asn1.ObjectIdentifier
	InfoValue asn1.RawValue `asn1:"optional"`
}

// decodeFirstCertReq extracts the fields needed for enrollment from the first
// CertReqMessage using manual ASN.1 peeling compatible with OpenSSL CMP.
func decodeFirstCertReq(bodyBytes []byte) (*firstCertReq, error) {
	var crMsgsSeq asn1.RawValue
	if _, err := asn1.Unmarshal(bodyBytes, &crMsgsSeq); err != nil {
		return nil, fmt.Errorf("CertReqMessages: %w", err)
	}

	var crMsg asn1.RawValue
	crMsgsRest, err := asn1.Unmarshal(crMsgsSeq.Bytes, &crMsg)
	if err != nil {
		return nil, fmt.Errorf("CertReqMsg: %w", err)
	}
	// RFC 9483 §4.1: exactly one CertReqMsg is allowed per ir/cr/kur.
	if len(crMsgsRest) > 0 {
		return nil, &certRequestRejection{
			CertReqID:   0,
			Reason:      "ir/cr/kur must contain exactly one CertReqMsg (RFC 9483 §4.1)",
			FailInfoBit: pkiFailureInfoBadRequest,
		}
	}

	var certReqSeq asn1.RawValue
	certReqMsgRest, err := asn1.Unmarshal(crMsg.Bytes, &certReqSeq)
	if err != nil {
		return nil, fmt.Errorf("CertRequest: %w", err)
	}

	// Try to decode the optional ProofOfPossession CHOICE that follows CertRequest.
	var popoRaw asn1.RawValue
	if len(certReqMsgRest) > 0 {
		// Peek at the first TLV; any parse error just means POPO is absent.
		if _, parseErr := asn1.Unmarshal(certReqMsgRest, &popoRaw); parseErr != nil {
			popoRaw = asn1.RawValue{} // reset on error
		}
	}

	var certReqIDRaw asn1.RawValue
	rest, err := asn1.Unmarshal(certReqSeq.Bytes, &certReqIDRaw)
	if err != nil {
		return nil, fmt.Errorf("certReqId: %w", err)
	}
	if certReqIDRaw.Tag != asn1.TagInteger || certReqIDRaw.Class != asn1.ClassUniversal {
		return nil, fmt.Errorf("expected INTEGER for certReqId, got class=%d tag=%d", certReqIDRaw.Class, certReqIDRaw.Tag)
	}

	var certReqID int
	if _, err := asn1.Unmarshal(certReqIDRaw.FullBytes, &certReqID); err != nil {
		return nil, fmt.Errorf("parse certReqId: %w", err)
	}
	// RFC 9483 §4.1: certReqId MUST be 0.
	if certReqID != 0 {
		return nil, &certRequestRejection{
			CertReqID:   certReqID,
			Reason:      fmt.Sprintf("certReqId must be 0 (RFC 9483 §4.1), got %d", certReqID),
			FailInfoBit: pkiFailureInfoBadRequest,
		}
	}

	var certTemplate asn1.RawValue
	controlsRest, err := asn1.Unmarshal(rest, &certTemplate)
	if err != nil {
		return nil, fmt.Errorf("CertTemplate: %w", err)
	}
	if certTemplate.Tag != asn1.TagSequence || certTemplate.Class != asn1.ClassUniversal {
		return nil, fmt.Errorf("expected UNIVERSAL SEQUENCE for CertTemplate, got class=%d tag=%d", certTemplate.Class, certTemplate.Tag)
	}

	// Optional `controls` SEQUENCE follows the CertTemplate (RFC 4211 §5). We only
	// care about id-regCtrl-oldCertID (KUR cert-to-update reference); ignore the
	// rest. A malformed controls block is non-fatal — it just yields no oldCertID.
	oldCID := parseOldCertIDControl(controlsRest)

	// regInfo (RFC 4211 §6): the CertReqMsg may carry a SEQUENCE OF
	// AttributeTypeAndValue after the CertRequest and optional POPO. POPO's
	// CHOICE alternatives are all context-tagged, so the first UNIVERSAL SEQUENCE
	// in the remainder is the regInfo. Captured raw for alt-CertReq validation.
	regInfoDER := findRegInfoDER(certReqMsgRest)

	var subjectDER []byte
	var publicKeyDER []byte
	var extensions []pkix.Extension
	// KGA (RFC 9483 §4.1.6) detection state: whether a publicKey field was
	// present at all, and whether it carried an empty subjectPublicKey (the
	// "generate this for me" signal), plus the algorithm hint if any.
	pubKeyPresent := false
	pubKeyEmpty := false
	kgaKeyAlg := x509.UnknownPublicKeyAlgorithm
	remaining := certTemplate.Bytes
	for len(remaining) > 0 {
		var field asn1.RawValue
		remaining, err = asn1.Unmarshal(remaining, &field)
		if err != nil {
			return nil, fmt.Errorf("CertTemplate field: %w", err)
		}

		switch {
		case field.Class == asn1.ClassContextSpecific && field.Tag == 5:
			subjectDER, err = normalizeSequenceDER(field.Bytes, "subject")
			if err != nil {
				return nil, err
			}
		case field.Class == asn1.ClassContextSpecific && field.Tag == 6:
			pubKeyPresent = true
			// The [6] content is a SubjectPublicKeyInfo body (algorithm ||
			// subjectPublicKey). A for_kga request sends the algorithm hint with a
			// zero-length subjectPublicKey; detect that and remember the key type.
			pubKeyEmpty, kgaKeyAlg = inspectKGATemplateKey(field.Bytes)
			publicKeyDER, err = wrapSequenceDER(field.Bytes, "SubjectPublicKeyInfo")
			if err != nil {
				return nil, err
			}
		case field.Class == asn1.ClassContextSpecific && field.Tag == 9:
			// extensions [9] Extensions (RFC 4211 §5). The EE uses these to
			// request KeyUsage/ExtKeyUsage/SubjectAltName; carry them so the
			// synthesized CSR reflects the requested template and the issuance
			// profile can honor them. A malformed extensions block is non-fatal:
			// it just yields no extensions rather than aborting enrollment.
			extensions = parseCertTemplateExtensions(field.Bytes)
		}
	}

	if isEmptySubjectDER(subjectDER) {
		// RFC 9483 §4.1.1 permits a NULL-DN (empty) subject when a
		// SubjectAltName extension carries the identity. Reject only when there
		// is neither a subject nor a SAN; otherwise normalize the subject to a
		// valid empty RDNSequence so the synthesized CSR encodes a proper
		// NULL-DN and the service derives the device identity from the SAN.
		if !hasSubjectAltNameExtension(extensions) {
			return nil, &certRequestRejection{
				CertReqID:   certReqID,
				Reason:      "subject field is required in CertTemplate unless a SubjectAltName extension is present (RFC 9483 §4.1.1)",
				FailInfoBit: pkiFailureInfoBadCertTemplate,
			}
		}
		subjectDER = emptyRDNSequenceDER()
	}
	// RFC 9483 §4.1.6 central key generation: the request deliberately omits a
	// usable public key so the server generates the key pair. Recognise the two
	// wire shapes the profile permits — publicKey present with a zero-length
	// subjectPublicKey, or publicKey absent together with an absent POPO (a plain
	// malformed request that merely forgot the key still carries a POPO, so this
	// stays distinct from that error) — and defer key handling to the KGA path.
	forKGA := pubKeyEmpty || (!pubKeyPresent && len(popoRaw.FullBytes) == 0)
	if len(publicKeyDER) == 0 && !forKGA {
		return nil, &certRequestRejection{
			CertReqID:   certReqID,
			Reason:      "publicKey field is required in CertTemplate (RFC 9483 §4.1.3)",
			FailInfoBit: pkiFailureInfoBadCertTemplate,
		}
	}

	return &firstCertReq{
		CertReqID:       certReqID,
		SubjectDER:      subjectDER,
		PublicKeyDER:    publicKeyDER,
		CertReqDER:      certReqSeq.FullBytes,
		POPORaw:         popoRaw,
		OldCertID:       oldCID,
		Extensions:      extensions,
		ControlsDER:     controlsRest,
		RegInfoDER:      regInfoDER,
		ForKGA:          forKGA,
		KGAKeyAlgorithm: kgaKeyAlg,
	}, nil
}

// inspectKGATemplateKey examines the body of a CertTemplate publicKey [6] field
// (a SubjectPublicKeyInfo: algorithm AlgorithmIdentifier, subjectPublicKey BIT
// STRING). It reports whether the subjectPublicKey is empty — the RFC 9483
// §4.1.6 "generate this key for me" signal — and, when it can, the public key
// algorithm named by the AlgorithmIdentifier (so the server knows which key
// type to generate). A parse failure yields (false, Unknown): treat it as a
// normal (non-empty) key and let downstream validation handle malformations.
func inspectKGATemplateKey(spkiBody []byte) (empty bool, alg x509.PublicKeyAlgorithm) {
	var algID asn1.RawValue
	rest, err := asn1.Unmarshal(spkiBody, &algID)
	if err != nil {
		return false, x509.UnknownPublicKeyAlgorithm
	}
	var subjectPublicKey asn1.BitString
	if _, err := asn1.Unmarshal(rest, &subjectPublicKey); err != nil {
		return false, x509.UnknownPublicKeyAlgorithm
	}
	if subjectPublicKey.BitLength != 0 {
		return false, x509.UnknownPublicKeyAlgorithm
	}
	// Empty key ⇒ for_kga. Resolve the algorithm OID for the key-type hint.
	var oid asn1.ObjectIdentifier
	if _, err := asn1.Unmarshal(algID.Bytes, &oid); err != nil {
		return true, x509.UnknownPublicKeyAlgorithm
	}
	switch {
	case oid.Equal(oidRSAEncryption):
		return true, x509.RSA
	case oid.Equal(oidECPublicKey):
		return true, x509.ECDSA
	default:
		return true, x509.UnknownPublicKeyAlgorithm
	}
}

// parseCertTemplateExtensions decodes the content of a CertTemplate `extensions
// [9]` field (RFC 4211 §5). The [9] tag is IMPLICIT over Extensions ::=
// SEQUENCE OF Extension, so contentDER is the concatenation of Extension TLVs.
// A parse error stops decoding and returns whatever was decoded so far — the
// extensions are advisory (the issuance profile decides what to honor), so a
// malformed trailer must not fail the enrollment.
func parseCertTemplateExtensions(contentDER []byte) []pkix.Extension {
	var exts []pkix.Extension
	rest := contentDER
	for len(rest) > 0 {
		var ext pkix.Extension
		var err error
		rest, err = asn1.Unmarshal(rest, &ext)
		if err != nil {
			return exts
		}
		exts = append(exts, ext)
	}
	return exts
}

// oidExtBasicConstraints / oidExtKeyUsage identify the two extensions whose
// presence in a CertTemplate changes whether the request is for a CA vs an
// end-entity certificate (RFC 5280 §4.2.1.9 / §4.2.1.3).
var (
	oidExtBasicConstraints = asn1.ObjectIdentifier{2, 5, 29, 19}
	oidExtKeyUsage         = asn1.ObjectIdentifier{2, 5, 29, 15}
)

// basicConstraints mirrors RFC 5280 §4.2.1.9 BasicConstraints for decoding the
// CertTemplate's requested value. PathLen is optional and defaults to 0 when
// absent; a positive pathLen on a non-CA template is what we treat as malformed.
type basicConstraints struct {
	IsCA    bool `asn1:"optional"`
	PathLen int  `asn1:"optional"`
}

// validateCertTemplatePolicy enforces Lamassu's end-entity-only CMP issuance
// policy against the requested CertTemplate extensions (RFC 9483 §5). It returns
// a *certRequestRejection to be delivered in the ip/cp/kup body, or nil when the
// template is acceptable:
//
//   - BasicConstraints cA=TRUE            → notAuthorized  (Lamassu never issues
//     or KeyUsage keyCertSign               CA certs over CMP)
//   - pathLenConstraint without cA=TRUE   → badCertTemplate (malformed per §4.2.1.9)
//
// The weak-RSA-key rejection is enforced earlier, before POPO verification
// (see handleEnrollment), so it is not repeated here.
func validateCertTemplatePolicy(req *firstCertReq) *certRequestRejection {
	var bc *basicConstraints
	var keyCertSign bool

	for _, ext := range req.Extensions {
		switch {
		case ext.Id.Equal(oidExtBasicConstraints):
			var parsed basicConstraints
			if _, err := asn1.Unmarshal(ext.Value, &parsed); err != nil {
				return &certRequestRejection{
					CertReqID:   req.CertReqID,
					Reason:      "malformed BasicConstraints extension in CertTemplate",
					FailInfoBit: pkiFailureInfoBadCertTemplate,
				}
			}
			bc = &parsed
		case ext.Id.Equal(oidExtKeyUsage):
			var ku asn1.BitString
			if _, err := asn1.Unmarshal(ext.Value, &ku); err == nil {
				// keyCertSign is bit 5 (RFC 5280 §4.2.1.3).
				if ku.At(5) == 1 {
					keyCertSign = true
				}
			}
		}
	}

	// BasicConstraints cA=TRUE is a request to be issued a CA certificate, which
	// Lamassu never does over CMP → notAuthorized (RFC 9483 §5).
	if bc != nil && bc.IsCA {
		return &certRequestRejection{
			CertReqID:   req.CertReqID,
			Reason:      "issuing CA certificates is not permitted over CMP (RFC 9483 §5): BasicConstraints cA=TRUE requested",
			FailInfoBit: pkiFailureInfoNotAuthorized,
		}
	}
	// keyCertSign without cA=TRUE is a self-inconsistent template: keyCertSign is
	// only valid on a CA certificate (RFC 5280 §4.2.1.3) → badCertTemplate.
	if keyCertSign {
		return &certRequestRejection{
			CertReqID:   req.CertReqID,
			Reason:      "keyCertSign KeyUsage requested without BasicConstraints cA=TRUE (RFC 5280 §4.2.1.3)",
			FailInfoBit: pkiFailureInfoBadCertTemplate,
		}
	}
	// pathLenConstraint is only meaningful when cA=TRUE; its presence on an
	// end-entity template is a malformed CertTemplate (RFC 5280 §4.2.1.9).
	if bc != nil && bc.PathLen > 0 {
		return &certRequestRejection{
			CertReqID:   req.CertReqID,
			Reason:      "pathLenConstraint present with cA=FALSE (RFC 5280 §4.2.1.9)",
			FailInfoBit: pkiFailureInfoBadCertTemplate,
		}
	}
	return nil
}

// minRSAKeyBits is the smallest RSA modulus Lamassu will certify over CMP.
// 2048 bits is the NIST SP 800-57 minimum for RSA; shorter keys are rejected
// with badCertTemplate.
const minRSAKeyBits = 2048

// maxRSAKeyBits is the largest RSA modulus Lamassu will certify over CMP.
// Oversized moduli (e.g. 16384/18000-bit keys) provide no meaningful additional
// security while imposing a large signing/verification cost, so they are a
// resource-exhaustion vector and are rejected with badCertTemplate (RFC 9483
// §3.5). 8192 bits is a generous ceiling well above any practical deployment.
const maxRSAKeyBits = 8192

// rsaKeyBits returns the RSA modulus size in bits for a SubjectPublicKeyInfo
// DER blob, or 0 if the key is not RSA or cannot be parsed. The modulus is read
// straight out of the DER rather than via x509.ParsePKIXPublicKey: modern Go
// refuses to parse weak RSA keys (<1024 bits) outright, which would hide the
// very keys this policy exists to reject. Manual decoding lets us measure and
// reject them with a precise badCertTemplate.
func rsaKeyBits(spkiDER []byte) int {
	if len(spkiDER) == 0 {
		return 0
	}
	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(spkiDER, &spki); err != nil {
		return 0
	}
	if !spki.Algorithm.Algorithm.Equal(oidRSAEncryption) {
		return 0
	}
	var rsaPub struct {
		N *big.Int
		E int
	}
	if _, err := asn1.Unmarshal(spki.PublicKey.Bytes, &rsaPub); err != nil {
		return 0
	}
	if rsaPub.N == nil {
		return 0
	}
	return rsaPub.N.BitLen()
}

// RFC 4211 registration control / registration info OIDs.
var (
	// id-regCtrl-pkiPublicationInfo (1.3.6.1.5.5.7.5.1.3): asks the CA to
	// publish (or not publish) the issued certificate (RFC 4211 §6.3).
	oidRegCtrlPKIPublicationInfo = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 5, 1, 3}
	// id-regInfo-certReq (1.3.6.1.5.5.7.5.2.2): an RA-supplied alternate
	// CertRequest carried in the CertReqMsg regInfo (RFC 4211 §7.2).
	oidRegInfoCertReq = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 5, 2, 2}
)

// findRegInfoDER extracts the CertReqMsg `regInfo` field from the bytes that
// follow the CertRequest inside a CertReqMsg. That remainder is [ POPO? regInfo? ];
// every ProofOfPossession CHOICE alternative is context-tagged, so the first
// UNIVERSAL SEQUENCE encountered is the regInfo (SEQUENCE OF AttributeTypeAndValue).
// Returns nil when no regInfo is present.
func findRegInfoDER(afterCertReq []byte) []byte {
	scan := afterCertReq
	for len(scan) > 0 {
		var tlv asn1.RawValue
		rest, err := asn1.Unmarshal(scan, &tlv)
		if err != nil {
			return nil
		}
		if tlv.Class == asn1.ClassUniversal && tlv.Tag == asn1.TagSequence {
			return tlv.FullBytes
		}
		scan = rest
	}
	return nil
}

// validatePKIPublicationInfoControls enforces the structural rules of the
// id-regCtrl-pkiPublicationInfo control (RFC 4211 §6.3) when present in a
// CertRequest's `controls`. It only inspects that one control OID, so other
// controls (oldCertID, regToken, authenticator) are untouched.
//
//	PKIPublicationInfo ::= SEQUENCE {
//	    action    INTEGER { dontPublish(0), pleasePublish(1) },
//	    pubInfos  SEQUENCE SIZE (1..MAX) OF SinglePubInfo OPTIONAL }
//	SinglePubInfo ::= SEQUENCE {
//	    pubMethod   INTEGER { dontCare(0), x500(1), web(2), ldap(3) },
//	    pubLocation GeneralName OPTIONAL }
//
// Rejections (badDataFormat):
//   - action outside {dontPublish, pleasePublish};
//   - dontPublish carrying any pubInfos (RFC 4211: none may be present);
//   - a pubMethod outside {dontCare, x500, web, ldap};
//   - pleasePublish with a concrete method (x500/web/ldap) but no pubLocation.
func validatePKIPublicationInfoControls(certReqID int, controlsDER []byte) *certRequestRejection {
	if len(controlsDER) == 0 {
		return nil
	}
	var controlsSeq asn1.RawValue
	if _, err := asn1.Unmarshal(controlsDER, &controlsSeq); err != nil {
		return nil // malformed controls block: non-fatal, nothing to validate
	}
	if controlsSeq.Tag != asn1.TagSequence || controlsSeq.Class != asn1.ClassUniversal {
		return nil
	}

	reject := func(reason string) *certRequestRejection {
		return &certRequestRejection{
			CertReqID:   certReqID,
			Reason:      reason,
			FailInfoBit: pkiFailureInfoBadDataFormat,
		}
	}

	rest := controlsSeq.Bytes
	for len(rest) > 0 {
		var attr asn1.RawValue
		var err error
		rest, err = asn1.Unmarshal(rest, &attr)
		if err != nil {
			return nil
		}
		// AttributeTypeAndValue ::= SEQUENCE { type OID, value ANY }
		var oid asn1.ObjectIdentifier
		valueRest, err := asn1.Unmarshal(attr.Bytes, &oid)
		if err != nil || !oid.Equal(oidRegCtrlPKIPublicationInfo) {
			continue
		}

		// value is a PKIPublicationInfo SEQUENCE.
		var pubInfo asn1.RawValue
		if _, err := asn1.Unmarshal(valueRest, &pubInfo); err != nil {
			return reject("malformed PKIPublicationInfo control (RFC 4211 §6.3)")
		}
		var action int
		pubInfosRest, err := asn1.Unmarshal(pubInfo.Bytes, &action)
		if err != nil {
			return reject("malformed PKIPublicationInfo action (RFC 4211 §6.3)")
		}
		const actionDontPublish, actionPleasePublish = 0, 1
		if action != actionDontPublish && action != actionPleasePublish {
			return reject(fmt.Sprintf("invalid PKIPublicationInfo action %d (RFC 4211 §6.3)", action))
		}

		hasPubInfos := len(pubInfosRest) > 0
		if action == actionDontPublish && hasPubInfos {
			return reject("PKIPublicationInfo dontPublish must not carry pubInfos (RFC 4211 §6.3)")
		}
		if !hasPubInfos {
			continue
		}

		// pleasePublish with pubInfos: validate each SinglePubInfo.
		var pubInfosSeq asn1.RawValue
		if _, err := asn1.Unmarshal(pubInfosRest, &pubInfosSeq); err != nil {
			return reject("malformed PKIPublicationInfo pubInfos (RFC 4211 §6.3)")
		}
		entries := pubInfosSeq.Bytes
		for len(entries) > 0 {
			var single asn1.RawValue
			entries, err = asn1.Unmarshal(entries, &single)
			if err != nil {
				return reject("malformed SinglePubInfo (RFC 4211 §6.3)")
			}
			var method int
			locRest, err := asn1.Unmarshal(single.Bytes, &method)
			if err != nil {
				return reject("malformed SinglePubInfo pubMethod (RFC 4211 §6.3)")
			}
			const methodDontCare = 0
			const methodLDAP = 3
			if method < methodDontCare || method > methodLDAP {
				return reject(fmt.Sprintf("invalid SinglePubInfo pubMethod %d (RFC 4211 §6.3)", method))
			}
			// A concrete publication method (x500/web/ldap) requires a location;
			// only dontCare may omit it.
			if method != methodDontCare && len(locRest) == 0 {
				return reject("PKIPublicationInfo pleasePublish requires a pubLocation (RFC 4211 §6.3)")
			}
		}
	}
	return nil
}

// validateAltCertReqPublicKey enforces RFC 4211 §7.2: when the regInfo carries
// an id-regInfo-certReq (an RA-supplied alternate CertRequest), its CertTemplate
// public key must match the public key of the primary CertRequest. A mismatch
// would invalidate the proof of possession, so it is rejected with
// badCertTemplate. Returns nil when no such control is present or the keys match.
func validateAltCertReqPublicKey(certReqID int, regInfoDER, mainPublicKeyDER []byte) *certRequestRejection {
	if len(regInfoDER) == 0 {
		return nil
	}
	var regInfoSeq asn1.RawValue
	if _, err := asn1.Unmarshal(regInfoDER, &regInfoSeq); err != nil {
		return nil
	}
	if regInfoSeq.Tag != asn1.TagSequence || regInfoSeq.Class != asn1.ClassUniversal {
		return nil
	}

	rest := regInfoSeq.Bytes
	for len(rest) > 0 {
		var attr asn1.RawValue
		var err error
		rest, err = asn1.Unmarshal(rest, &attr)
		if err != nil {
			return nil
		}
		var oid asn1.ObjectIdentifier
		valueRest, err := asn1.Unmarshal(attr.Bytes, &oid)
		if err != nil || !oid.Equal(oidRegInfoCertReq) {
			continue
		}
		// value is a CertRequest; extract its CertTemplate publicKey [6].
		altPub := certRequestPublicKeyDER(valueRest)
		if len(altPub) == 0 || len(mainPublicKeyDER) == 0 {
			continue
		}
		if !bytes.Equal(altPub, mainPublicKeyDER) {
			return &certRequestRejection{
				CertReqID:   certReqID,
				Reason:      "alternate CertRequest in regInfo carries a different public key than the primary request (RFC 4211 §7.2)",
				FailInfoBit: pkiFailureInfoBadCertTemplate,
			}
		}
	}
	return nil
}

// certRequestPublicKeyDER decodes a CertRequest SEQUENCE and returns its
// CertTemplate publicKey [6] re-wrapped as a SubjectPublicKeyInfo SEQUENCE, or
// nil if absent/unparseable.
func certRequestPublicKeyDER(certReqDER []byte) []byte {
	var certReq asn1.RawValue
	if _, err := asn1.Unmarshal(certReqDER, &certReq); err != nil {
		return nil
	}
	// CertRequest ::= SEQUENCE { certReqId INTEGER, certTemplate SEQUENCE, ... }
	inner := certReq.Bytes
	var certReqID asn1.RawValue
	inner, err := asn1.Unmarshal(inner, &certReqID)
	if err != nil {
		return nil
	}
	var certTemplate asn1.RawValue
	if _, err := asn1.Unmarshal(inner, &certTemplate); err != nil {
		return nil
	}
	fields := certTemplate.Bytes
	for len(fields) > 0 {
		var field asn1.RawValue
		fields, err = asn1.Unmarshal(fields, &field)
		if err != nil {
			return nil
		}
		if field.Class == asn1.ClassContextSpecific && field.Tag == 6 {
			spki, e := wrapSequenceDER(field.Bytes, "SubjectPublicKeyInfo")
			if e != nil {
				return nil
			}
			return spki
		}
	}
	return nil
}

// oidRegCtrlOldCertID is RFC 4211 §6.2 id-regCtrl-oldCertID (1.3.6.1.5.5.7.5.1.5).
var oidRegCtrlOldCertID = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 5, 1, 5}

// parseOldCertIDControl scans an optional CertRequest `controls` field
// (SEQUENCE OF AttributeTypeAndValue) for id-regCtrl-oldCertID and decodes its
// CertId value { issuer GeneralName, serialNumber INTEGER }. It returns nil if
// controls is absent, the control is not present, or anything fails to parse —
// the control is optional, so a parse problem must not break enrollment.
func parseOldCertIDControl(controlsDER []byte) *oldCertID {
	if len(controlsDER) == 0 {
		return nil
	}
	var controlsSeq asn1.RawValue
	if _, err := asn1.Unmarshal(controlsDER, &controlsSeq); err != nil {
		return nil
	}
	if controlsSeq.Tag != asn1.TagSequence || controlsSeq.Class != asn1.ClassUniversal {
		return nil
	}

	rest := controlsSeq.Bytes
	for len(rest) > 0 {
		var attr asn1.RawValue
		var err error
		rest, err = asn1.Unmarshal(rest, &attr)
		if err != nil {
			return nil
		}
		// AttributeTypeAndValue ::= SEQUENCE { type OID, value ANY }
		var oid asn1.ObjectIdentifier
		valDER, err := asn1.Unmarshal(attr.Bytes, &oid)
		if err != nil || !oid.Equal(oidRegCtrlOldCertID) {
			continue
		}
		// value is CertId ::= SEQUENCE { issuer GeneralName, serialNumber INTEGER }
		var certIDSeq asn1.RawValue
		if _, err := asn1.Unmarshal(valDER, &certIDSeq); err != nil {
			return nil
		}
		inner := certIDSeq.Bytes
		var issuer asn1.RawValue
		inner, err = asn1.Unmarshal(inner, &issuer)
		if err != nil {
			return nil
		}
		// issuer GeneralName directoryName [4] EXPLICIT Name: issuer.Bytes is the
		// RDNSequence DER, directly comparable to x509.Certificate.RawIssuer.
		if issuer.Class != asn1.ClassContextSpecific || issuer.Tag != 4 {
			return nil
		}
		var serial *big.Int
		if _, err := asn1.Unmarshal(inner, &serial); err != nil {
			return nil
		}
		return &oldCertID{IssuerNameDER: issuer.Bytes, SerialNumber: serial}
	}
	return nil
}

// cmpSignerCertFromGin returns the verified CMP protection (signer) certificate
// that HandleCMP stashed on the request context after protection verification,
// or nil when the request was unprotected.
func cmpSignerCertFromGin(ctx *gin.Context) *x509.Certificate {
	v := ctx.Request.Context().Value(string(identityextractors.IdentityExtractorCMPSignerCertificate))
	cert, _ := v.(*x509.Certificate)
	return cert
}

// certTemplateNameMatches reports whether the DER-encoded X.501 Name in a CMP
// CertTemplate field (issuer [3] / subject [5]) is equal to want. The
// comparison is semantic: the DER is parsed into an RDNSequence and compared by
// its canonical string form, so it tolerates the encoding differences that
// arise when a CMP client re-encodes a Name extracted from a parsed certificate
// (e.g. PrintableString vs UTF8String) — a raw byte comparison would reject
// legitimately-equal names. An unparseable DER never matches.
func certTemplateNameMatches(der []byte, want pkix.Name) bool {
	var rdn pkix.RDNSequence
	if _, err := asn1.Unmarshal(der, &rdn); err != nil {
		return false
	}
	var got pkix.Name
	got.FillFromRDNSequence(&rdn)
	return got.String() == want.String()
}

// validateOldCertID checks that a KUR's id-regCtrl-oldCertID references the
// certificate actually being updated — the protection (signer) certificate.
// Issuer (DER-compared against RawIssuer) and serialNumber must both match;
// otherwise it returns a badCertId cert-request rejection. Returns nil when no
// oldCertID control was supplied (it is optional, RFC 9483 §4.1.3).
func validateOldCertID(req *firstCertReq, signer *x509.Certificate) *certRequestRejection {
	oc := req.OldCertID
	if oc == nil {
		return nil
	}
	serialMatches := oc.SerialNumber != nil && signer.SerialNumber != nil &&
		oc.SerialNumber.Cmp(signer.SerialNumber) == 0
	issuerMatches := bytes.Equal(oc.IssuerNameDER, signer.RawIssuer)
	if serialMatches && issuerMatches {
		return nil
	}
	return &certRequestRejection{
		CertReqID:   req.CertReqID,
		Reason:      "controls oldCertId does not match the certificate being updated (RFC 9483 §4.1.3)",
		FailInfoBit: pkiFailureInfoBadCertId,
	}
}

func normalizeSequenceDER(der []byte, label string) ([]byte, error) {
	var rv asn1.RawValue
	if _, err := asn1.Unmarshal(der, &rv); err == nil && rv.Class == asn1.ClassUniversal && rv.Tag == asn1.TagSequence {
		return rv.FullBytes, nil
	}

	wrapped, err := wrapSequenceDER(der, label)
	if err != nil {
		return nil, err
	}

	var wrappedRV asn1.RawValue
	if _, err := asn1.Unmarshal(wrapped, &wrappedRV); err != nil {
		return nil, fmt.Errorf("%s: %w", label, err)
	}
	return wrappedRV.FullBytes, nil
}

func wrapSequenceDER(content []byte, label string) ([]byte, error) {
	der, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      content,
	})
	if err != nil {
		return nil, fmt.Errorf("rewrap %s: %w", label, err)
	}
	return der, nil
}

func decodeRequestHeader(headerDER []byte) (requestPKIHeader, error) {
	var seq asn1.RawValue
	if _, err := asn1.Unmarshal(headerDER, &seq); err != nil {
		return requestPKIHeader{}, fmt.Errorf("PKIHeader: %w", err)
	}
	if seq.Class != asn1.ClassUniversal || seq.Tag != asn1.TagSequence {
		return requestPKIHeader{}, fmt.Errorf("PKIHeader is not a SEQUENCE")
	}

	var header requestPKIHeader
	remaining := seq.Bytes

	var pvnoRaw asn1.RawValue
	var err error
	remaining, err = asn1.Unmarshal(remaining, &pvnoRaw)
	if err != nil {
		return requestPKIHeader{}, fmt.Errorf("pvno: %w", err)
	}
	if _, err := asn1.Unmarshal(pvnoRaw.FullBytes, &header.PVNO); err != nil {
		return requestPKIHeader{}, fmt.Errorf("parse pvno: %w", err)
	}

	remaining, err = asn1.Unmarshal(remaining, &header.Sender)
	if err != nil {
		return requestPKIHeader{}, fmt.Errorf("sender: %w", err)
	}

	remaining, err = asn1.Unmarshal(remaining, &header.Recipient)
	if err != nil {
		return requestPKIHeader{}, fmt.Errorf("recipient: %w", err)
	}

	for len(remaining) > 0 {
		var field asn1.RawValue
		remaining, err = asn1.Unmarshal(remaining, &field)
		if err != nil {
			return requestPKIHeader{}, fmt.Errorf("optional header field: %w", err)
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
			header.TransactionID, err = decodeExplicitOctetString(field.Bytes, "transactionID")
		case 5:
			header.SenderNonce, err = decodeExplicitOctetString(field.Bytes, "senderNonce")
		case 6:
			header.RecipNonce, err = decodeExplicitOctetString(field.Bytes, "recipNonce")
		case 8:
			header.GeneralInfo, err = decodeGeneralInfo(field.Bytes)
		}
		if err != nil {
			return requestPKIHeader{}, err
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
func hasImplicitConfirmOID(generalInfo []asn1.RawValue) bool {
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
func extractOrigPKIMessage(generalInfo []asn1.RawValue) (*rawPKIMessageFull, pkix.AlgorithmIdentifier, bool) {
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
		var orig rawPKIMessageFull
		if _, err := asn1.Unmarshal(itav.Value.Bytes, &orig); err != nil {
			continue
		}
		origHeader, err := decodeRequestHeader(orig.Header.FullBytes)
		if err != nil {
			continue
		}
		return &orig, origHeader.ProtectionAlg, true
	}
	return nil, pkix.AlgorithmIdentifier{}, false
}

func decodeExplicitOctetString(der []byte, label string) ([]byte, error) {
	var value []byte
	if _, err := asn1.Unmarshal(der, &value); err != nil {
		return nil, fmt.Errorf("%s: %w", label, err)
	}
	return value, nil
}

func decodeCertConfStatuses(seqDER []byte) ([]certStatusASN1, error) {
	var outer asn1.RawValue
	if _, err := asn1.Unmarshal(seqDER, &outer); err != nil {
		return nil, fmt.Errorf("CertConfirmContent: %w", err)
	}
	if outer.Class != asn1.ClassUniversal || outer.Tag != asn1.TagSequence {
		return nil, fmt.Errorf("CertConfirmContent is not a SEQUENCE")
	}

	var statuses []certStatusASN1
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

		var status certStatusASN1
		status.CertHash, err = findFirstOctetString(certStatusSeq.FullBytes)
		if err != nil {
			return nil, fmt.Errorf("certHash: %w", err)
		}
		if len(status.CertHash) == 0 {
			return nil, fmt.Errorf("certHash missing")
		}

		// Parse certReqId (INTEGER) and the optional statusInfo (PKIStatusInfo
		// SEQUENCE) and hashAlg [0] from the CertStatus SEQUENCE fields. The
		// caller relies on CertReqID and StatusInfo for the structural
		// validation in handleCertConf (RFC 9483 §4.1.1).
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
func parseCertStatusFields(content []byte, status *certStatusASN1) {
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
			// certHash — already captured via findFirstOctetString.
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
		// hashAlg is [0] IMPLICIT — context-specific, tag 0, constructed.
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

func findFirstOctetString(der []byte) ([]byte, error) {
	var root asn1.RawValue
	if _, err := asn1.Unmarshal(der, &root); err != nil {
		return nil, err
	}
	return findOctetStringInRaw(root)
}

func findOctetStringInRaw(rv asn1.RawValue) ([]byte, error) {
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
		found, err := findOctetStringInRaw(child)
		if err != nil {
			return nil, err
		}
		if len(found) > 0 {
			return found, nil
		}
	}
	return nil, nil
}

// verifyPOPO verifies the Proof-Of-Possession for an ir/cr CertReqMsg.
//
// Per RFC 9483 §4.1, the POPO signature (if present) is a self-signature by the
// new private key over the DER-encoded CertRequest (certReqDER). If the POPO is
// errPOPORAVerifiedFromEE signals that the request carried a raVerified [0]
// POPO. On this endpoint the requester authenticates as an end entity (the
// message-protection signer), so asserting raVerified is unauthorized; the
// caller maps this to PKIFailureInfo notAuthorized rather than badPOP.
var errPOPORAVerifiedFromEE = errors.New("raVerified POPO not accepted from an end entity (RFC 9483 §4.1)")

// absent and enforce is true the request is rejected. If raVerified [0] is set
// the request is rejected as notAuthorized (see errPOPORAVerifiedFromEE).
// For KUR, POPO is proven implicitly by the message-level protection key being the
// old cert key (RFC 9483 §4.1.3), so this function is NOT called for KUR.
func verifyPOPO(certReqDER []byte, popoRaw asn1.RawValue, pubKeyDER []byte, enforce bool) error {
	isPOPOPresent := len(popoRaw.FullBytes) > 0

	if !isPOPOPresent {
		if enforce {
			return fmt.Errorf("proof of possession (POPO) is required but absent in the certificate request")
		}
		return nil
	}

	switch {
	case popoRaw.Class == asn1.ClassContextSpecific && popoRaw.Tag == 0:
		// raVerified [0] NULL — asserts "an RA already verified POPO". On this
		// endpoint the message-protection signer IS the requester (an EE); there
		// is no trusted-RA path, so an EE asserting raVerified is bypassing POPO
		// and MUST be rejected as notAuthorized (RFC 9483 §4.1 / RFC 4211 §4).
		return errPOPORAVerifiedFromEE

	case popoRaw.Class == asn1.ClassContextSpecific && popoRaw.Tag == 1:
		// signature [1] POPOSigningKey
		return checkPOPOSigningKey(certReqDER, popoRaw.Bytes, pubKeyDER)

	default:
		// keyEncipherment [2] / keyAgreement [3] are not used in the LWC profile.
		if !enforce {
			return nil
		}
		return fmt.Errorf("unsupported POPO type (class=%d tag=%d): only raVerified [0] and signature [1] are supported", popoRaw.Class, popoRaw.Tag)
	}
}

// checkPOPOSigningKey verifies a POPOSigningKey against certReqDER.
//
// POPOSigningKey ::= SEQUENCE {
//
//	poposkInput  [0] POPOSigningKeyInput OPTIONAL,
//	algorithmIdentifier AlgorithmIdentifier,
//	signature   BIT STRING
//
// }
//
// The signature is over the DER encoding of CertRequest (certReqDER).
func checkPOPOSigningKey(certReqDER, poposkContent, pubKeyDER []byte) error {
	remaining := poposkContent

	// Skip optional [0] poposkInput (only present when subject/key absent from certTemplate).
	{
		var first asn1.RawValue
		peek, err := asn1.Unmarshal(remaining, &first)
		if err != nil {
			return fmt.Errorf("POPO: parse first field: %w", err)
		}
		if first.Class == asn1.ClassContextSpecific && first.Tag == 0 {
			remaining = peek // consume the optional poposkInput
		}
	}

	// Parse AlgorithmIdentifier.
	var algID pkix.AlgorithmIdentifier
	rest, err := asn1.Unmarshal(remaining, &algID)
	if err != nil {
		return fmt.Errorf("POPO: parse AlgorithmIdentifier: %w", err)
	}

	// Parse BIT STRING signature.
	var sig asn1.BitString
	if _, err := asn1.Unmarshal(rest, &sig); err != nil {
		return fmt.Errorf("POPO: parse signature: %w", err)
	}

	// Parse the public key from SubjectPublicKeyInfo DER.
	pubKey, err := x509.ParsePKIXPublicKey(pubKeyDER)
	if err != nil {
		return fmt.Errorf("POPO: parse public key: %w", err)
	}

	return popoVerifySignature(certReqDER, sig.Bytes, algID, pubKey)
}

// popoVerifySignature verifies a raw signature over data using the algorithm
// identified by algID. Supports RSA PKCS#1v15, RSASSA-PSS, ECDSA, and Ed25519.
func popoVerifySignature(data, sigBytes []byte, algID pkix.AlgorithmIdentifier, pub crypto.PublicKey) error {
	// Use the AlgorithmIdentifier-aware helper so that id-RSASSA-PSS
	// (OID 1.2.840.113549.1.1.10) resolves its hash from the Parameters
	// SEQUENCE per RFC 4055 §3.1; the OID-only variant rejects PSS.
	hashAlg, err := hashFromSignatureAlgID(algID)
	if err != nil {
		return fmt.Errorf("POPO: %w", err)
	}

	switch pub := pub.(type) {
	case *rsa.PublicKey:
		if hashAlg == 0 {
			return fmt.Errorf("POPO: RSA key with no hash algorithm (OID %s)", algID.Algorithm)
		}
		h := hashAlg.New()
		h.Write(data)
		digest := h.Sum(nil)
		// RFC 4055 §3.1: id-RSASSA-PSS uses RSA-PSS, not PKCS#1 v1.5.
		// PSSOptions{SaltLength: PSSSaltLengthAuto} lets crypto/rsa derive
		// the saltLength from the signature, matching what RFC 9481-compliant
		// clients (OpenSSL, BouncyCastle, etc.) produce.
		if algID.Algorithm.Equal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}) {
			if err := rsa.VerifyPSS(pub, hashAlg, digest, sigBytes, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto}); err != nil {
				return fmt.Errorf("POPO: RSA-PSS signature verification failed: %w", err)
			}
			return nil
		}
		if err := rsa.VerifyPKCS1v15(pub, hashAlg, digest, sigBytes); err != nil {
			return fmt.Errorf("POPO: RSA signature verification failed: %w", err)
		}
		return nil

	case *ecdsa.PublicKey:
		if hashAlg == 0 {
			return fmt.Errorf("POPO: ECDSA key with no hash algorithm (OID %s)", algID.Algorithm)
		}
		h := hashAlg.New()
		h.Write(data)
		if !ecdsa.VerifyASN1(pub, h.Sum(nil), sigBytes) {
			return fmt.Errorf("POPO: ECDSA signature verification failed")
		}
		return nil

	case ed25519.PublicKey:
		if !ed25519.Verify(pub, data, sigBytes) {
			return fmt.Errorf("POPO: Ed25519 signature verification failed")
		}
		return nil

	default:
		return fmt.Errorf("POPO: unsupported public key type %T", pub)
	}
}

// buildSyntheticCSR constructs a *x509.CertificateRequest from the Subject and
// SubjectPublicKeyInfo carried in a CMP CertTemplate (RFC 4211 §5).
//
// Because POPO is handled at the CMP layer (not inside the CSR), the resulting
// CSR has a dummy 1-byte zero signature. Set VerifyCSRSignature=false in the
// DMS EnrollmentSettings when using CMP to bypass csr.CheckSignature().
func buildSyntheticCSR(subjectDER, spkiDER []byte, extensions []pkix.Extension) (*x509.CertificateRequest, error) {
	// Parse public key to determine signature algorithm.
	pubKey, err := x509.ParsePKIXPublicKey(spkiDER)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}

	// Select a signature algorithm OID compatible with the key type.
	var sigAlgOID asn1.ObjectIdentifier
	switch pubKey.(type) {
	case *rsa.PublicKey:
		sigAlgOID = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11} // SHA256WithRSA
	case *ecdsa.PublicKey:
		sigAlgOID = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2} // ECDSAWithSHA256
	default:
		sigAlgOID = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11} // fallback RSA
	}

	// Assemble the CertificationRequestInfo attributes field ([0] IMPLICIT SET
	// OF Attribute). It is REQUIRED by Go's x509.ParseCertificateRequest even
	// when empty; omitting the tag causes "sequence truncated".
	//
	// The requested CertTemplate extensions (KeyUsage/ExtKeyUsage/SAN) MUST be
	// carried inside the DER via a PKCS#9 extensionRequest attribute — NOT just
	// attached to the parsed Go struct — because the CA client re-serializes the
	// CSR from its .Raw bytes over HTTP, which would drop struct-only fields.
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

	// Assemble CertificationRequest with dummy signature.
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

	// Parse into *x509.CertificateRequest to populate all exported fields.
	// x509.ParseCertificateRequest reads the extensionRequest attribute we
	// embedded above into csr.Extensions, so the requested extensions survive
	// the CA client's .Raw-based re-serialization. What actually lands on the
	// issued cert is still gated by the issuance profile's Honor* flags.
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
	// Extensions ::= SEQUENCE OF Extension
	extsSeqDER, err := asn1.Marshal(exts)
	if err != nil {
		return nil, fmt.Errorf("marshal extensions sequence: %w", err)
	}
	// AttributeValue SET OF { Extensions }
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

func cmpTagToString(t int) string {
	switch t {
	case cmpBodyTagIR:
		return "ir"
	case cmpBodyTagCR:
		return "cr"
	case cmpBodyTagKUR:
		return "kur"
	case cmpBodyTagCP:
		return "cp"
	case cmpBodyTagIP:
		return "ip"
	case cmpBodyTagKUP:
		return "kup"
	case cmpBodyTagRR:
		return "rr"
	case cmpBodyTagRP:
		return "rp"
	case cmpBodyTagCertConf:
		return "certConf"
	case cmpBodyTagPKIConf:
		return "pkiConf"
	case cmpBodyTagError:
		return "error"
	case cmpBodyTagPollReq:
		return "pollReq"
	case cmpBodyTagPollRep:
		return "pollRep"
	case cmpBodyTagGenMsg:
		return "genm"
	case cmpBodyTagGenRep:
		return "genp"
	default:
		return fmt.Sprintf("unknown(%d)", t)
	}
}
