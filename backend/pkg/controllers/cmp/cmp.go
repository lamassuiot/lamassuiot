package cmp

import (
	"bytes"
	"context"
	"crypto"
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
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	cmpwfx "github.com/lamassuiot/lamassuiot/backend/v3/pkg/integrations/wfx"
	corecmp "github.com/lamassuiot/lamassuiot/core/v3/pkg/cmp"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/errs"
	chelpers "github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
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

// RequirePKIXCMP is a Gin middleware that rejects requests whose Content-Type
// is not application/pkixcmp with HTTP 415 Unsupported Media Type.
func RequirePKIXCMP() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		ct := ctx.GetHeader("Content-Type")
		if ct != "application/pkixcmp" {
			ctx.AbortWithStatusJSON(http.StatusUnsupportedMediaType, gin.H{
				"error": "Content-Type must be application/pkixcmp",
			})
			return
		}
		ctx.Next()
	}
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
		r.rejectWithError(ctx, nil, corecmp.PKIStatus(2), "missing DMS id", "", corecmp.PKIFailureInfoBadRequest)
		return
	}

	// Read DER body
	bodyBytes, err := io.ReadAll(ctx.Request.Body)
	if err != nil || len(bodyBytes) == 0 {
		r.rejectWithError(ctx, nil, corecmp.PKIStatus(2), "cannot read request body", dmsID, corecmp.PKIFailureInfoBadDataFormat)
		return
	}

	// Decode PKIMessage fully (including Protection and ExtraCerts for verification).
	var fullMsg corecmp.RawPKIMessageFull
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

	reqHeader, err := corecmp.DecodeRequestHeader(header.FullBytes)
	if err != nil {
		lFunc.Warnf("failed to decode PKIHeader: %v", err)
		r.rejectWithError(ctx, nil, corecmp.PKIStatus(2), "malformed PKIHeader", dmsID, corecmp.PKIFailureInfoBadDataFormat)
		return
	}

	// Run wire-level envelope validation (pvno, transactionID, senderNonce,
	// messageTime drift). See cmp_validator.go — extracted so the controller
	// stays a dispatcher and each rule is unit-testable in isolation.
	if rej := validateRequestEnvelope(reqHeader, time.Now(), body.Tag); rej != nil {
		lFunc.Warnf("envelope validation: %s", rej.reason)
		r.rejectWithError(ctx, &reqHeader, corecmp.PKIStatus(2), rej.reason, dmsID, rej.failInfo)
		return
	}
	if rej := validateGeneralInfo(reqHeader.GeneralInfo); rej != nil {
		lFunc.Warnf("generalInfo validation: %s", rej.reason)
		r.rejectWithError(ctx, &reqHeader, corecmp.PKIStatus(2), rej.reason, dmsID, rej.failInfo)
		return
	}

	// RFC 9483 §3.1: recipNonce MUST be absent in the initial request of a
	// transaction (ir/cr/p10cr). If the EE set it, reject per §3.5 badRecipientNonce.
	if (body.Tag == corecmp.BodyTagIR || body.Tag == corecmp.BodyTagCR || body.Tag == corecmp.BodyTagP10CR) && len(reqHeader.RecipNonce) > 0 {
		lFunc.Warnf("recipNonce present on initial %s message", cmpTagToString(body.Tag))
		r.rejectWithError(ctx, &reqHeader, corecmp.PKIStatus(2),
			"recipNonce must be absent in the initial request (RFC 9483 §3.1)",
			dmsID, corecmp.PKIFailureInfoBadRecipientNonce)
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
		r.rejectWithError(ctx, &reqHeader, corecmp.PKIStatus(2), "could not load DMS configuration", dmsID, corecmp.PKIFailureInfoSystemFailure)
		return
	}

	// Stash the resolved WFX workflow name on the request context so every
	// reportCMPState call for this request lands in (and only transitions
	// within) the DMS's selected workflow.
	// RFC011: resolve the effective workflow for the request's operation so the
	// WFX job is created in the workflow that will actually run (a per-operation
	// policy_overrides.workflow can differ from the DMS-general one). Non-
	// enrollment tags resolve to the general workflow.
	workflowName := cmpwfx.WorkflowNameFor(enrollOpts.EffectiveWorkflow(cmpTagToString(body.Tag)))
	ctx.Request = ctx.Request.WithContext(context.WithValue(ctx.Request.Context(), cmpWorkflowCtxKey, workflowName))

	// Received is only meaningful for enrollment-initiating messages
	// (IR/CR/P10CR/KUR). Follow-up messages (certConf, pollReq, rr) reference an
	// already-created WFX job that is well past Received; emitting it on such
	// jobs would attempt an invalid backward transition (e.g. AwaitingCertConf
	// → Received) which either gets rejected by WFX or silently resets the job
	// to the wrong state.
	if body.Tag == corecmp.BodyTagIR || body.Tag == corecmp.BodyTagCR || body.Tag == corecmp.BodyTagP10CR || body.Tag == corecmp.BodyTagKUR {
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
	requireProtection := requireClientCertProtection(enrollOpts)
	// RFC 9483 §5.3.2 / RFC011: a revocation request (rr) MUST be
	// signature-protected regardless of the DMS auth_mode — an unsigned rr is
	// never accepted, even under NO_AUTH / EXTERNAL_WEBHOOK. This is a fixed
	// protocol invariant, not a per-DMS toggle.
	if body.Tag == corecmp.BodyTagRR {
		requireProtection = true
	}
	// RFC 9483 §4.3 / RFC011 GENM.AccessPolicy: general messages are
	// informational capability-discovery queries whose protection requirement
	// is governed by the SEPARATE GENM.AccessPolicy, NOT the enrollment
	// auth_mode. That separation is the whole point of the field — a DMS may
	// require client-certificate protection for enrollment (ir/cr/kur) yet
	// still answer discovery genm unauthenticated (public_discovery). Setting
	// GENM.AccessPolicy=require_signed opts genm back into mandatory protection.
	// This deliberately overrides the auth_mode-derived default above so that
	// public_discovery is honoured on every deployment, not only on DMSes whose
	// auth_mode happens not to require a client certificate.
	if body.Tag == corecmp.BodyTagGenMsg {
		requireProtection = enrollOpts.GENM.AccessPolicy == models.CMPGENMAccessPolicyRequireSigned
	}
	signerCert, err := verifyRequestProtection(fullMsg, reqHeader.ProtectionAlg, requireProtection)
	if err != nil {
		lFunc.Warnf("protection verification failed: %v", err)
		// Map error category to PKIFailureInfo per RFC 9810 §5.1.3 / RFC 9483
		// §3.6.4: a rejected protection AlgorithmIdentifier carries its own bit
		// (badAlg for an unknown/unsupported algorithm, wrongIntegrity for a
		// MAC-based protection where a signature was required); anything else
		// (signature mismatch, missing extraCerts, malformed protection field)
		// maps to badMessageCheck.
		failBit := protectionRejectFailInfo(err)
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
		if body.Tag != corecmp.BodyTagGenMsg {
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
	}

	// RFC 9483 §5.2.3: when a PKI management entity forwards the EE's original
	// message inside generalInfo (id-it-origPKIMessage), the CA MUST verify that
	// original message's own protection. The RA is vouching (e.g. via
	// raVerified) for a message the EE signed; a broken original protection
	// means that assertion cannot be trusted, so the request is rejected with
	// badMessageCheck (RFC 9483 §3.5) regardless of the outer RA protection
	// being valid.
	if origFull, origAlg, ok := corecmp.ExtractOrigPKIMessage(reqHeader.GeneralInfo); ok {
		if _, err := verifyRequestProtection(*origFull, origAlg, true); err != nil {
			lFunc.Warnf("origPKIMessage protection verification failed: %v", err)
			r.rejectRequest(ctx, lFunc, reqHeader, body.Tag,
				fmt.Sprintf("original PKIMessage (generalInfo) protection verification failed: %v", err),
				corecmp.PKIFailureInfoBadMessageCheck, dmsID)
			return
		}
	}

	// Per-operation enable gates (RFC011): a DMS may disable individual CMP
	// operations. Rejected uniformly here at dispatch with notAuthorized before
	// any handler runs. Follow-up/transport messages (certConf, pollReq,
	// popdecr, nested) are not gated — they continue an already-authorized
	// transaction.
	if !operationEnabled(enrollOpts, body.Tag) {
		lFunc.Warnf("CMP operation %s is disabled for DMS '%s'", cmpTagToString(body.Tag), dmsID)
		r.rejectRequest(ctx, lFunc, reqHeader, body.Tag,
			fmt.Sprintf("CMP operation %s is not enabled for this DMS", cmpTagToString(body.Tag)),
			corecmp.PKIFailureInfoNotAuthorized, dmsID)
		return
	}

	// Dispatch on body CHOICE tag
	switch body.Tag {
	case corecmp.BodyTagIR, corecmp.BodyTagCR:
		r.handleEnrollment(ctx, lFunc, reqHeader, body, dmsID, enrollOpts, enrollmentVariantInitial, signerCert)
	case corecmp.BodyTagP10CR:
		r.handleP10CR(ctx, lFunc, reqHeader, body, dmsID, enrollOpts, signerCert)
	case corecmp.BodyTagKUR:
		r.handleEnrollment(ctx, lFunc, reqHeader, body, dmsID, enrollOpts, enrollmentVariantUpdate, signerCert)
	case corecmp.BodyTagRR:
		r.handleRevoke(ctx, lFunc, reqHeader, body, dmsID, enrollOpts, signerCert)
	case corecmp.BodyTagCCR:
		r.handleCrossCertification(ctx, lFunc, reqHeader, body, dmsID, enrollOpts, signerCert)
	case corecmp.BodyTagNested:
		r.handleNested(ctx, lFunc, reqHeader, body, dmsID)
	case corecmp.BodyTagCertConf:
		r.handleCertConf(ctx, lFunc, reqHeader, body, bodyBytes, dmsID, signerCert)
	case corecmp.BodyTagPollReq:
		r.handlePoll(ctx, lFunc, reqHeader, body, dmsID, enrollOpts)
	case corecmp.BodyTagPopDecr:
		r.handlePOPODecKeyResp(ctx, lFunc, reqHeader, body, dmsID, enrollOpts, signerCert)
	case corecmp.BodyTagGenMsg:
		r.handleGeneralMessage(ctx, lFunc, reqHeader, body, dmsID, enrollOpts, signerCert)
	default:
		lFunc.Warnf("unsupported CMP body tag %d", body.Tag)
		r.rejectWithError(ctx, &reqHeader, corecmp.PKIStatus(2),
			fmt.Sprintf("unsupported body tag %d", body.Tag), dmsID, corecmp.PKIFailureInfoBadRequest)
	}
}

// operationEnabled reports whether the DMS permits the CMP operation named by
// the body tag (RFC011 per-operation enable gates). Follow-up/transport
// messages that are not directly configurable operations return true — they
// continue a transaction that was already authorized at its initiating request.
func operationEnabled(o *models.EnrollmentOptionsLWCRFC9483, tag int) bool {
	switch tag {
	case corecmp.BodyTagIR:
		return o.IR.Enabled
	case corecmp.BodyTagCR:
		return o.CR.Enabled
	case corecmp.BodyTagP10CR:
		return o.P10CR.Enabled
	case corecmp.BodyTagKUR:
		return o.KUR.Enabled
	case corecmp.BodyTagRR:
		return o.RR.Enabled
	case corecmp.BodyTagCCR:
		return o.CCR.Enabled
	case corecmp.BodyTagGenMsg:
		return o.GENM.Enabled
	default:
		return true
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
func (r *cmpHttpRoutes) handleRevoke(ctx *gin.Context, lFunc *logrus.Entry, header corecmp.RequestPKIHeader, body asn1.RawValue, dmsID string, enrollOpts *models.EnrollmentOptionsLWCRFC9483, signerCert *x509.Certificate) {
	rd, err := corecmp.DecodeRevDetails(body.Bytes)
	if err != nil {
		lFunc.Errorf("rr: decode RevDetails: %v", err)
		r.rejectRevocation(ctx, lFunc, header, "malformed RevReqContent", corecmp.PKIFailureInfoBadDataFormat, dmsID)
		return
	}

	// --- CRLReason validation (RFC 9483 §4.2 / RFC 5280 §5.3.1) ---
	// More than one CRLReason extension (including a revoke+revive mix) is a
	// malformed request → badRequest.
	if rd.ReasonExtCount > 1 {
		lFunc.Warnf("rr: %d CRLReason extensions present", rd.ReasonExtCount)
		r.rejectRevocation(ctx, lFunc, header, "more than one CRLReason extension", corecmp.PKIFailureInfoBadRequest, dmsID)
		return
	}
	if rd.ReasonDecodeErr {
		r.rejectRevocation(ctx, lFunc, header, "malformed CRLReason value", corecmp.PKIFailureInfoBadDataFormat, dmsID)
		return
	}
	for _, rc := range rd.Reasons {
		if !corecmp.IsKnownCRLReason(rc) {
			lFunc.Warnf("rr: unknown CRLReason %d", rc)
			r.rejectRevocation(ctx, lFunc, header, fmt.Sprintf("unknown CRLReason %d", rc), corecmp.PKIFailureInfoBadDataFormat, dmsID)
			return
		}
	}
	reason := 0
	if len(rd.Reasons) == 1 {
		reason = rd.Reasons[0]
	}
	revive := reason == corecmp.CRLReasonRemoveFromCRL

	// version[9], when present, is asserted by the requester as additional
	// information (RFC 9483 §4.2) and MUST match what every cert Lamassu
	// issues carries: X.509 v3. Checked before the signer-bound comparisons
	// below because it doesn't depend on having a signer cert at all.
	if rd.HasVersion && rd.Version != 2 {
		lFunc.Warnf("rr: CertTemplate version %d asserted, expected v3 (2)", rd.Version)
		r.rejectRevocation(ctx, lFunc, header, fmt.Sprintf("CertTemplate version must be v3 (2), got %d (RFC 9483 §4.2)", rd.Version), corecmp.PKIFailureInfoBadRequest, dmsID)
		return
	}

	// --- CertTemplate validation against the protection certificate ---
	// The cert being revoked signs its own rr, so its CertTemplate fields MUST
	// match the signer cert. This is only enforced for protected requests; an
	// unprotected request (NO_AUTH DMS, no signer cert) revokes by serial alone.
	//
	// Exception (RFC 9483 §5.3.2): a trusted PKI management entity (id-kp-cmcRA)
	// may revoke ANOTHER entity's certificate. In that case the CertTemplate
	// references the target certificate, not the signer, so the signer-match
	// checks are skipped; authorization is enforced by the service layer, which
	// chain-validates the RA signer against the DMS validation CAs before
	// acting (an untrusted cert merely claiming the cmcRA EKU is rejected there
	// with signerNotTrusted).
	signer := signerCert
	raInitiated := signer != nil && rd.HasSerial && signer.SerialNumber != nil &&
		new(big.Int).SetBytes(rd.SerialNumber).Cmp(signer.SerialNumber) != 0 &&
		chelpers.CertHasExtKeyUsageOID(signer, chelpers.OidExtKeyUsageCMCRA)
	if raInitiated {
		lFunc.Infof("rr: RA-initiated revocation (signer CN=%s carries id-kp-cmcRA, target serial differs)", signer.Subject.CommonName)
		if !rd.HasIssuer {
			r.rejectRevocation(ctx, lFunc, header, "missing issuer in CertTemplate", corecmp.PKIFailureInfoAddInfoNotAvailable, dmsID)
			return
		}
	} else if signer != nil {
		if !rd.HasIssuer {
			r.rejectRevocation(ctx, lFunc, header, "missing issuer in CertTemplate", corecmp.PKIFailureInfoAddInfoNotAvailable, dmsID)
			return
		}
		if !rd.HasSerial {
			r.rejectRevocation(ctx, lFunc, header, "missing serialNumber in CertTemplate", corecmp.PKIFailureInfoAddInfoNotAvailable, dmsID)
			return
		}
		if signer.SerialNumber != nil &&
			new(big.Int).SetBytes(rd.SerialNumber).Cmp(signer.SerialNumber) != 0 {
			r.rejectRevocation(ctx, lFunc, header, "serialNumber does not match certificate", corecmp.PKIFailureInfoBadCertID, dmsID)
			return
		}
		// Compare the issuer/subject Names semantically rather than by raw DER:
		// CMP clients re-encode the Name from the parsed certificate, so the
		// byte encoding (string types, etc.) can legitimately differ from the
		// certificate's original RawIssuer/RawSubject even when the names are
		// equal. A raw bytes.Equal here would reject every valid revocation.
		if !certTemplateNameMatches(rd.IssuerDER, signer.Issuer) {
			r.rejectRevocation(ctx, lFunc, header, "issuer does not match certificate", corecmp.PKIFailureInfoBadCertID, dmsID)
			return
		}
		if rd.HasSubject && !certTemplateNameMatches(rd.SubjectDER, signer.Subject) {
			r.rejectRevocation(ctx, lFunc, header, "subject does not match certificate", corecmp.PKIFailureInfoBadCertID, dmsID)
			return
		}
		if rd.HasPublicKey && !bytes.Equal(rd.PublicKeyDER, signer.RawSubjectPublicKeyInfo) {
			r.rejectRevocation(ctx, lFunc, header, "publicKey does not match certificate", corecmp.PKIFailureInfoBadCertID, dmsID)
			return
		}
		// extensions[9], like subject/publicKey above, is optional additional
		// information the requester asserts about the cert being revoked; RFC
		// 9483 §4.2 requires it to match exactly when present.
		if rd.HasExtensions && !extensionsMatch(rd.Extensions, signer.Extensions) {
			r.rejectRevocation(ctx, lFunc, header, "extensions do not match certificate", corecmp.PKIFailureInfoBadCertID, dmsID)
			return
		}
	} else if !rd.HasSerial {
		r.rejectRevocation(ctx, lFunc, header, "missing serialNumber in CertTemplate", corecmp.PKIFailureInfoBadDataFormat, dmsID)
		return
	}

	serialHex := hex.EncodeToString(rd.SerialNumber)
	lFunc = lFunc.WithField("serial", serialHex)
	lFunc.Infof("revocation request serial=%s reason=%d revive=%t", serialHex, reason, revive)

	if err := r.svc.LWCRevokeCertificate(ctx.Request.Context(), services.RevokeCertificateInput{
		APS:          dmsID,
		SerialNumber: serialHex,
		Reason:       models.RevocationReason(reason),
	}, signer); err != nil {
		lFunc.Errorf("rr: revoke failed: %v", err)
		// Map the service-layer error to the appropriate PKIFailureInfo bit
		// (RFC 9810 §5.1.3 / RFC 9483 §3.6.4) and deliver it in an rp body:
		//   - certificate not found / bad serial                  → badCertId
		//   - illegal status transition on a revoke (already
		//     revoked)                                            → certRevoked
		//   - illegal status transition on a revive (target is
		//     not revoked / cannot be revived)                    → badCertId
		//   - anything else                                       → systemFailure
		failBit := corecmp.PKIFailureInfoSystemFailure
		switch {
		case errors.Is(err, errs.ErrCertificateNotFound):
			failBit = corecmp.PKIFailureInfoBadCertID
		case errors.Is(err, errs.ErrDMSEnrollInvalidCert):
			// RA-initiated revocation whose signer does not chain to any DMS
			// validation CA (RFC 9483 §5.3.2): the claimed management entity is
			// not trusted.
			failBit = corecmp.PKIFailureInfoSignerNotTrusted
		case errors.Is(err, errs.ErrCMPPendingUpdate):
			// The device has a key-update awaiting certConf; its certificates'
			// revocation state must not change until the open transaction
			// completes or times out (RFC 9483 §4.1.3).
			failBit = corecmp.PKIFailureInfoBadRequest
		case errors.Is(err, errs.ErrCertificateStatusTransitionNotAllowed):
			if revive {
				failBit = corecmp.PKIFailureInfoBadCertID
			} else {
				failBit = corecmp.PKIFailureInfoCertRevoked
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
	rpDER, err := corecmp.MarshalRevRepBody(corecmp.PKIStatus(0), statusText)
	if err != nil {
		lFunc.Errorf("rr: build rp body: %v", err)
		r.rejectRevocation(ctx, lFunc, header, "cannot build rp response", corecmp.PKIFailureInfoSystemFailure, dmsID)
		return
	}
	r.sendRawBody(ctx, lFunc, header, corecmp.BodyTagRP, rpDER, dmsID)
}

// handleCertConf processes a certConf (24) body.
// It verifies the SHA-256 certHash and responds with pkiConf (19).
func (r *cmpHttpRoutes) handleCertConf(ctx *gin.Context, lFunc *logrus.Entry, header corecmp.RequestPKIHeader, body asn1.RawValue, requestDER []byte, dmsID string, signerCert *x509.Certificate) {
	// The PKIBody CHOICE uses EXPLICIT tagging (RFC 4210 Appendix F module),
	// so certConf [24] EXPLICIT CertConfirmContent means body.Bytes already
	// holds the complete CertConfirmContent SEQUENCE TLV. Decode it directly —
	// do NOT re-wrap it in another SEQUENCE, otherwise the decoder would see a
	// single element (the inner SEQUENCE) and silently collapse a multi-status
	// / wrong-certReqId body into one accepted entry.
	statuses, err := corecmp.DecodeCertConfStatuses(body.Bytes)
	if err != nil {
		lFunc.Errorf("certConf: decode: %v", err)
		r.rejectWithError(ctx, &header, corecmp.PKIStatus(2), "malformed certConf", dmsID, corecmp.PKIFailureInfoBadDataFormat)
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
		r.rejectWithError(ctx, &header, corecmp.PKIStatus(2),
			fmt.Sprintf("certConf must carry exactly one CertStatus, got %d", len(statuses)),
			dmsID, corecmp.PKIFailureInfoBadRequest)
		return
	}
	// The certReqId of the first (and only) issued certificate is 0 for
	// ir/cr/kur (RFC 9483 §4.1.1) and -1 for p10cr (RFC 4210 Errata 8806).
	// Any other value is malformed regardless of the transaction; the exact
	// per-transaction match is enforced below once the row is loaded.
	if statuses[0].CertReqID != 0 && statuses[0].CertReqID != p10crCertReqID {
		lFunc.Warnf("certConf: invalid certReqId %d (must be 0, or -1 for p10cr)", statuses[0].CertReqID)
		r.rejectWithError(ctx, &header, corecmp.PKIStatus(2),
			fmt.Sprintf("certConf certReqId must be 0 (or -1 for p10cr), got %d", statuses[0].CertReqID),
			dmsID, corecmp.PKIFailureInfoBadRequest)
		return
	}
	// A CertStatus declaring status "accepted" MUST NOT also carry a failInfo —
	// the two are mutually inconsistent (RFC 9483 §4.1.1 / RFC 4210 §5.2.3).
	if statuses[0].StatusInfo.Status == corecmp.PKIStatus(corecmp.PKIStatusAccepted) && statuses[0].StatusInfo.FailInfo.BitLength > 0 {
		lFunc.Warnf("certConf: status 'accepted' carries a failInfo (inconsistent)")
		r.rejectWithError(ctx, &header, corecmp.PKIStatus(2),
			"certConf status 'accepted' must not include a failInfo",
			dmsID, corecmp.PKIFailureInfoBadRequest)
		return
	}
	// id-it-implicitConfirm is only permitted in the generalInfo of an
	// ir/cr/kur/p10cr request or an ip/cp/kup response (RFC 9483 §3.1); it is
	// prohibited on every other body, including certConf. An EE that sets it on
	// a certConf sent a malformed header → badRequest (RFC 9483 §3.5).
	if corecmp.HasImplicitConfirmOID(header.GeneralInfo) {
		lFunc.Warnf("certConf: implicitConfirm present in generalInfo (prohibited outside ir/cr/kur/ip/cp/kup, RFC 9483 §3.1)")
		r.rejectWithError(ctx, &header, corecmp.PKIStatus(2),
			"implicitConfirm is not permitted in a certConf message (RFC 9483 §3.1)",
			dmsID, corecmp.PKIFailureInfoBadRequest)
		return
	}

	txHex := hex.EncodeToString(header.TransactionID)
	tx, ok, err := r.store.Select(ctx.Request.Context(), txHex)
	if err != nil {
		lFunc.Errorf("certConf: lookup transaction: %v", err)
		r.rejectWithError(ctx, &header, corecmp.PKIStatus(2), "internal error", dmsID, corecmp.PKIFailureInfoSystemFailure)
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
			r.rejectWithError(ctx, &header, corecmp.PKIStatus(2),
				"transaction expired: confirmation_timeout exceeded", dmsID,
				corecmp.PKIFailureInfoBadRequest)
			return
		}
		lFunc.Warnf("certConf: unknown transactionID %s", txHex)
		r.rejectWithError(ctx, &header, corecmp.PKIStatus(2), "unknown transactionID", dmsID, corecmp.PKIFailureInfoBadRequest)
		return
	}

	// Bind the certReqId to the transaction's request type: a p10cr-issued
	// certificate is confirmed with certReqId -1 (RFC 4210 Errata 8806), an
	// ir/cr/kur one with 0 (RFC 9483 §4.1.1). A mismatch means the EE is
	// confirming under the wrong convention.
	expectedCertReqID := 0
	if tx.RequestType == cmpTagToString(corecmp.BodyTagP10CR) {
		expectedCertReqID = p10crCertReqID
	}
	if statuses[0].CertReqID != expectedCertReqID {
		lFunc.Warnf("certConf: certReqId %d does not match the %s transaction (expected %d)",
			statuses[0].CertReqID, tx.RequestType, expectedCertReqID)
		r.rejectWithError(ctx, &header, corecmp.PKIStatus(2),
			fmt.Sprintf("certConf certReqId must be %d for a %s transaction, got %d",
				expectedCertReqID, tx.RequestType, statuses[0].CertReqID),
			dmsID, corecmp.PKIFailureInfoBadRequest)
		return
	}

	// RFC 9810 §5.1.1 / RFC 9483 §3.1 line 753: the EE's recipNonce on a
	// follow-up message MUST equal the server's previous senderNonce. The
	// dedicated PKIFailureInfo bit for this is badRecipientNonce (13).
	sentNonce, _ := hex.DecodeString(tx.SentNonce)
	if len(sentNonce) > 0 && !bytes.Equal(header.RecipNonce, sentNonce) {
		lFunc.Errorf("certConf: recipNonce mismatch: got %x want %x", header.RecipNonce, sentNonce)
		r.rejectWithError(ctx, &header, corecmp.PKIStatus(2), "recipNonce mismatch", dmsID, corecmp.PKIFailureInfoBadRecipientNonce)
		return
	}

	// RFC 9483 §3.1: every message carries a *fresh* senderNonce. A certConf that
	// reuses the senderNonce from the initiating request (ir/cr/kur) defeats the
	// replay protection, so reject it with badSenderNonce.
	recvNonce, _ := hex.DecodeString(tx.ReceivedNonce)
	if len(recvNonce) > 0 && bytes.Equal(header.SenderNonce, recvNonce) {
		lFunc.Errorf("certConf: senderNonce reuses the initiating request's senderNonce")
		r.rejectWithError(ctx, &header, corecmp.PKIStatus(2),
			"certConf senderNonce must be fresh, not reused from the initial request (RFC 9483 §3.1)",
			dmsID, corecmp.PKIFailureInfoBadSenderNonce)
		return
	}

	// RFC 9483 §4.1.1: the certConf MUST be protected with the same credential
	// as the original request, not the newly issued certificate. The EE cannot
	// use the just-issued cert to confirm itself — it hasn't been confirmed yet,
	// so it is not a valid protection credential for this transaction. Detect
	// this by comparing the certConf signer against the issued cert: if they are
	// the same certificate, the confirmation used the wrong authority.
	if signer := signerCert; signer != nil && tx.CertSerialNumber != "" {
		signerSerial := hex.EncodeToString(signer.SerialNumber.Bytes())
		if signerSerial == tx.CertSerialNumber {
			lFunc.Errorf("certConf: protected with the newly issued cert (SN=%s) instead of the request credential", signerSerial)
			r.rejectWithError(ctx, &header, corecmp.PKIStatus(2),
				"certConf must be protected with the original request credential, not the newly issued certificate (RFC 9483 §4.1.1)",
				dmsID, corecmp.PKIFailureInfoBadRequest)
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
		if len(s.HashAlgOID) > 0 && header.PVNO != corecmp.PVNOCMP2021 {
			lFunc.Warnf("certConf: entry %d carries hashAlg %v but pvno=%d (RFC 9810 §5.3.18 requires cmp2021)",
				i, s.HashAlgOID, header.PVNO)
			r.rejectWithError(ctx, &header, corecmp.PKIStatus(2),
				"CertStatus.hashAlg requires cmp2021(3) (RFC 9810 §5.3.18)",
				dmsID, corecmp.PKIFailureInfoBadDataFormat)
			return
		}
		expected, hashErr := corecmp.ComputeCertHash(tx.Certificate.Raw, s.HashAlgOID)
		if hashErr != nil {
			lFunc.Errorf("certConf: entry %d unsupported hashAlg %v: %v", i, s.HashAlgOID, hashErr)
			r.rejectWithError(ctx, &header, corecmp.PKIStatus(2),
				fmt.Sprintf("unsupported certConf hashAlg OID %v", s.HashAlgOID), dmsID, corecmp.PKIFailureInfoBadAlg)
			return
		}
		if !hashesEqual(s.CertHash, expected) {
			lFunc.Errorf("certConf: entry %d certHash mismatch", i)
			// The EE's claimed certHash does not match the issued cert — they
			// are confirming a different certificate. badCertId (4) says
			// "no certificate could be found matching the provided criteria"
			// which fits more precisely than the generic badRequest.
			r.rejectWithError(ctx, &header, corecmp.PKIStatus(2), "certHash mismatch", dmsID, corecmp.PKIFailureInfoBadCertID)
			return
		}
		lFunc.Debugf("certConf: entry %d certReqId=%d hash OK", i, s.CertReqID)
	}

	lFunc.Infof("certConf verified, transitioning to CONFIRMED")
	_, prior, updated, confirmErr := r.store.Confirm(ctx.Request.Context(), txHex)
	if confirmErr != nil {
		lFunc.Errorf("certConf: confirm storage error: %v", confirmErr)
		r.rejectWithError(ctx, &header, corecmp.PKIStatus(2), "internal error: storage", dmsID, corecmp.PKIFailureInfoSystemFailure)
		return
	}
	if !updated {
		switch prior {
		case models.CMPTransactionStateRevoked:
			// Race we MUST surface (audit S1): between this handler's Select
			// and Confirm, the confirmation monitor revoked the cert at the
			// CA. The EE believes enrollment succeeded but the cert is gone.
			// Reject so the EE re-enrolls instead of acting on a dead cert.
			lFunc.Warnf("certConf: tx %s already REVOKED — race with confirmation monitor", txHex)
			r.rejectWithError(ctx, &header, corecmp.PKIStatus(2),
				"certificate was revoked before confirmation was processed", dmsID, corecmp.PKIFailureInfoBadRequest)
			return
		case models.CMPTransactionStateConfirmed:
			// The transaction is already CONFIRMED. Two distinct cases:
			//
			//   - Confirmed implicitly at issuance (RFC 4210 §5.2.8): marked by
			//     ConfirmedAt == CreatedAt exactly (issueAndStore stamps both
			//     from one clock read). An EE MAY still send certConf even when
			//     implicitConfirm was granted; that first confirmation is
			//     answered with a normal pkiConf.
			//   - Confirmed by an earlier certConf (Confirm() stamped a later
			//     ConfirmedAt): this one is a duplicate. RFC 9483 §4.1.1 /
			//     RFC 4210 §5.3.18 answer it with an error carrying failInfo
			//     certConfirmed (11) — the EE still learns the certificate is
			//     confirmed, so a client retrying a lost pkiConf isn't left blind.
			if tx.ConfirmedAt.Equal(tx.CreatedAt) {
				lFunc.Infof("certConf: tx %s was implicitly confirmed at issuance — acknowledging with pkiConf", txHex)
				break
			}
			lFunc.Infof("certConf: tx %s already CONFIRMED — replying error(certConfirmed)", txHex)
			r.rejectWithError(ctx, &header, corecmp.PKIStatus(2),
				"certificate confirmation was already received for this transaction",
				dmsID, corecmp.PKIFailureInfoCertConfirmed)
			return
		default:
			lFunc.Errorf("certConf: tx %s in unexpected prior state %q for confirmation", txHex, prior)
			r.rejectWithError(ctx, &header, corecmp.PKIStatus(2),
				fmt.Sprintf("transaction in unexpected state %q for confirmation", prior), dmsID, corecmp.PKIFailureInfoBadRequest)
			return
		}
	}

	pkiConfDER, err := corecmp.MarshalPKIConfBody()
	if err != nil {
		lFunc.Errorf("certConf: build pkiConf: %v", err)
		r.rejectWithError(ctx, &header, corecmp.PKIStatus(2), "cannot build pkiConf", dmsID, corecmp.PKIFailureInfoSystemFailure)
		return
	}
	// Commit the deferred key-update now that the EE has confirmed (RFC 9483
	// §4.1.3): bind the new cert as the device's active identity and supersede
	// the previous one. Only on a real transition (not an idempotent replay)
	// and only for re-enrollments — ir/cr bind their identity at issuance.
	if updated && tx.IsReenrollment {
		r.commitReenrollment(ctx.Request.Context(), lFunc, dmsID, tx.CertSerialNumber)
	}
	responseDER := r.sendRawBody(ctx, lFunc, header, corecmp.BodyTagPKIConf, pkiConfDER, dmsID)
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
func (r *cmpHttpRoutes) handlePoll(ctx *gin.Context, lFunc *logrus.Entry, header corecmp.RequestPKIHeader, body asn1.RawValue, dmsID string, enrollOpts *models.EnrollmentOptionsLWCRFC9483) {
	certReqID, err := corecmp.DecodePollReqContent(body.Bytes)
	if err != nil {
		lFunc.Errorf("pollReq: decode: %v", err)
		r.rejectWithError(ctx, &header, corecmp.PKIStatus(2), "malformed pollReq", dmsID, corecmp.PKIFailureInfoBadDataFormat)
		return
	}
	lFunc = lFunc.WithField("certReqId", certReqID)

	txHex := hex.EncodeToString(header.TransactionID)
	tx, ok, err := r.store.Select(ctx.Request.Context(), txHex)
	if err != nil {
		lFunc.Errorf("pollReq: lookup transaction: %v", err)
		r.rejectWithError(ctx, &header, corecmp.PKIStatus(2), "internal error", dmsID, corecmp.PKIFailureInfoSystemFailure)
		return
	}
	if !ok {
		lFunc.Warnf("pollReq: unknown transactionID %s", txHex)
		r.rejectWithError(ctx, &header, corecmp.PKIStatus(2), "unknown transactionID", dmsID, corecmp.PKIFailureInfoBadRequest)
		return
	}

	switch tx.State {
	case models.CMPTransactionStatePending:
		// Dead path in sync-only mode (no PENDING rows are created), but kept
		// for forward-compatibility if async issuance is reintroduced.
		checkAfter := defaultPollIntervalSeconds
		repDER, err := corecmp.MarshalPollRepBody(certReqID, checkAfter)
		if err != nil {
			lFunc.Errorf("pollReq: build pollRep: %v", err)
			r.rejectWithError(ctx, &header, corecmp.PKIStatus(2), "cannot build pollRep", dmsID, corecmp.PKIFailureInfoSystemFailure)
			return
		}
		lFunc.Infof("pollReq: tx %s still PENDING, replying pollRep(checkAfter=%ds)", txHex, checkAfter)
		r.sendRawBody(ctx, lFunc, header, corecmp.BodyTagPollRep, repDER, dmsID)

	case models.CMPTransactionStateIssued:
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

		// Decide whether this delivery is an IP (ir-derived) or CP (cr/p10cr/kur).
		// PENDING rows store IsReenrollment; for sync-stored ISSUED rows
		// (lost-response recovery) the original body tag is lost, so we default
		// to CP — both IP and CP carry the same CertRepMessage structure and
		// any modern CMP client accepts either as the cert-bearing response.
		// A p10cr row is never an IP: its response is always cp (RFC 9483 §4.1.4).
		respTag := pollRespTagFor(tx)
		var txCertRaw []byte
		if tx.Certificate != nil {
			txCertRaw = tx.Certificate.Raw
		}
		certRepDER, err := corecmp.MarshalCertRepBody(respTag, certReqID, txCertRaw)
		if err != nil {
			lFunc.Errorf("pollReq: build cert rep body: %v", err)
			r.rejectWithError(ctx, &header, corecmp.PKIStatus(2), "cannot build response", dmsID, corecmp.PKIFailureInfoSystemFailure)
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
				r.rejectWithError(ctx, &header, corecmp.PKIStatus(2), "internal error: storage", dmsID, corecmp.PKIFailureInfoSystemFailure)
				return
			}
			if !updated {
				if prior == models.CMPTransactionStateRevoked {
					lFunc.Warnf("pollReq: tx %s already REVOKED — race with confirmation monitor", txHex)
					r.rejectWithError(ctx, &header, corecmp.PKIStatus(2),
						"certificate was revoked before implicit confirmation could be processed", dmsID, corecmp.PKIFailureInfoBadRequest)
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

	case models.CMPTransactionStateConfirmed:
		// Lost-response recovery for implicit-confirm enrollments: the IR
		// already drove the row to CONFIRMED at IP delivery (RFC 4210 §5.2.8),
		// but the EE never received the IP. The pollReq retries; we re-deliver
		// the cert and leave the row in CONFIRMED. No certConf will follow and
		// no nonce echo is needed.
		respTag := pollRespTagFor(tx)
		var txCertRaw []byte
		if tx.Certificate != nil {
			txCertRaw = tx.Certificate.Raw
		}
		certRepDER, err := corecmp.MarshalCertRepBody(respTag, certReqID, txCertRaw)
		if err != nil {
			lFunc.Errorf("pollReq: build cert rep body for CONFIRMED row: %v", err)
			r.rejectWithError(ctx, &header, corecmp.PKIStatus(2), "cannot build response", dmsID, corecmp.PKIFailureInfoSystemFailure)
			return
		}
		// Echo the implicit-confirm OID so the EE sees the same negotiation it
		// originally received on the lost IP — keeps the protocol view consistent.
		header.ResponseImplicitConfirm = true
		lFunc.Infof("pollReq: tx %s CONFIRMED (implicit), re-delivering cert via %s", txHex, cmpTagToString(respTag))
		r.sendRawBody(ctx, lFunc, header, respTag, certRepDER, dmsID)

	case models.CMPTransactionStateIssueFailed:
		reason := tx.ErrorMessage
		if reason == "" {
			reason = "issuance failed"
		}
		lFunc.Warnf("pollReq: tx %s ISSUE_FAILED, returning CMP error: %s", txHex, reason)
		// CA-layer issuance failure surfaced via pollReq — same rationale as
		// the inline enroll-error path above (systemFailure until structured
		// service-layer error categories exist).
		r.rejectWithError(ctx, &header, corecmp.PKIStatus(corecmp.PKIStatusRejection), reason, dmsID, corecmp.PKIFailureInfoSystemFailure)

	case models.CMPTransactionStateRevoked:
		// The confirmation monitor rolled the row back (the certConf/delivery
		// window elapsed before the EE picked the cert up or confirmed it), or
		// the certificate was revoked out-of-band via the API. Tell the EE
		// precisely what happened — falling through to the generic
		// unknown-state systemFailure reads as a server bug and gives the
		// operator nothing to act on.
		lFunc.Warnf("pollReq: tx %s REVOKED, returning CMP error", txHex)
		r.rejectWithError(ctx, &header, corecmp.PKIStatus(corecmp.PKIStatusRejection),
			"certificate for this transaction has been revoked (confirmation window elapsed or revoked via API); start a new enrollment", dmsID, corecmp.PKIFailureInfoCertRevoked)

	default:
		lFunc.Errorf("pollReq: tx %s has unknown state %q", txHex, tx.State)
		r.rejectWithError(ctx, &header, corecmp.PKIStatus(2), "internal error: unknown transaction state", dmsID, corecmp.PKIFailureInfoSystemFailure)
	}
}

// pollRespTagFor picks the cert-bearing response body tag for a pollReq
// delivery from the persisted transaction: re-enrollments (kur) and p10cr
// transactions get cp; everything else (ir/cr sync rows, where the historical
// default is ip) gets ip. p10cr must never yield an ip — its response body is
// cp in every phase of the exchange (RFC 9483 §4.1.4).
func pollRespTagFor(tx models.CMPTransaction) int {
	if tx.RequestType == cmpTagToString(corecmp.BodyTagCCR) {
		return corecmp.BodyTagCCP
	}
	if tx.IsReenrollment || tx.RequestType == cmpTagToString(corecmp.BodyTagP10CR) {
		return corecmp.BodyTagCP
	}
	return corecmp.BodyTagIP
}

// isImplicitConfirm reports whether the current request should be treated as
// implicitly confirmed — i.e. the DMS is configured to accept implicit
// confirmation AND the EE included the id-it-implicitConfirm OID in the
// request's generalInfo header.
func (r *cmpHttpRoutes) isImplicitConfirm(ctx context.Context, header corecmp.RequestPKIHeader, dmsID string) bool {
	if !corecmp.HasImplicitConfirmOID(header.GeneralInfo) {
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
func (r *cmpHttpRoutes) rejectCertRequest(ctx *gin.Context, lFunc *logrus.Entry, header corecmp.RequestPKIHeader, respTag int, dmsID string, rej *corecmp.CertRequestRejection) {
	body, err := corecmp.MarshalCertRepRejectionBody(rej.CertReqID, rej.Reason, rej.FailInfoBit)
	if err != nil {
		lFunc.Errorf("build cert rep rejection body: %v", err)
		r.rejectWithError(ctx, &header, corecmp.PKIStatus(corecmp.PKIStatusRejection), rej.Reason, dmsID, rej.FailInfoBit)
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
func (r *cmpHttpRoutes) rejectRevocation(ctx *gin.Context, lFunc *logrus.Entry, header corecmp.RequestPKIHeader, reason string, failInfoBit int, dmsID string) {
	body, err := corecmp.MarshalRevRepBody(corecmp.PKIStatus(corecmp.PKIStatusRejection), reason, failInfoBit)
	if err != nil {
		lFunc.Errorf("build rp rejection body: %v", err)
		r.rejectWithError(ctx, &header, corecmp.PKIStatus(corecmp.PKIStatusRejection), reason, dmsID, failInfoBit)
		return
	}
	header.ResponseImplicitConfirm = false
	r.sendRawBody(ctx, lFunc, header, corecmp.BodyTagRP, body, dmsID)
}

// rejectRequest routes a pre-dispatch rejection (protection / sender / senderKID
// failures) to the body type appropriate for the inbound request. For rr the
// response MUST be an rp body (RFC 9483 §4.2); all other request types fall
// back to the generic error body.
func (r *cmpHttpRoutes) rejectRequest(ctx *gin.Context, lFunc *logrus.Entry, header corecmp.RequestPKIHeader, bodyTag int, reason string, failInfoBit int, dmsID string) {
	if bodyTag == corecmp.BodyTagRR {
		r.rejectRevocation(ctx, lFunc, header, reason, failInfoBit, dmsID)
		return
	}
	r.rejectWithError(ctx, &header, corecmp.PKIStatus(corecmp.PKIStatusRejection), reason, dmsID, failInfoBit)
}

func (r *cmpHttpRoutes) rejectWithError(ctx *gin.Context, header *corecmp.RequestPKIHeader, status corecmp.PKIStatus, reason string, aps string, failInfoBits ...int) {
	errBody, err := corecmp.MarshalErrorBody(status, reason, failInfoBits...)
	if err != nil {
		ctx.Status(http.StatusInternalServerError)
		return
	}
	var h corecmp.RequestPKIHeader
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
	r.sendRawBody(ctx, r.logger, h, corecmp.BodyTagError, errBody, aps)
}

// writeCMPResponse logs and writes a fully-assembled response PKIMessage DER
// to the Gin context. Shared by sendRawBody and sendRawBodyWithSigner.
func writeCMPResponse(ctx *gin.Context, lFunc *logrus.Entry, bodyTag int, respDER []byte) {
	lFunc.Infof("CMP response (tag=%d) PEM:\n%s", bodyTag,
		pem.EncodeToMemory(&pem.Block{Type: "CMP MESSAGE", Bytes: respDER}))
	ctx.Data(http.StatusOK, "application/pkixcmp", respDER)
}

// sendRawBody assembles a PKIMessage from a pre-encoded body CHOICE DER and
// writes the result as application/pkixcmp to the Gin context.
func (r *cmpHttpRoutes) sendRawBody(ctx *gin.Context, lFunc *logrus.Entry, reqHeader corecmp.RequestPKIHeader, bodyTag int, bodyDER []byte, aps string) []byte {
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
				writeCMPResponse(ctx, lFunc, bodyTag, respDER)
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
	writeCMPResponse(ctx, lFunc, bodyTag, respDER)
	return respDER
}

// sendRawBodyWithSigner is sendRawBody for the rare case where the response
// must be protection-signed by a specific key/cert chain rather than the
// DMS's normal CMP protection credentials — currently only the ECDH
// originator minted for a keyAgreement encrCert/challengeResp recipient (see
// mintECDHOriginator in cmp_popo_indirect.go), whose certificate must be the
// one the recipient finds in extraCerts to complete the key agreement.
func (r *cmpHttpRoutes) sendRawBodyWithSigner(ctx *gin.Context, lFunc *logrus.Entry, reqHeader corecmp.RequestPKIHeader, bodyTag int, bodyDER []byte, certChain []*x509.Certificate, signer crypto.Signer) []byte {
	respDER, err := marshalProtectedResponseWithSigner(reqHeader, bodyTag, bodyDER, certChain, certChain[0], signer)
	if err != nil {
		lFunc.Errorf("marshal protected response PKIMessage: %v", err)
		ctx.Status(http.StatusInternalServerError)
		return nil
	}
	writeCMPResponse(ctx, lFunc, bodyTag, respDER)
	return respDER
}

// sendKARIProtectedResponse sends a KARI (ECDH key-agreement) response — an
// encrCert cp/ip or a challengeResp popdecc — whose EnvelopedData/Challenge was
// built against an ephemeral ECDH originator. The OUTER PKIMessage protection
// is signed by the DMS's normal CMP protection credentials when configured, so
// clients that pin the responder identity (openssl cmp -srvcert / -expect_sender)
// still see the expected sender — while the originator certificate is kept at
// extraCerts[0] (where the RFC 9483 §4.1.6 compliance validator expects it, and
// where any client locates its ECDH partner by SKI). Signing party and CMS
// originator are independent: the recipient derives the CEK from the originator
// in extraCerts regardless of who signed the message.
//
// Only when the DMS has no protection credentials configured does it fall back
// to signing with the originator itself (the pre-fix behaviour). Previously ALL
// KARI responses signed with the originator, which made a -srvcert-pinning
// client reject them with "unexpected sender: /CN=Lamassu CMP ECDH Originator".
func (r *cmpHttpRoutes) sendKARIProtectedResponse(ctx *gin.Context, lFunc *logrus.Entry, reqHeader corecmp.RequestPKIHeader, bodyTag int, bodyDER []byte, aps string, originator *ecdhOriginator) []byte {
	origChain := append([]*x509.Certificate{originator.cert}, originator.chain...)
	if aps != "" {
		if provider, ok := r.svc.(services.LightweightCMPProtectionProvider); ok {
			certChain, signer, credErr := provider.LWCProtectionCredentials(ctx.Request.Context(), aps)
			if credErr != nil {
				lFunc.Errorf("load cmp protection credentials: %v", credErr)
				ctx.Status(http.StatusInternalServerError)
				return nil
			}
			if len(certChain) > 0 && signer != nil {
				// originator FIRST (extraCerts[0]); DMS chain appended so
				// -trusted-only clients can still build the protection path.
				extra := append(append([]*x509.Certificate{}, origChain...), certChain...)
				respDER, err := marshalProtectedResponseWithSigner(reqHeader, bodyTag, bodyDER, extra, certChain[0], signer)
				if err != nil {
					lFunc.Errorf("marshal protected response PKIMessage: %v", err)
					ctx.Status(http.StatusInternalServerError)
					return nil
				}
				writeCMPResponse(ctx, lFunc, bodyTag, respDER)
				return respDER
			}
		}
	}
	return r.sendRawBodyWithSigner(ctx, lFunc, reqHeader, bodyTag, bodyDER, origChain, originator.key)
}

// buildResponseHeader constructs a response PKIHeader mirroring the
// transactionID from the request and echoing senderNonce as recipNonce.
//
// Per RFC 9810 §7 line 3754 the response pvno MUST equal the request pvno when
// the server supports it (we support both cmp2000(2) and cmp2021(3)). Per RFC
// 9483 §3.1 line 725 messageTime SHOULD be present on responses for time-sync
// purposes — we always emit it.
func buildResponseHeader(req corecmp.RequestPKIHeader) (corecmp.Header, error) {
	sender := corecmp.DefaultSenderGeneralName()
	if len(req.Recipient.FullBytes) > 0 {
		sender = asn1.RawValue{FullBytes: req.Recipient.FullBytes}
	}

	recipient := corecmp.DefaultRecipientGeneralName()
	if len(req.Sender.FullBytes) > 0 {
		recipient = asn1.RawValue{FullBytes: req.Sender.FullBytes}
	}

	respSenderNonce := req.ResponseSenderNonce
	if len(respSenderNonce) == 0 {
		var err error
		respSenderNonce, err = corecmp.NewNonce()
		if err != nil {
			return corecmp.Header{}, err
		}
	}

	// RFC 9810 §7: echo the received pvno when supported. Fall back to cmp2000
	// for malformed/legacy requests that never set a valid version.
	respPVNO := corecmp.PVNOCMP2000
	if req.PVNO == corecmp.PVNOCMP2021 {
		respPVNO = corecmp.PVNOCMP2021
	}

	var generalInfo []corecmp.InfoTypeAndValue
	if req.ResponseImplicitConfirm {
		generalInfo = []corecmp.InfoTypeAndValue{
			{InfoType: corecmp.OIDImplicitConfirm(), InfoValue: asn1.NullRawValue},
		}
	}

	return corecmp.Header{
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
	case corecmp.BodyTagIR, corecmp.BodyTagCR, corecmp.BodyTagKUR:
		req, err := corecmp.DecodeFirstCertReq(body.Bytes)
		if err != nil {
			return ""
		}
		return extractCNFromSubjectDER(req.SubjectDER)
	case corecmp.BodyTagP10CR:
		csrDER, err := p10crCSRDER(body.Bytes)
		if err != nil {
			return ""
		}
		csr, err := x509.ParseCertificateRequest(csrDER)
		if err != nil {
			return ""
		}
		return csr.Subject.CommonName
	case corecmp.BodyTagPollReq, corecmp.BodyTagCertConf, corecmp.BodyTagRR:
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
func validateCertTemplatePolicy(req *corecmp.CertRequest) *corecmp.CertRequestRejection {
	var bc *basicConstraints
	var keyCertSign bool

	for _, ext := range req.Extensions {
		switch {
		case ext.Id.Equal(oidExtBasicConstraints):
			var parsed basicConstraints
			if _, err := asn1.Unmarshal(ext.Value, &parsed); err != nil {
				return &corecmp.CertRequestRejection{
					CertReqID:   req.CertReqID,
					Reason:      "malformed BasicConstraints extension in CertTemplate",
					FailInfoBit: corecmp.PKIFailureInfoBadCertTemplate,
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
		return &corecmp.CertRequestRejection{
			CertReqID:   req.CertReqID,
			Reason:      "issuing CA certificates is not permitted over CMP (RFC 9483 §5): BasicConstraints cA=TRUE requested",
			FailInfoBit: corecmp.PKIFailureInfoNotAuthorized,
		}
	}
	// keyCertSign without cA=TRUE is a self-inconsistent template: keyCertSign is
	// only valid on a CA certificate (RFC 5280 §4.2.1.3) → badCertTemplate.
	if keyCertSign {
		return &corecmp.CertRequestRejection{
			CertReqID:   req.CertReqID,
			Reason:      "keyCertSign KeyUsage requested without BasicConstraints cA=TRUE (RFC 5280 §4.2.1.3)",
			FailInfoBit: corecmp.PKIFailureInfoBadCertTemplate,
		}
	}
	// pathLenConstraint is only meaningful when cA=TRUE; its presence on an
	// end-entity template is a malformed CertTemplate (RFC 5280 §4.2.1.9).
	if bc != nil && bc.PathLen > 0 {
		return &corecmp.CertRequestRejection{
			CertReqID:   req.CertReqID,
			Reason:      "pathLenConstraint present with cA=FALSE (RFC 5280 §4.2.1.9)",
			FailInfoBit: corecmp.PKIFailureInfoBadCertTemplate,
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
	if !spki.Algorithm.Algorithm.Equal(corecmp.OIDRSAEncryption()) {
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

// rejectWeakOrOversizedRSAKey enforces the RSA modulus policy on the
// SubjectPublicKeyInfo in spkiDER (min/max bits). It returns nil when the key
// is not RSA or its size is within policy, or a populated *certRequestRejection
// (badCertTemplate) — emitting the matching Warnf — when the modulus is too
// short or too large. Shared by the CRMF enrollment path (logPrefix
// "ir/cr"/"kur", req.CertReqID) and the p10cr path (logPrefix "p10cr",
// p10crCertReqID); the caller delivers the rejection with rejectCertRequest.
func rejectWeakOrOversizedRSAKey(spkiDER []byte, logPrefix string, certReqID int, lFunc *logrus.Entry) *corecmp.CertRequestRejection {
	if bits := rsaKeyBits(spkiDER); bits > 0 && bits < minRSAKeyBits {
		lFunc.Warnf("%s: RSA public key too short: %d-bit (minimum %d)", logPrefix, bits, minRSAKeyBits)
		return &corecmp.CertRequestRejection{
			CertReqID:   certReqID,
			Reason:      fmt.Sprintf("RSA public key too short: %d-bit key is below the %d-bit minimum (NIST SP 800-57)", bits, minRSAKeyBits),
			FailInfoBit: corecmp.PKIFailureInfoBadCertTemplate,
		}
	}
	if bits := rsaKeyBits(spkiDER); bits > maxRSAKeyBits {
		lFunc.Warnf("%s: RSA public key too large: %d-bit (maximum %d)", logPrefix, bits, maxRSAKeyBits)
		return &corecmp.CertRequestRejection{
			CertReqID:   certReqID,
			Reason:      fmt.Sprintf("RSA public key too large: %d-bit key exceeds the %d-bit maximum", bits, maxRSAKeyBits),
			FailInfoBit: corecmp.PKIFailureInfoBadCertTemplate,
		}
	}
	return nil
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

// extensionsMatch reports whether requested is exactly the same SET of
// extensions as actual — same count, and every (OID, Critical, Value) triple
// in requested has an identical counterpart in actual. Used by handleRevoke
// to enforce RFC 9483 §4.2's rule that an rr's optional CertTemplate
// extensions[9], when present, MUST match the certificate being revoked: a
// caller who bothers to assert the extensions at all must get them exactly
// right, not just a subset.
func extensionsMatch(requested, actual []pkix.Extension) bool {
	if len(requested) != len(actual) {
		return false
	}
	key := func(e pkix.Extension) string {
		return e.Id.String() + "|" + strconv.FormatBool(e.Critical) + "|" + hex.EncodeToString(e.Value)
	}
	actualSet := make(map[string]int, len(actual))
	for _, e := range actual {
		actualSet[key(e)]++
	}
	for _, e := range requested {
		k := key(e)
		if actualSet[k] == 0 {
			return false
		}
		actualSet[k]--
	}
	return true
}

// validateOldCertID checks that a KUR's id-regCtrl-oldCertID references the
// certificate actually being updated — the protection (signer) certificate.
// Issuer (DER-compared against RawIssuer) and serialNumber must both match;
// otherwise it returns a badCertId cert-request rejection. Returns nil when no
// oldCertID control was supplied (it is optional, RFC 9483 §4.1.3).
func validateOldCertID(req *corecmp.CertRequest, signer *x509.Certificate) *corecmp.CertRequestRejection {
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
	return &corecmp.CertRequestRejection{
		CertReqID:   req.CertReqID,
		Reason:      "controls oldCertId does not match the certificate being updated (RFC 9483 §4.1.3)",
		FailInfoBit: corecmp.PKIFailureInfoBadCertID,
	}
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

func cmpTagToString(t int) string {
	switch t {
	case corecmp.BodyTagIR:
		return "ir"
	case corecmp.BodyTagCR:
		return "cr"
	case corecmp.BodyTagP10CR:
		return "p10cr"
	case corecmp.BodyTagPopDecc:
		return "popdecc"
	case corecmp.BodyTagPopDecr:
		return "popdecr"
	case corecmp.BodyTagKUR:
		return "kur"
	case corecmp.BodyTagCP:
		return "cp"
	case corecmp.BodyTagIP:
		return "ip"
	case corecmp.BodyTagKUP:
		return "kup"
	case corecmp.BodyTagRR:
		return "rr"
	case corecmp.BodyTagRP:
		return "rp"
	case corecmp.BodyTagCertConf:
		return "certConf"
	case corecmp.BodyTagPKIConf:
		return "pkiConf"
	case corecmp.BodyTagError:
		return "error"
	case corecmp.BodyTagPollReq:
		return "pollReq"
	case corecmp.BodyTagPollRep:
		return "pollRep"
	case corecmp.BodyTagGenMsg:
		return "genm"
	case corecmp.BodyTagGenRep:
		return "genp"
	case corecmp.BodyTagCCR:
		return "ccr"
	case corecmp.BodyTagCCP:
		return "ccp"
	default:
		return fmt.Sprintf("unknown(%d)", t)
	}
}
