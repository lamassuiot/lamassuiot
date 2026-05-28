package controllers

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
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/errs"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
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

	// Inner-POPO verification is meaningful for ir/cr (RFC 9483 §4.1 /
	// RFC 4211 §4.1 clause 3). For kur, the protection certificate proves
	// possession of the key being updated, so a separate inner-POPO check
	// would be redundant (and is omitted by RFC 9483 §4.1.3).
	if variant.verifyInnerPOPO {
		if err := verifyPOPO(req.CertReqDER, req.POPORaw, req.PublicKeyDER, enrollOpts.EnforcePOPO); err != nil {
			lFunc.Warnf("%s: POPO verification failed: %v", variant.logPrefix, err)
			r.rejectCertRequest(ctx, lFunc, header, respTag, dmsID, &certRequestRejection{
				CertReqID:   req.CertReqID,
				Reason:      fmt.Sprintf("proof of possession verification failed: %v", err),
				FailInfoBit: pkiFailureInfoBadPOP,
			})
			return
		}
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
	enroll   func(ctx context.Context, csr *x509.CertificateRequest) (*x509.Certificate, error)
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
	csr, err := buildSyntheticCSR(req.SubjectDER, req.PublicKeyDER)
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
		// CA-layer rejections cover a wide range of conditions (policy
		// violation, signing-key unavailability, revocation, etc.). Without
		// structured error categorisation from the service layer we map all
		// CA failures to systemFailure, which is the broadest "server-side
		// inability to complete the request" bit (RFC 9810 §5.1.3).
		r.rejectWithError(ctx, header, PKIStatus(2), err.Error(), dmsID, pkiFailureInfoSystemFailure)
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
		ConfirmedAt:       confirmedAt,
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

	certRepDER, err := marshalCertRepBody(params.respTag, req.CertReqID, cert.Raw)
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
