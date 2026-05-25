package controllers

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
	"encoding/base64"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
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

// NewCMPHttpRoutes creates and initialises the CMP HTTP handler, backed by
// a DB-persisted transaction store retrieved from the service via type assertion.
func NewCMPHttpRoutes(logger *logrus.Entry, svc services.LightweightCMPService) *cmpHttpRoutes {
	var repo storage.CMPTransactionRepo
	var reporter cmpwfx.CMPReporter
	if storer, ok := svc.(cmpTransactionStorer); ok {
		repo = storer.GetCMPTransactionRepo()
	} else {
		logger.Warn("CMP: service does not implement cmpTransactionStorer; transaction store will be nil")
	}
	if provider, ok := svc.(cmpWFXReporterProvider); ok {
		reporter = provider.GetCMPWFXReporter()
	}
	return &cmpHttpRoutes{svc: svc, logger: logger, store: repo, wfx: reporter}
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
		r.rejectWithError(ctx, nil, PKIStatus(2), "missing DMS id", "")
		return
	}

	// Read DER body
	bodyBytes, err := io.ReadAll(ctx.Request.Body)
	if err != nil || len(bodyBytes) == 0 {
		r.rejectWithError(ctx, nil, PKIStatus(2), "cannot read request body", dmsID)
		return
	}

	// Decode PKIMessage fully (including Protection and ExtraCerts for verification).
	var fullMsg rawPKIMessageFull
	if _, err := asn1.Unmarshal(bodyBytes, &fullMsg); err != nil {
		lFunc.Warnf("failed to unmarshal PKIMessage: %v", err)
		r.rejectWithError(ctx, nil, PKIStatus(2), "malformed PKIMessage", dmsID)
		return
	}

	header := fullMsg.Header
	body := fullMsg.Body

	reqHeader, err := decodeRequestHeader(header.FullBytes)
	if err != nil {
		lFunc.Warnf("failed to decode PKIHeader: %v", err)
		r.rejectWithError(ctx, nil, PKIStatus(2), "malformed PKIHeader", dmsID, pkiFailureInfoBadRequest)
		return
	}

	// RFC 9810 §7 / RFC 9483 §3.5: pvno MUST be cmp2000(2) or cmp2021(3); any
	// other value triggers an error response with the unsupportedVersion bit.
	if reqHeader.PVNO != pvnoCMP2000 && reqHeader.PVNO != pvnoCMP2021 {
		lFunc.Warnf("unsupported pvno=%d", reqHeader.PVNO)
		r.rejectWithError(ctx, &reqHeader, PKIStatus(2),
			fmt.Sprintf("unsupported protocol version %d (must be cmp2000(2) or cmp2021(3))", reqHeader.PVNO),
			dmsID, pkiFailureInfoUnsupportedVersion)
		return
	}

	// RFC 9483 §3.5 line 949: transactionID MUST be present.
	// RFC 9483 §3.1 line 747: first message MUST carry 128 bits of random data.
	if len(reqHeader.TransactionID) == 0 {
		lFunc.Warnf("transactionID missing from PKIHeader")
		r.rejectWithError(ctx, &reqHeader, PKIStatus(2),
			"transactionID is required (RFC 9483 §3.5)",
			dmsID, pkiFailureInfoBadRequest)
		return
	}
	if len(reqHeader.TransactionID) < 16 {
		lFunc.Warnf("transactionID too short (%d bytes, need >=16)", len(reqHeader.TransactionID))
		r.rejectWithError(ctx, &reqHeader, PKIStatus(2),
			"transactionID must contain at least 128 bits of data (RFC 9483 §3.1)",
			dmsID, pkiFailureInfoBadRequest)
		return
	}

	// RFC 9483 §3.5 line 959: senderNonce MUST be present and MUST contain at
	// least 128 bits of data. failInfo: badSenderNonce.
	if len(reqHeader.SenderNonce) < 16 {
		lFunc.Warnf("senderNonce missing or too short (%d bytes)", len(reqHeader.SenderNonce))
		r.rejectWithError(ctx, &reqHeader, PKIStatus(2),
			"senderNonce must be present and contain at least 128 bits (RFC 9483 §3.5)",
			dmsID, pkiFailureInfoBadSenderNonce)
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

	// Received and Parsed are only meaningful for enrollment-initiating
	// messages (IR/CR/KUR). Follow-up messages (certConf, pollReq, rr)
	// reference an already-created WFX job that is well past Parsed; emitting
	// these states on such jobs would attempt an invalid backward transition
	// (e.g. AwaitingCertConf → Received) which either gets rejected by WFX or
	// silently resets the job to the wrong state.
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
		r.reportCMPState(ctx.Request.Context(), lFunc, cmpwfx.CMPTransition{
			TransactionID:     txHex,
			DMSID:             dmsID,
			RequestType:       cmpTagToString(body.Tag),
			SubjectCommonName: deviceCN,
			State:             cmpwfx.CMPStateParsed,
			Metadata: map[string]any{
				"bodyTag": body.Tag,
			},
		})
	}

	// Fetch DMS enrollment options so we can make per-request decisions
	// (request-protection enforcement, implicit-confirm mode, etc.).
	enrollOpts, err := r.svc.LWCGetEnrollmentOptions(ctx.Request.Context(), dmsID)
	if err != nil {
		lFunc.Errorf("could not load enrollment options for DMS '%s': %v", dmsID, err)
		r.rejectWithError(ctx, &reqHeader, PKIStatus(2), "could not load DMS configuration", dmsID)
		return
	}

	// Verify signature-based protection on the incoming request. When the
	// request is protected, the parsed EE signer cert (extraCerts[0]) is
	// returned and stashed on the request context so downstream service
	// methods (LWCEnroll, LWCReenroll) can apply ValidationCAs, RFC 9483
	// §4.1.3 signer binding, and revocation checks — mirroring the EST
	// mTLS auth path. When the request is unprotected and protection is
	// not enforced, signerCert is nil and no further auth is applied.
	signerCert, err := verifyRequestProtection(fullMsg, reqHeader.ProtectionAlg, enrollOpts.EnforceRequestProtection)
	if err != nil {
		lFunc.Warnf("protection verification failed: %v", err)
		// Map error category to PKIFailureInfo per RFC 9810 §5.1.3 / RFC 9483
		// §3.6.4: algorithm-not-supported maps to badAlg, anything else
		// (signature mismatch, missing extraCerts, malformed protection field)
		// maps to badMessageCheck.
		failBit := pkiFailureInfoBadMessageCheck
		if isProtectionAlgError(err) {
			failBit = pkiFailureInfoBadAlg
		}
		r.rejectWithError(ctx, &reqHeader, PKIStatus(2),
			fmt.Sprintf("protection verification failed: %v", err), dmsID, failBit)
		return
	}
	if signerCert != nil {
		reqCtx := context.WithValue(ctx.Request.Context(), string(identityextractors.IdentityExtractorCMPSignerCertificate), signerCert)
		ctx.Request = ctx.Request.WithContext(reqCtx)
	}

	// Dispatch on body CHOICE tag
	switch body.Tag {
	case cmpBodyTagIR, cmpBodyTagCR:
		r.handleEnroll(ctx, lFunc, reqHeader, body, dmsID, enrollOpts)
	case cmpBodyTagKUR:
		r.handleReenroll(ctx, lFunc, reqHeader, body, dmsID, enrollOpts)
	case cmpBodyTagRR:
		r.handleRevoke(ctx, lFunc, reqHeader, body, dmsID)
	case cmpBodyTagCertConf:
		r.handleCertConf(ctx, lFunc, reqHeader, body, bodyBytes, dmsID)
	case cmpBodyTagPollReq:
		r.handlePoll(ctx, lFunc, reqHeader, body, dmsID, enrollOpts)
	default:
		lFunc.Warnf("unsupported CMP body tag %d", body.Tag)
		r.rejectWithError(ctx, &reqHeader, PKIStatus(2),
			fmt.Sprintf("unsupported body tag %d", body.Tag), dmsID)
	}
}

// handleEnroll processes an ir (0) or cr (2) body.
// Both ir and cr route to svc.LWCEnroll; the DMS enrollment policy governs access.
func (r *cmpHttpRoutes) handleEnroll(ctx *gin.Context, lFunc *logrus.Entry, header requestPKIHeader, body asn1.RawValue, dmsID string, enrollOpts *models.EnrollmentOptionsLWCRFC9483) {
	req, err := decodeFirstCertReq(body.Bytes)
	if err != nil {
		lFunc.Errorf("ir/cr: decode CertReqMessage: %v", err)
		r.rejectWithError(ctx, &header, PKIStatus(2), "malformed CertReqMessage", dmsID)
		return
	}

	// Verify inner POPO (RFC 9483 §4.1 / RFC 4211 §4.1 clause 3).
	// RFC 9810 §5.1.3 maps POP verification failures to PKIFailureInfo badPOP (9).
	if err := verifyPOPO(req.CertReqDER, req.POPORaw, req.PublicKeyDER, enrollOpts.EnforcePOPO); err != nil {
		lFunc.Warnf("ir/cr: POPO verification failed: %v", err)
		r.rejectWithError(ctx, &header, PKIStatus(2),
			fmt.Sprintf("proof of possession verification failed: %v", err),
			dmsID, pkiFailureInfoBadPOP)
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

	// Respond IP (tag 1) for ir, CP (tag 3) for cr
	respTag := cmpBodyTagCP
	if body.Tag == cmpBodyTagIR {
		respTag = cmpBodyTagIP
	}

	r.issueAndStore(ctx, lFunc, &header, req, dmsID, enrollOpts, issueParams{
		isReenrollment: false,
		requestTag:     body.Tag,
		respTag:        respTag,
		wfxJobID:       wfxJobID,
		enroll: func(ctx context.Context, csr *x509.CertificateRequest) (*x509.Certificate, error) {
			return r.svc.LWCEnroll(ctx, csr, dmsID)
		},
	})
}

// handleReenroll processes a kur (7) body and responds with kup (8).
//
// Per RFC 9483 §4.1.3, KUR message-level protection MUST use the certificate
// being updated — making the message protection itself a proof of possession
// of the old key. When EnforcePOPO is true we therefore require that the
// incoming KUR carries valid signature-based message protection; an unprotected
// KUR is rejected because there is no other way to prove possession.
func (r *cmpHttpRoutes) handleReenroll(ctx *gin.Context, lFunc *logrus.Entry, header requestPKIHeader, body asn1.RawValue, dmsID string, enrollOpts *models.EnrollmentOptionsLWCRFC9483) {
	if enrollOpts.EnforcePOPO {
		if len(header.ProtectionAlg.Algorithm) == 0 {
			lFunc.Warnf("kur: POPO enforcement requires message-level protection (RFC 9483 §4.1.3)")
			r.rejectWithError(ctx, &header, PKIStatus(2),
				"KUR requires message-level signature protection as proof of possession (RFC 9483 §4.1.3)",
				dmsID, pkiFailureInfoBadPOP)
			return
		}
	}

	req, err := decodeFirstCertReq(body.Bytes)
	if err != nil {
		lFunc.Errorf("kur: decode CertReqMessage: %v", err)
		r.rejectWithError(ctx, &header, PKIStatus(2), "malformed CertReqMessage", dmsID)
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
		isReenrollment: true,
		requestTag:     body.Tag,
		respTag:        cmpBodyTagKUP,
		wfxJobID:       wfxJobID,
		enroll: func(ctx context.Context, csr *x509.CertificateRequest) (*x509.Certificate, error) {
			return r.svc.LWCReenroll(ctx, csr, dmsID)
		},
	})
}

// issueParams holds the per-operation differences between ir/cr and kur flows.
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
		r.rejectWithError(ctx, header, PKIStatus(2), "cannot build CSR from CertTemplate", dmsID)
		return
	}
	lFunc = lFunc.WithField("cn", csr.Subject.CommonName)
	lFunc.Infof("enrollment request CN=%s (reenroll=%v)", csr.Subject.CommonName, params.isReenrollment)

	implicitConfirm := r.isImplicitConfirm(ctx.Request.Context(), *header, dmsID)
	header.ResponseImplicitConfirm = implicitConfirm

	// Early duplicate-transactionID check before calling the CA.
	txHex := hex.EncodeToString(header.TransactionID)
	if r.store != nil {
		if exists, err := r.store.Exists(ctx.Request.Context(), txHex); err != nil {
			lFunc.Errorf("check existing txID: %v", err)
			r.rejectWithError(ctx, header, PKIStatus(2), "internal error", dmsID)
			return
		} else if exists {
			lFunc.Warnf("duplicate transactionID %s (pre-enroll check)", txHex)
			r.rejectWithError(ctx, header, PKIStatus(2), "transactionID already in use", dmsID)
			return
		}
	}

	// Detach from the HTTP connection so issuance completes even if the EE
	// drops the TCP connection mid-request.
	issuanceCtx := context.WithoutCancel(ctx.Request.Context())
	cert, err := params.enroll(issuanceCtx, csr)
	if err != nil {
		lFunc.Errorf("enroll failed: %v", err)
		r.rejectWithError(ctx, header, PKIStatus(2), err.Error(), dmsID)
		return
	}
	certSerial := hex.EncodeToString(cert.SerialNumber.Bytes())

	// Persist ISSUED row for lost-response recovery via pollReq.
	if r.store != nil {
		senderNonce := newNonce()
		if !implicitConfirm {
			header.ResponseSenderNonce = senderNonce
		}
		if storeErr := r.store.Insert(issuanceCtx, storage.CMPTransaction{
			TransactionID:     txHex,
			DMSID:             dmsID,
			State:             storage.CMPTransactionStateIssued,
			CertSerialNumber:  certSerial,
			Certificate:       (*models.X509Certificate)(cert),
			IsReenrollment:    params.isReenrollment,
			RequestType:       cmpTagToString(params.requestTag),
			SubjectCommonName: csr.Subject.CommonName,
			WFXJobID:          params.wfxJobID,
			SentNonce:         hex.EncodeToString(senderNonce),
			ExpiresAt:         time.Now().Add(confirmationTimeoutOrDefault(enrollOpts.ConfirmationTimeout)),
			CreatedAt:         time.Now(),
		}); storeErr != nil {
			if errors.Is(storeErr, errs.ErrCMPTransactionAlreadyExists) {
				lFunc.Warnf("duplicate transactionID %s", txHex)
				r.rejectWithError(ctx, header, PKIStatus(2), "transactionID already in use", dmsID)
				return
			}
			lFunc.Errorf("store transaction: %v", storeErr)
			lFunc.Warnf("failed to persist ISSUED row (cert delivered inline): %v", storeErr)
		}
	}

	certRepDER, err := marshalCertRepBody(params.respTag, req.CertReqID, cert.Raw)
	if err != nil {
		lFunc.Errorf("build cert rep body: %v", err)
		r.rejectWithError(ctx, header, PKIStatus(2), "cannot build response", dmsID)
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

// handleRevoke processes an rr (11) body.
// It extracts the serial number from the CertTemplate and calls LWCRevokeCertificate.
func (r *cmpHttpRoutes) handleRevoke(ctx *gin.Context, lFunc *logrus.Entry, header requestPKIHeader, body asn1.RawValue, dmsID string) {
	serialBytes, reason, err := decodeRevReqContent(body.Bytes)
	if err != nil {
		lFunc.Errorf("rr: decode RevReqContent: %v", err)
		r.rejectWithError(ctx, &header, PKIStatus(2), "malformed RevReqContent", dmsID)
		return
	}

	serialHex := hex.EncodeToString(serialBytes)
	lFunc = lFunc.WithField("serial", serialHex)
	lFunc.Infof("revocation request serial=%s reason=%d", serialHex, reason)

	if err := r.svc.LWCRevokeCertificate(ctx.Request.Context(), services.RevokeCertificateInput{
		APS:          dmsID,
		SerialNumber: serialHex,
		Reason:       models.RevocationReason(reason),
	}); err != nil {
		lFunc.Errorf("rr: revoke failed: %v", err)
		r.rejectWithError(ctx, &header, PKIStatus(2), err.Error(), dmsID)
		return
	}

	// Transition the CMP transaction to REVOKED for audit visibility.
	if r.store != nil {
		if markErr := r.store.MarkRevokedByCertSerial(ctx.Request.Context(), serialHex); markErr != nil {
			lFunc.Warnf("rr: failed to mark transaction as revoked: %v", markErr)
		}
	}

	rpDER, err := marshalRevRepBody(PKIStatus(0))
	if err != nil {
		lFunc.Errorf("rr: build rp body: %v", err)
		r.rejectWithError(ctx, &header, PKIStatus(2), "cannot build rp response", dmsID)
		return
	}
	r.sendRawBody(ctx, lFunc, header, cmpBodyTagRP, rpDER, dmsID)
}

// handleCertConf processes a certConf (24) body.
// It verifies the SHA-256 certHash and responds with pkiConf (19).
func (r *cmpHttpRoutes) handleCertConf(ctx *gin.Context, lFunc *logrus.Entry, header requestPKIHeader, body asn1.RawValue, requestDER []byte, dmsID string) {
	seqDER, err := rewrapBodyAsSequence(body.Bytes)
	if err != nil {
		r.rejectWithError(ctx, &header, PKIStatus(2), "cannot decode certConf body", dmsID)
		return
	}
	statuses, err := decodeCertConfStatuses(seqDER)
	if err != nil {
		lFunc.Errorf("certConf: decode: %v", err)
		r.rejectWithError(ctx, &header, PKIStatus(2), "malformed certConf", dmsID)
		return
	}

	if r.store == nil {
		lFunc.Errorf("certConf: transaction store not available")
		r.rejectWithError(ctx, &header, PKIStatus(2), "internal error: transaction store unavailable", dmsID)
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
			r.rejectWithError(ctx, &header, PKIStatus(2),
				"transaction expired: confirmation_timeout exceeded", dmsID,
				pkiFailureInfoIncorrectData)
			return
		}
		lFunc.Warnf("certConf: unknown transactionID %s", txHex)
		r.rejectWithError(ctx, &header, PKIStatus(2), "unknown transactionID", dmsID, pkiFailureInfoBadRequest)
		return
	}

	// RFC 4210 §5.1.1: the EE's recipNonce must equal the server's previous senderNonce.
	sentNonce, _ := hex.DecodeString(tx.SentNonce)
	if len(sentNonce) > 0 && !bytes.Equal(header.RecipNonce, sentNonce) {
		lFunc.Errorf("certConf: recipNonce mismatch: got %x want %x", header.RecipNonce, sentNonce)
		r.rejectWithError(ctx, &header, PKIStatus(2), "recipNonce mismatch", dmsID, pkiFailureInfoBadRequest)
		return
	}

	for i, s := range statuses {
		expected, hashErr := computeCertHash(tx.Certificate.Raw, s.HashAlgOID)
		if hashErr != nil {
			lFunc.Errorf("certConf: entry %d unsupported hashAlg %v: %v", i, s.HashAlgOID, hashErr)
			r.rejectWithError(ctx, &header, PKIStatus(2),
				fmt.Sprintf("unsupported certConf hashAlg OID %v", s.HashAlgOID), dmsID, pkiFailureInfoBadRequest)
			return
		}
		if !hashesEqual(s.CertHash, expected) {
			lFunc.Errorf("certConf: entry %d certHash mismatch", i)
			r.rejectWithError(ctx, &header, PKIStatus(2), "certHash mismatch", dmsID, pkiFailureInfoBadRequest)
			return
		}
		lFunc.Debugf("certConf: entry %d certReqId=%d hash OK", i, s.CertReqID)
	}

	lFunc.Infof("certConf verified, transitioning to CONFIRMED")
	if _, _, confirmErr := r.store.Confirm(ctx.Request.Context(), txHex); confirmErr != nil {
		lFunc.Warnf("certConf: failed to confirm transaction (continuing): %v", confirmErr)
	}

	pkiConfDER, err := marshalPKIConfBody()
	if err != nil {
		lFunc.Errorf("certConf: build pkiConf: %v", err)
		r.rejectWithError(ctx, &header, PKIStatus(2), "cannot build pkiConf", dmsID)
		return
	}
	responseDER := r.sendRawBody(ctx, lFunc, header, cmpBodyTagPKIConf, pkiConfDER, dmsID)
	if len(responseDER) == 0 {
		return
	}
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
		r.rejectWithError(ctx, &header, PKIStatus(2), "malformed pollReq", dmsID)
		return
	}
	lFunc = lFunc.WithField("certReqId", certReqID)

	if r.store == nil {
		lFunc.Errorf("pollReq: transaction store not available")
		r.rejectWithError(ctx, &header, PKIStatus(2), "internal error: transaction store unavailable", dmsID)
		return
	}

	txHex := hex.EncodeToString(header.TransactionID)
	tx, ok, err := r.store.Select(ctx.Request.Context(), txHex)
	if err != nil {
		lFunc.Errorf("pollReq: lookup transaction: %v", err)
		r.rejectWithError(ctx, &header, PKIStatus(2), "internal error", dmsID)
		return
	}
	if !ok {
		lFunc.Warnf("pollReq: unknown transactionID %s", txHex)
		r.rejectWithError(ctx, &header, PKIStatus(2), "unknown transactionID", dmsID)
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
			r.rejectWithError(ctx, &header, PKIStatus(2), "cannot build pollRep", dmsID)
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
			r.rejectWithError(ctx, &header, PKIStatus(2), "cannot build response", dmsID)
			return
		}

		// When implicit confirm, transition the transaction to CONFIRMED —
		// no certConf message will arrive to do it later.
		// RFC 4210 §5.2.8: once the server grants implicit confirmation the
		// transaction is complete upon cert delivery.
		if implicitConfirm {
			if _, _, confirmErr := r.store.Confirm(ctx.Request.Context(), txHex); confirmErr != nil {
				lFunc.Warnf("pollReq: failed to confirm tx after implicit-confirm delivery: %v", confirmErr)
			} else {
				lFunc.Debugf("pollReq: tx %s confirmed (implicit confirm)", txHex)
			}
		}

		lFunc.Infof("pollReq: tx %s ISSUED, delivering cert via %s (implicitConfirm=%v)", txHex, cmpTagToString(respTag), implicitConfirm)
		r.sendRawBody(ctx, lFunc, header, respTag, certRepDER, dmsID)

	case storage.CMPTransactionStateIssueFailed:
		reason := tx.ErrorMessage
		if reason == "" {
			reason = "issuance failed"
		}
		lFunc.Warnf("pollReq: tx %s ISSUE_FAILED, returning CMP error: %s", txHex, reason)
		r.rejectWithError(ctx, &header, PKIStatus(pkiStatusRejection), reason, dmsID)

	default:
		lFunc.Errorf("pollReq: tx %s has unknown state %q", txHex, tx.State)
		r.rejectWithError(ctx, &header, PKIStatus(2), "internal error: unknown transaction state", dmsID)
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
func (r *cmpHttpRoutes) rejectWithError(ctx *gin.Context, header *requestPKIHeader, status PKIStatus, reason string, aps string, failInfoBits ...int) {
	errBody, err := marshalErrorBody(status, reason, failInfoBits...)
	if err != nil {
		ctx.Status(http.StatusInternalServerError)
		return
	}
	var h requestPKIHeader
	if header != nil {
		h = *header
		// Best-effort CN lookup: if a transaction row already exists for
		// this txID we can route the Rejected transition to the matching
		// WFX job. For brand-new requests rejected before the row is
		// written there is no CN to find — Emit drops it silently, which
		// is the correct behaviour (no useful WFX job to attach to).
		txHex := hex.EncodeToString(header.TransactionID)
		var deviceCN string
		if r.store != nil {
			if tx, ok, err := r.store.Select(ctx.Request.Context(), txHex); err == nil && ok {
				deviceCN = tx.SubjectCommonName
			}
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
func buildResponseHeader(req requestPKIHeader) responsePKIHeader {
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
		respSenderNonce = newNonce()
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
	}
}

// newNonce generates a 16-byte cryptographically random nonce.
func newNonce() []byte {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return []byte("lamassu-cmp-nonce")
	}
	return b
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
		if r.store == nil || txHex == "" {
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
	if _, err := asn1.Unmarshal(crMsgsSeq.Bytes, &crMsg); err != nil {
		return nil, fmt.Errorf("CertReqMsg: %w", err)
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

	var certTemplate asn1.RawValue
	if _, err := asn1.Unmarshal(rest, &certTemplate); err != nil {
		return nil, fmt.Errorf("CertTemplate: %w", err)
	}
	if certTemplate.Tag != asn1.TagSequence || certTemplate.Class != asn1.ClassUniversal {
		return nil, fmt.Errorf("expected UNIVERSAL SEQUENCE for CertTemplate, got class=%d tag=%d", certTemplate.Class, certTemplate.Tag)
	}

	var subjectDER []byte
	var publicKeyDER []byte
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
			publicKeyDER, err = wrapSequenceDER(field.Bytes, "SubjectPublicKeyInfo")
			if err != nil {
				return nil, err
			}
		}
	}

	if len(subjectDER) == 0 {
		return nil, fmt.Errorf("Subject [5] field not found in CertTemplate")
	}
	if len(publicKeyDER) == 0 {
		return nil, fmt.Errorf("PublicKey [6] field not found in CertTemplate")
	}

	return &firstCertReq{
		CertReqID:    certReqID,
		SubjectDER:   subjectDER,
		PublicKeyDER: publicKeyDER,
		CertReqDER:   certReqSeq.FullBytes,
		POPORaw:      popoRaw,
	}, nil
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
			// senderKID [2] OCTET STRING OPTIONAL (IMPLICIT, RFC 9483 §3.1).
			// field.Bytes holds the OCTET STRING content directly.
			header.SenderKID = field.Bytes
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

		// Look for the optional hashAlg [0] AlgorithmIdentifier within the
		// CertStatus SEQUENCE. It follows certHash (OCTET STRING), certReqId
		// (INTEGER), and the optional statusInfo (SEQUENCE). If present, its
		// inner SEQUENCE contains {algorithm OID, parameters}.
		status.HashAlgOID = extractHashAlgFromCertStatus(certStatusSeq.Bytes)

		statuses = append(statuses, status)
	}

	return statuses, nil
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
// absent and enforce is true the request is rejected. If raVerified [0] is set
// the check is skipped (an authorized RA already verified possession upstream).
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
		// raVerified [0] NULL — an RA upstream already verified POPO; trust it.
		return nil

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
// identified by algID. Supports RSA PKCS#1v15, ECDSA, and Ed25519.
func popoVerifySignature(data, sigBytes []byte, algID pkix.AlgorithmIdentifier, pub crypto.PublicKey) error {
	hashAlg, err := hashFromSignatureAlgOID(algID.Algorithm)
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
		if err := rsa.VerifyPKCS1v15(pub, hashAlg, h.Sum(nil), sigBytes); err != nil {
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
func buildSyntheticCSR(subjectDER, spkiDER []byte) (*x509.CertificateRequest, error) {
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

	// Assemble CertificationRequestInfo (PKCS#10 §4.1).
	// The attributes field [0] IMPLICIT SET is REQUIRED by Go's
	// x509.ParseCertificateRequest even when empty; omitting it causes
	// "sequence truncated" because the decoder expects the tag.
	emptyAttrs, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal empty attrs: %w", err)
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
		Attrs:   asn1.RawValue{FullBytes: emptyAttrs},
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
	return x509.ParseCertificateRequest(csrDER)
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
	default:
		return fmt.Sprintf("unknown(%d)", t)
	}
}
