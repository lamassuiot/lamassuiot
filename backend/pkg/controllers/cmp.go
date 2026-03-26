package controllers

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	"github.com/sirupsen/logrus"
	"github.com/zjj/gocmp/cmp"
)

// pendingTx holds state for an in-progress CMP enrollment transaction
// between the CP/KUP response and the certConf confirmation.
type pendingTx struct {
	CAID         string
	SerialNumber string
	CertDER      []byte
	SentAt       time.Time
}

// cmpTxStore is a thread-safe in-memory store keyed by hex-encoded transactionID.
type cmpTxStore struct {
	m sync.Map
}

const cmpTxTTL = 5 * time.Minute

// put stores a pending transaction.
func (s *cmpTxStore) put(txID []byte, tx pendingTx) {
	s.m.Store(hex.EncodeToString(txID), tx)
}

// get retrieves and removes a pending transaction; returns (zero, false) if absent.
func (s *cmpTxStore) get(txID []byte) (pendingTx, bool) {
	key := hex.EncodeToString(txID)
	v, ok := s.m.LoadAndDelete(key)
	if !ok {
		return pendingTx{}, false
	}
	return v.(pendingTx), true
}

// startCleanup runs a background goroutine that evicts stale transactions.
func (s *cmpTxStore) startCleanup() {
	go func() {
		t := time.NewTicker(cmpTxTTL)
		defer t.Stop()
		for range t.C {
			cutoff := time.Now().Add(-cmpTxTTL)
			s.m.Range(func(k, v any) bool {
				if v.(pendingTx).SentAt.Before(cutoff) {
					s.m.Delete(k)
				}
				return true
			})
		}
	}()
}

// cmpHttpRoutes is the Gin handler for /.well-known/cmp/p/:id.
type cmpHttpRoutes struct {
	svc    services.LightweightCMPService
	logger *logrus.Entry
	store  *cmpTxStore
}

// NewCMPHttpRoutes creates and initialises the CMP HTTP handler.
func NewCMPHttpRoutes(logger *logrus.Entry, svc services.LightweightCMPService) *cmpHttpRoutes {
	store := &cmpTxStore{}
	store.startCleanup()
	return &cmpHttpRoutes{svc: svc, logger: logger, store: store}
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
		r.rejectWithError(ctx, nil, cmp.PKIStatus(2), "missing DMS id", "")
		return
	}

	// Read DER body
	bodyBytes, err := io.ReadAll(ctx.Request.Body)
	if err != nil || len(bodyBytes) == 0 {
		r.rejectWithError(ctx, nil, cmp.PKIStatus(2), "cannot read request body", dmsID)
		return
	}

	// Decode PKIMessage fully (including Protection and ExtraCerts for verification).
	var fullMsg rawPKIMessageFull
	if _, err := asn1.Unmarshal(bodyBytes, &fullMsg); err != nil {
		lFunc.Warnf("failed to unmarshal PKIMessage: %v", err)
		r.rejectWithError(ctx, nil, cmp.PKIStatus(2), "malformed PKIMessage", dmsID)
		return
	}

	header := fullMsg.Header
	body := fullMsg.Body

	reqHeader, err := decodeRequestHeader(header.FullBytes)
	if err != nil {
		lFunc.Warnf("failed to decode PKIHeader: %v", err)
		r.rejectWithError(ctx, nil, cmp.PKIStatus(2), "malformed PKIHeader", dmsID)
		return
	}

	lFunc = lFunc.
		WithField("dms", dmsID).
		WithField("bodyTag", body.Tag).
		WithField("bodyTagStr", cmpTagToString(body.Tag)).
		WithField("txid", hex.EncodeToString(reqHeader.TransactionID))
	lFunc.Debugf("received CMP message body tag=%d", body.Tag)

	// Verify signature-based protection if present in the request.
	if err := verifyRequestProtection(fullMsg); err != nil {
		lFunc.Warnf("protection verification failed: %v", err)
		r.rejectWithError(ctx, &reqHeader, cmp.PKIStatus(2),
			fmt.Sprintf("protection verification failed: %v", err), dmsID)
		return
	}

	// Dispatch on body CHOICE tag
	switch body.Tag {
	case cmpBodyTagIR, cmpBodyTagCR:
		r.handleEnroll(ctx, lFunc, reqHeader, body, dmsID)
	case cmpBodyTagKUR:
		r.handleReenroll(ctx, lFunc, reqHeader, body, dmsID)
	case cmpBodyTagCertConf:
		r.handleCertConf(ctx, lFunc, reqHeader, body, dmsID)
	default:
		lFunc.Warnf("unsupported CMP body tag %d", body.Tag)
		r.rejectWithError(ctx, &reqHeader, cmp.PKIStatus(2),
			fmt.Sprintf("unsupported body tag %d", body.Tag), dmsID)
	}
}

// handleEnroll processes an ir (0) or cr (2) body.
// Both ir and cr route to svc.LWCEnroll; the DMS enrollment policy governs access.
func (r *cmpHttpRoutes) handleEnroll(ctx *gin.Context, lFunc *logrus.Entry, header requestPKIHeader, body asn1.RawValue, dmsID string) {
	req, err := decodeFirstCertReq(body.Bytes)
	if err != nil {
		lFunc.Errorf("ir/cr: decode CertReqMessage: %v", err)
		r.rejectWithError(ctx, &header, cmp.PKIStatus(2), "malformed CertReqMessage", dmsID)
		return
	}

	csr, err := buildSyntheticCSR(req.SubjectDER, req.PublicKeyDER)
	if err != nil {
		lFunc.Errorf("ir/cr: synthesize CSR: %v", err)
		r.rejectWithError(ctx, &header, cmp.PKIStatus(2), "cannot build CSR from CertTemplate", dmsID)
		return
	}
	lFunc = lFunc.WithField("cn", csr.Subject.CommonName)
	lFunc.Infof("enroll request CN=%s", csr.Subject.CommonName)

	cert, err := r.svc.LWCEnroll(ctx.Request.Context(), csr, dmsID)
	if err != nil {
		lFunc.Errorf("ir/cr: enroll failed: %v", err)
		r.rejectWithError(ctx, &header, cmp.PKIStatus(2), err.Error(), dmsID)
		return
	}

	// Only store the pending transaction when explicit confirmation is required.
	// When the DMS is in IMPLICIT mode AND the EE included id-it-implicitConfirm
	// in its request generalInfo, skip the store so no certConf is expected.
	if !r.isImplicitConfirm(ctx.Request.Context(), header, dmsID) {
		r.store.put(header.TransactionID, pendingTx{CertDER: cert.Raw, SentAt: time.Now()})
	} else {
		lFunc.Debugf("implicit confirm: skipping transaction store for txID %s",
			hex.EncodeToString(header.TransactionID))
	}

	// Respond IP (tag 1) for ir, CP (tag 3) for cr
	respTag := cmpBodyTagCP
	if body.Tag == cmpBodyTagIR {
		respTag = cmpBodyTagIP
	}
	certRepDER, err := marshalCertRepBody(respTag, req.CertReqID, cert.Raw)
	if err != nil {
		lFunc.Errorf("ir/cr: build cert rep body: %v", err)
		r.rejectWithError(ctx, &header, cmp.PKIStatus(2), "cannot build response", dmsID)
		return
	}
	r.sendRawBody(ctx, lFunc, header, respTag, certRepDER, dmsID)
}

// handleReenroll processes a kur (7) body and responds with kup (8).
func (r *cmpHttpRoutes) handleReenroll(ctx *gin.Context, lFunc *logrus.Entry, header requestPKIHeader, body asn1.RawValue, dmsID string) {
	req, err := decodeFirstCertReq(body.Bytes)
	if err != nil {
		lFunc.Errorf("kur: decode CertReqMessage: %v", err)
		r.rejectWithError(ctx, &header, cmp.PKIStatus(2), "malformed CertReqMessage", dmsID)
		return
	}

	csr, err := buildSyntheticCSR(req.SubjectDER, req.PublicKeyDER)
	if err != nil {
		lFunc.Errorf("kur: synthesize CSR: %v", err)
		r.rejectWithError(ctx, &header, cmp.PKIStatus(2), "cannot build CSR from CertTemplate", dmsID)
		return
	}
	lFunc = lFunc.WithField("cn", csr.Subject.CommonName)
	lFunc.Infof("reenroll request (kur) CN=%s", csr.Subject.CommonName)

	cert, err := r.svc.LWCReenroll(ctx.Request.Context(), csr, dmsID)
	if err != nil {
		lFunc.Errorf("kur: reenroll failed: %v", err)
		r.rejectWithError(ctx, &header, cmp.PKIStatus(2), err.Error(), dmsID)
		return
	}

	r.store.put(header.TransactionID, pendingTx{CertDER: cert.Raw, SentAt: time.Now()})

	kupDER, err := marshalCertRepBody(cmpBodyTagKUP, req.CertReqID, cert.Raw)
	if err != nil {
		lFunc.Errorf("kur: build kup body: %v", err)
		r.rejectWithError(ctx, &header, cmp.PKIStatus(2), "cannot build response", dmsID)
		return
	}
	r.sendRawBody(ctx, lFunc, header, cmpBodyTagKUP, kupDER, dmsID)
}

// handleCertConf processes a certConf (24) body.
// It verifies the SHA-256 certHash and responds with pkiConf (19).
func (r *cmpHttpRoutes) handleCertConf(ctx *gin.Context, lFunc *logrus.Entry, header requestPKIHeader, body asn1.RawValue, dmsID string) {
	seqDER, err := rewrapBodyAsSequence(body.Bytes)
	if err != nil {
		r.rejectWithError(ctx, &header, cmp.PKIStatus(2), "cannot decode certConf body", dmsID)
		return
	}
	statuses, err := decodeCertConfStatuses(seqDER)
	if err != nil {
		lFunc.Errorf("certConf: decode: %v", err)
		r.rejectWithError(ctx, &header, cmp.PKIStatus(2), "malformed certConf", dmsID)
		return
	}

	tx, ok := r.store.get(header.TransactionID)
	if !ok {
		lFunc.Warnf("certConf: unknown transactionID %s", hex.EncodeToString(header.TransactionID))
		r.rejectWithError(ctx, &header, cmp.PKIStatus(2), "unknown transactionID", dmsID)
		return
	}

	expected := certHashSHA256(tx.CertDER)
	for i, s := range statuses {
		if !hashesEqual(s.CertHash, expected) {
			lFunc.Errorf("certConf: entry %d certHash mismatch", i)
			r.rejectWithError(ctx, &header, cmp.PKIStatus(2), "certHash mismatch", dmsID)
			return
		}
		lFunc.Debugf("certConf: entry %d certReqId=%d hash OK", i, s.CertReqID)
	}

	lFunc.Infof("certConf verified, sending pkiConf")
	pkiConfDER, err := marshalPKIConfBody()
	if err != nil {
		lFunc.Errorf("certConf: build pkiConf: %v", err)
		r.rejectWithError(ctx, &header, cmp.PKIStatus(2), "cannot build pkiConf", dmsID)
		return
	}
	r.sendRawBody(ctx, lFunc, header, cmpBodyTagPKIConf, pkiConfDER, dmsID)
}

// isImplicitConfirm reports whether the current request should be treated as
// implicitly confirmed — i.e. the DMS is in IMPLICIT mode AND the EE included
// the id-it-implicitConfirm OID in the request's generalInfo header.
func (r *cmpHttpRoutes) isImplicitConfirm(ctx context.Context, header requestPKIHeader, dmsID string) bool {
	if !hasImplicitConfirmOID(header.GeneralInfo) {
		return false
	}
	opts, err := r.svc.LWCGetEnrollmentOptions(ctx, dmsID)
	if err != nil || opts == nil {
		return false
	}
	return opts.ConfirmationMode == models.CMPConfirmationModeImplicit
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
func (r *cmpHttpRoutes) rejectWithError(ctx *gin.Context, header *requestPKIHeader, status cmp.PKIStatus, reason string, aps string) {
	errBody, err := marshalErrorBody(status, reason)
	if err != nil {
		ctx.Status(http.StatusInternalServerError)
		return
	}
	var h requestPKIHeader
	if header != nil {
		h = *header
	}
	r.sendRawBody(ctx, r.logger, h, cmpBodyTagError, errBody, aps)
}

// sendRawBody assembles a PKIMessage from a pre-encoded body CHOICE DER and
// writes the result as application/pkixcmp to the Gin context.
func (r *cmpHttpRoutes) sendRawBody(ctx *gin.Context, lFunc *logrus.Entry, reqHeader requestPKIHeader, bodyTag int, bodyDER []byte, aps string) {
	sendResponse := func(respDER []byte) {
		lFunc.Infof("CMP response (tag=%d) PEM:\n%s", bodyTag,
			pem.EncodeToMemory(&pem.Block{Type: "CMP MESSAGE", Bytes: respDER}))
		ctx.Data(http.StatusOK, "application/pkixcmp", respDER)
	}

	if aps != "" {
		if provider, ok := r.svc.(services.LightweightCMPProtectionProvider); ok {
			certChain, signer, credErr := provider.LWCProtectionCredentials(aps)
			if credErr != nil {
				lFunc.Errorf("load cmp protection credentials: %v", credErr)
				ctx.Status(http.StatusInternalServerError)
				return
			}
			respDER, err := marshalProtectedResponse(reqHeader, bodyTag, bodyDER, certChain, signer)
			if err != nil {
				lFunc.Errorf("marshal protected response PKIMessage: %v", err)
				ctx.Status(http.StatusInternalServerError)
				return
			}
			sendResponse(respDER)
			return
		}
	}

	respDER, err := marshalUnprotectedResponse(reqHeader, bodyTag, bodyDER)
	if err != nil {
		lFunc.Errorf("marshal response PKIMessage: %v", err)
		ctx.Status(http.StatusInternalServerError)
		return
	}
	sendResponse(respDER)
}

// buildResponseHeader constructs a response PKIHeader mirroring the
// transactionID from the request and echoing senderNonce as recipNonce.
func buildResponseHeader(req requestPKIHeader) responsePKIHeader {
	defaultHeader := cmp.NewPKIHeader()
	sender := defaultHeader.Sender
	if len(req.Recipient.FullBytes) > 0 {
		sender = asn1.RawValue{FullBytes: req.Recipient.FullBytes}
	}

	recipient := defaultHeader.Recipient
	if len(req.Sender.FullBytes) > 0 {
		recipient = asn1.RawValue{FullBytes: req.Sender.FullBytes}
	}

	return responsePKIHeader{
		PVNO:          pvnoCMP2000,
		Sender:        sender,
		Recipient:     recipient,
		TransactionID: req.TransactionID,
		RecipNonce:    req.SenderNonce,
		SenderNonce:   newNonce(),
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

type firstCertReq struct {
	CertReqID    int
	SubjectDER   []byte
	PublicKeyDER []byte
}

type responsePKIHeader struct {
	PVNO          int                      `asn1:"default:2"`
	Sender        interface{}              // GeneralName
	Recipient     interface{}              // GeneralName
	MessageTime   time.Time                `asn1:"generalized,explicit,optional,tag:0,omitempty"`
	ProtectionAlg pkix.AlgorithmIdentifier `asn1:"explicit,optional,tag:1,omitempty"`
	TransactionID []byte                   `asn1:"optional,explicit,tag:4,omitempty"`
	SenderNonce   []byte                   `asn1:"optional,explicit,tag:5,omitempty"`
	RecipNonce    []byte                   `asn1:"optional,explicit,tag:6,omitempty"`
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
	if _, err := asn1.Unmarshal(crMsg.Bytes, &certReqSeq); err != nil {
		return nil, fmt.Errorf("CertRequest: %w", err)
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

		statuses = append(statuses, status)
	}

	return statuses, nil
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
	case cmpBodyTagCertConf:
		return "certConf"
	case cmpBodyTagPKIConf:
		return "pkiConf"
	case cmpBodyTagError:
		return "error"
	default:
		return fmt.Sprintf("unknown(%d)", t)
	}
}
