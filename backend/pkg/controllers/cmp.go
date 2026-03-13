package controllers

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
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
	svc    services.DMSManagerService
	logger *logrus.Entry
	store  *cmpTxStore
}

// NewCMPHttpRoutes creates and initialises the CMP HTTP handler.
func NewCMPHttpRoutes(logger *logrus.Entry, svc services.DMSManagerService) *cmpHttpRoutes {
	store := &cmpTxStore{}
	store.startCleanup()
	return &cmpHttpRoutes{svc: svc, logger: logger, store: store}
}

// HandleCMP handles all inbound CMP messages posted to /.well-known/cmp/p/:id.
//
// It reads a DER-encoded PKIMessage, dispatches on the body CHOICE tag, calls
// the appropriate svc.Enroll / svc.Reenroll method, and returns a DER-encoded
// response.
//
// Unprotected responses are used in this implementation; RFC 9480 §3.2 permits
// unprotected messages for private networks / testing.
func (r *cmpHttpRoutes) HandleCMP(ctx *gin.Context) {
	lFunc := r.logger.WithField("component", "cmp-handler")

	// Identify DMS from path /:id
	dmsID := ctx.Param("id")
	if dmsID == "" {
		r.rejectWithError(ctx, nil, cmp.PKIStatus(2), "missing DMS id")
		return
	}

	// Read DER body
	bodyBytes, err := io.ReadAll(ctx.Request.Body)
	if err != nil || len(bodyBytes) == 0 {
		r.rejectWithError(ctx, nil, cmp.PKIStatus(2), "cannot read request body")
		return
	}

	// Decode PKIMessage – capture header and raw body CHOICE value
	var rawMsg rawPKIMessage
	if _, err := asn1.Unmarshal(bodyBytes, &rawMsg); err != nil {
		lFunc.Warnf("failed to unmarshal PKIMessage: %v", err)
		r.rejectWithError(ctx, nil, cmp.PKIStatus(2), "malformed PKIMessage")
		return
	}

	header := rawMsg.Header
	body := rawMsg.Body

	lFunc = lFunc.
		WithField("dms", dmsID).
		WithField("bodyTag", body.Tag).
		WithField("txid", hex.EncodeToString(header.TransactionID))
	lFunc.Debugf("received CMP message body tag=%d", body.Tag)

	// Dispatch on body CHOICE tag
	switch body.Tag {
	case cmpBodyTagIR, cmpBodyTagCR:
		r.handleEnroll(ctx, lFunc, header, body, dmsID)
	case cmpBodyTagKUR:
		r.handleReenroll(ctx, lFunc, header, body, dmsID)
	case cmpBodyTagCertConf:
		r.handleCertConf(ctx, lFunc, header, body)
	default:
		lFunc.Warnf("unsupported CMP body tag %d", body.Tag)
		r.rejectWithError(ctx, &header, cmp.PKIStatus(2),
			fmt.Sprintf("unsupported body tag %d", body.Tag))
	}
}

// handleEnroll processes an ir (0) or cr (2) body.
// Both ir and cr route to svc.Enroll; the DMS enrollment policy governs access.
func (r *cmpHttpRoutes) handleEnroll(
	ctx *gin.Context,
	lFunc *logrus.Entry,
	header cmp.PKIHeader,
	body asn1.RawValue,
	dmsID string,
) {
	msgs, err := decodeCertReqMessages(body.Bytes)
	if err != nil {
		lFunc.Errorf("ir/cr: decode CertReqMessages: %v", err)
		r.rejectWithError(ctx, &header, cmp.PKIStatus(2), "malformed CertReqMessages")
		return
	}
	if len(msgs) == 0 {
		r.rejectWithError(ctx, &header, cmp.PKIStatus(2), "empty CertReqMessages")
		return
	}

	msg := msgs[0]
	csr, err := buildSyntheticCSR(msg.CertReq.CertTemplate)
	if err != nil {
		lFunc.Errorf("ir/cr: synthesize CSR: %v", err)
		r.rejectWithError(ctx, &header, cmp.PKIStatus(2), "cannot build CSR from CertTemplate")
		return
	}
	lFunc = lFunc.WithField("cn", csr.Subject.CommonName)
	lFunc.Infof("enroll request CN=%s", csr.Subject.CommonName)

	cert, err := r.svc.Enroll(ctx.Request.Context(), csr, dmsID)
	if err != nil {
		lFunc.Errorf("ir/cr: enroll failed: %v", err)
		r.rejectWithError(ctx, &header, cmp.PKIStatus(2), err.Error())
		return
	}

	r.store.put(header.TransactionID, pendingTx{CertDER: cert.Raw, SentAt: time.Now()})

	// Respond IP (tag 1) for ir, CP (tag 3) for cr
	respTag := cmpBodyTagCP
	if body.Tag == cmpBodyTagIR {
		respTag = cmpBodyTagIP
	}
	certRepDER, err := marshalCertRepBody(respTag, msg.CertReq.CertReqID, cert.Raw)
	if err != nil {
		lFunc.Errorf("ir/cr: build cert rep body: %v", err)
		r.rejectWithError(ctx, &header, cmp.PKIStatus(2), "cannot build response")
		return
	}
	r.sendRawBody(ctx, lFunc, header, certRepDER)
}

// handleReenroll processes a kur (7) body and responds with kup (8).
func (r *cmpHttpRoutes) handleReenroll(
	ctx *gin.Context,
	lFunc *logrus.Entry,
	header cmp.PKIHeader,
	body asn1.RawValue,
	dmsID string,
) {
	msgs, err := decodeCertReqMessages(body.Bytes)
	if err != nil {
		lFunc.Errorf("kur: decode CertReqMessages: %v", err)
		r.rejectWithError(ctx, &header, cmp.PKIStatus(2), "malformed CertReqMessages")
		return
	}
	if len(msgs) == 0 {
		r.rejectWithError(ctx, &header, cmp.PKIStatus(2), "empty CertReqMessages")
		return
	}

	msg := msgs[0]
	csr, err := buildSyntheticCSR(msg.CertReq.CertTemplate)
	if err != nil {
		lFunc.Errorf("kur: synthesize CSR: %v", err)
		r.rejectWithError(ctx, &header, cmp.PKIStatus(2), "cannot build CSR from CertTemplate")
		return
	}
	lFunc = lFunc.WithField("cn", csr.Subject.CommonName)
	lFunc.Infof("reenroll request (kur) CN=%s", csr.Subject.CommonName)

	cert, err := r.svc.Reenroll(ctx.Request.Context(), csr, dmsID)
	if err != nil {
		lFunc.Errorf("kur: reenroll failed: %v", err)
		r.rejectWithError(ctx, &header, cmp.PKIStatus(2), err.Error())
		return
	}

	r.store.put(header.TransactionID, pendingTx{CertDER: cert.Raw, SentAt: time.Now()})

	kupDER, err := marshalCertRepBody(cmpBodyTagKUP, msg.CertReq.CertReqID, cert.Raw)
	if err != nil {
		lFunc.Errorf("kur: build kup body: %v", err)
		r.rejectWithError(ctx, &header, cmp.PKIStatus(2), "cannot build response")
		return
	}
	r.sendRawBody(ctx, lFunc, header, kupDER)
}

// handleCertConf processes a certConf (24) body.
// It verifies the SHA-256 certHash and responds with pkiConf (19).
func (r *cmpHttpRoutes) handleCertConf(
	ctx *gin.Context,
	lFunc *logrus.Entry,
	header cmp.PKIHeader,
	body asn1.RawValue,
) {
	seqDER, err := rewrapBodyAsSequence(body.Bytes)
	if err != nil {
		r.rejectWithError(ctx, &header, cmp.PKIStatus(2), "cannot decode certConf body")
		return
	}
	var statuses []certStatusASN1
	if _, err := asn1.Unmarshal(seqDER, &statuses); err != nil {
		lFunc.Errorf("certConf: decode: %v", err)
		r.rejectWithError(ctx, &header, cmp.PKIStatus(2), "malformed certConf")
		return
	}

	tx, ok := r.store.get(header.TransactionID)
	if !ok {
		lFunc.Warnf("certConf: unknown transactionID %s", hex.EncodeToString(header.TransactionID))
		r.rejectWithError(ctx, &header, cmp.PKIStatus(2), "unknown transactionID")
		return
	}

	expected := certHashSHA256(tx.CertDER)
	for i, s := range statuses {
		if !hashesEqual(s.CertHash, expected) {
			lFunc.Errorf("certConf: entry %d certHash mismatch", i)
			r.rejectWithError(ctx, &header, cmp.PKIStatus(2), "certHash mismatch")
			return
		}
		lFunc.Debugf("certConf: entry %d certReqId=%d hash OK", i, s.CertReqID)
	}

	lFunc.Infof("certConf verified, sending pkiConf")
	pkiConfDER, err := marshalPKIConfBody()
	if err != nil {
		lFunc.Errorf("certConf: build pkiConf: %v", err)
		r.rejectWithError(ctx, &header, cmp.PKIStatus(2), "cannot build pkiConf")
		return
	}
	r.sendRawBody(ctx, lFunc, header, pkiConfDER)
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

// rejectWithError sends a CMP Error PKIMessage response.
// header may be nil if the incoming PKIMessage header could not be parsed.
func (r *cmpHttpRoutes) rejectWithError(
	ctx *gin.Context,
	header *cmp.PKIHeader,
	status cmp.PKIStatus,
	reason string,
) {
	errBody, err := marshalErrorBody(status, reason)
	if err != nil {
		ctx.Status(http.StatusInternalServerError)
		return
	}
	var h cmp.PKIHeader
	if header != nil {
		h = *header
	} else {
		h = *cmp.NewPKIHeader()
	}
	r.sendRawBody(ctx, r.logger, h, errBody)
}

// sendRawBody assembles a PKIMessage from a pre-encoded body CHOICE DER and
// writes the result as application/pkixcmp to the Gin context.
func (r *cmpHttpRoutes) sendRawBody(
	ctx *gin.Context,
	lFunc *logrus.Entry,
	reqHeader cmp.PKIHeader,
	bodyChoiceDER []byte,
) {
	respHeader := buildResponseHeader(reqHeader)

	type serverPKIMessage struct {
		Header cmp.PKIHeader
		Body   asn1.RawValue
	}
	respDER, err := asn1.Marshal(serverPKIMessage{
		Header: respHeader,
		Body:   asn1.RawValue{FullBytes: bodyChoiceDER},
	})
	if err != nil {
		lFunc.Errorf("marshal response PKIMessage: %v", err)
		ctx.Status(http.StatusInternalServerError)
		return
	}
	ctx.Data(http.StatusOK, "application/pkixcmp", respDER)
}

// buildResponseHeader constructs a response PKIHeader mirroring the
// transactionID from the request and echoing senderNonce as recipNonce.
func buildResponseHeader(req cmp.PKIHeader) cmp.PKIHeader {
	resp := *cmp.NewPKIHeader()
	resp.PVNO = pvnoCMP2000
	resp.TransactionID = req.TransactionID
	resp.RecipNonce = req.SenderNonce
	resp.SenderNonce = newNonce()
	return resp
}

// newNonce generates a 16-byte cryptographically random nonce.
func newNonce() []byte {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return []byte("lamassu-cmp-nonce")
	}
	return b
}

// decodeCertReqMessages re-wraps the raw CHOICE body bytes with a SEQUENCE
// header and decodes them into a []cmp.CertReqMessage.
//
// Per RFC 4210 IMPLICIT TAGS, the CHOICE tag replaces the outer SEQUENCE tag
// of CertReqMessages; we must restore the SEQUENCE header to unmarshal.
func decodeCertReqMessages(bodyBytes []byte) ([]cmp.CertReqMessage, error) {
	seqDER, err := rewrapBodyAsSequence(bodyBytes)
	if err != nil {
		return nil, err
	}
	var msgs []cmp.CertReqMessage
	if _, err := asn1.Unmarshal(seqDER, &msgs); err != nil {
		return nil, fmt.Errorf("unmarshal CertReqMessages: %w", err)
	}
	return msgs, nil
}

// buildSyntheticCSR constructs a *x509.CertificateRequest from a CMP
// CertTemplate (RFC 4211 §5).
//
// Because POPO is handled at the CMP layer (not inside the CSR), the resulting
// CSR has a dummy 1-byte zero signature. Set VerifyCSRSignature=false in the
// DMS EnrollmentSettings when using CMP to bypass csr.CheckSignature().
func buildSyntheticCSR(certTemplate cmp.CertTemplate) (*x509.CertificateRequest, error) {
	// Build SPKI DER from CertTemplate.PublicKey (cmp.SubjectPublicKeyInfo).
	spkiDER, err := asn1.Marshal(certTemplate.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal SPKI: %w", err)
	}

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

	// Build Subject DER via pkix.Name for correct SET-OF encoding.
	var pname pkix.Name
	rdns := certTemplate.Subject.RDNSequence
	pname.FillFromRDNSequence(&rdns)
	subjectDER, err := asn1.Marshal(pname.ToRDNSequence())
	if err != nil {
		return nil, fmt.Errorf("marshal subject: %w", err)
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
