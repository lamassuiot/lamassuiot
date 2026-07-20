package cmp

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"

	"github.com/gin-gonic/gin"
	corecmp "github.com/lamassuiot/lamassuiot/core/v3/pkg/cmp"
	"github.com/sirupsen/logrus"
)

// This file implements the CMP nested message operation (nested [20], RFC 4210
// §5.1.3 / RFC 9483 §5.2.2). A nested PKIMessage is an envelope whose body is a
// SEQUENCE OF PKIMessage (PKIMessages) — used by a PKI management entity to add
// its own protection over an EE's already-protected message ("added
// protection", §5.2.2.1) or to batch several messages together (§5.2.2.2). The
// outer envelope is protection-verified by the generic protection layer before
// dispatch; this handler unwraps the inner message(s) and applies each inner
// request's own authorization rules.
//
// A single inner message is treated as added protection: the outer header MUST
// copy the inner transactionID and senderNonce (§5.2.2.1) and the inner request
// is processed by the normal pipeline, yielding a single ip/cp/kup response.
// Multiple inner messages are a batch (§5.2.2.2): the outer header carries
// FRESH transactionID/senderNonce, every inner message's own protection is
// verified before any is acted on, each is processed independently through the
// full pipeline, and the responses are returned wrapped in a nested body in
// request order.
//
// The ccr case keeps the RFC 4210bis §5.3.11 authorization rule that a
// cross-certification request may only originate from a CA; full ccr forwarding
// is not implemented.

// cmpNestedInnerKey marks a request context as "already inside a nested
// envelope" so a batched inner message cannot itself be a nested message
// (recursion guard).
const cmpNestedInnerKey cmpCtxKey = "cmp-nested-inner"

// handleNested processes a nested (20) body.
func (r *cmpHttpRoutes) handleNested(ctx *gin.Context, lFunc *logrus.Entry, header corecmp.RequestPKIHeader, body asn1.RawValue, dmsID string) {
	lFunc = lFunc.WithField("op", "nested")

	if inner, _ := ctx.Request.Context().Value(cmpNestedInnerKey).(bool); inner {
		lFunc.Warnf("nested: nested message inside a nested batch is not supported")
		r.rejectWithError(ctx, &header, corecmp.PKIStatus(corecmp.PKIStatusRejection),
			"nested messages may not be nested inside a batch", dmsID, corecmp.PKIFailureInfoBadRequest)
		return
	}

	inners, err := decodeNestedMessages(body.Bytes)
	if err != nil {
		lFunc.Warnf("nested: could not decode inner PKIMessages: %v", err)
		r.rejectWithError(ctx, &header, corecmp.PKIStatus(corecmp.PKIStatusRejection),
			"malformed nested PKIMessage", dmsID, corecmp.PKIFailureInfoBadDataFormat)
		return
	}

	// Two or more inner messages form a batch (RFC 9483 §5.2.2.2); exactly one
	// is added protection (§5.2.2.1).
	if len(inners) > 1 {
		r.handleNestedBatch(ctx, lFunc, header, inners, dmsID)
		return
	}

	inner := &inners[0].msg
	innerTag := inner.Body.Tag
	lFunc = lFunc.WithField("innerBodyTag", innerTag)

	switch innerTag {
	case corecmp.BodyTagIR, corecmp.BodyTagCR, corecmp.BodyTagP10CR, corecmp.BodyTagKUR:
		// RFC 9483 §5.2.2.1 "adding protection": a PKI management entity wraps its
		// own (already verified) protection around an EE's protected enrollment
		// request. The CA processes the INNER request on its own merits — verify
		// the inner EE protection, then run the normal enrollment pipeline and
		// return the resulting ip/cp/kup.
		r.handleNestedAddedProtection(ctx, lFunc, header, inner, dmsID, innerTag)
	case corecmp.BodyTagCCR:
		// RFC 4210bis §5.3.11: a ccr may only be sent by a CA. The decision is
		// made against the INNER message's own protection signer (its extraCerts),
		// not the RA/CA cert that protects the outer envelope.
		innerSigner := parseFirstExtraCert(inner.ExtraCerts)
		if innerSigner == nil || !innerSigner.IsCA {
			lFunc.Warnf("nested ccr rejected: inner request signer is not a CA (present=%v)", innerSigner != nil)
			r.rejectWithError(ctx, &header, corecmp.PKIStatus(corecmp.PKIStatusRejection),
				"cross-certification requests may only be sent by a CA (RFC 4210bis §5.3.11)",
				dmsID, corecmp.PKIFailureInfoNotAuthorized)
			return
		}
		// A CA-signed inner ccr would require full added-protection forwarding
		// (validating the RA, honoring the inner protection, issuing and
		// re-wrapping the response), which is not implemented.
		lFunc.Warnf("nested ccr from a CA is not supported (added-protection forwarding not implemented)")
		r.rejectWithError(ctx, &header, corecmp.PKIStatus(corecmp.PKIStatusRejection),
			"nested cross-certification forwarding is not supported", dmsID, corecmp.PKIFailureInfoSystemFailure)
	default:
		lFunc.Warnf("nested message with inner body tag %d is not supported", innerTag)
		r.rejectWithError(ctx, &header, corecmp.PKIStatus(corecmp.PKIStatusRejection),
			fmt.Sprintf("nested message processing is not supported for inner body tag %d", innerTag),
			dmsID, corecmp.PKIFailureInfoBadRequest)
	}
}

// handleNestedAddedProtection processes an inner ir/cr/p10cr/kur wrapped in an
// added-protection nested envelope (RFC 9483 §5.2.2.1). The outer envelope's RA
// protection has already been verified by the generic protection layer. Here we
// verify the INNER EE protection, bind the inner signer certificate onto the
// request context, and hand the inner request to the shared enrollment pipeline
// so the CA issues a certificate and replies with the corresponding ip/cp/kup.
func (r *cmpHttpRoutes) handleNestedAddedProtection(ctx *gin.Context, lFunc *logrus.Entry, outerHeader corecmp.RequestPKIHeader, inner *corecmp.RawPKIMessageFull, dmsID string, innerTag int) {
	innerHeader, err := corecmp.DecodeRequestHeader(inner.Header.FullBytes)
	if err != nil {
		lFunc.Warnf("nested added-protection: malformed inner PKIHeader: %v", err)
		r.rejectWithError(ctx, nil, corecmp.PKIStatus(corecmp.PKIStatusRejection),
			"malformed inner PKIHeader", dmsID, corecmp.PKIFailureInfoBadDataFormat)
		return
	}

	// RFC 9483 §5.2.2.1: the wrapping entity MUST copy the transactionID and
	// senderNonce of the original message into the nested header. A mismatch
	// means the envelope does not belong to the request it carries — reject
	// before acting on the inner message.
	if !bytes.Equal(outerHeader.TransactionID, innerHeader.TransactionID) {
		lFunc.Warnf("nested added-protection: outer transactionID does not copy the inner one (RFC 9483 §5.2.2.1)")
		r.rejectWithError(ctx, &outerHeader, corecmp.PKIStatus(corecmp.PKIStatusRejection),
			"added-protection nested header must copy the inner transactionID (RFC 9483 §5.2.2.1)",
			dmsID, corecmp.PKIFailureInfoBadRequest)
		return
	}
	if !bytes.Equal(outerHeader.SenderNonce, innerHeader.SenderNonce) {
		lFunc.Warnf("nested added-protection: outer senderNonce does not copy the inner one (RFC 9483 §5.2.2.1)")
		r.rejectWithError(ctx, &outerHeader, corecmp.PKIStatus(corecmp.PKIStatusRejection),
			"added-protection nested header must copy the inner senderNonce (RFC 9483 §5.2.2.1)",
			dmsID, corecmp.PKIFailureInfoBadSenderNonce)
		return
	}

	enrollOpts, err := r.svc.LWCGetEnrollmentOptions(ctx.Request.Context(), dmsID)
	if err != nil {
		lFunc.Errorf("nested added-protection: could not load enrollment options for DMS '%s': %v", dmsID, err)
		r.rejectWithError(ctx, &innerHeader, corecmp.PKIStatus(corecmp.PKIStatusRejection),
			"could not load DMS configuration", dmsID, corecmp.PKIFailureInfoSystemFailure)
		return
	}

	// Verify the inner EE protection. The requirement mirrors the top-level
	// dispatch: CLIENT_CERTIFICATE-based auth modes require a signature-protected
	// inner message (and therefore a signer cert), while the other modes accept
	// an unprotected inner request.
	requireProtection := requireClientCertProtection(enrollOpts)
	signerCert, err := verifyRequestProtection(*inner, innerHeader.ProtectionAlg, requireProtection)
	if err != nil {
		lFunc.Warnf("nested added-protection: inner protection verification failed: %v", err)
		failBit := protectionRejectFailInfo(err)
		r.rejectRequest(ctx, lFunc, innerHeader, inner.Body.Tag,
			fmt.Sprintf("inner protection verification failed: %v", err), failBit, dmsID)
		return
	}
	if signerCert != nil {
		// RFC 9483 §3.5 / §3.1: the inner sender and senderKID MUST match the
		// inner protection certificate, exactly as for a non-nested request.
		if rej := verifySenderMatchesProtectionCert(innerHeader.Sender, signerCert); rej != nil {
			lFunc.Warnf("nested added-protection: inner sender/subject mismatch: %s", rej.reason)
			r.rejectRequest(ctx, lFunc, innerHeader, inner.Body.Tag, rej.reason, rej.failInfo, dmsID)
			return
		}
		if rej := verifySenderKIDMatchesProtectionCert(innerHeader.SenderKID, signerCert); rej != nil {
			lFunc.Warnf("nested added-protection: inner senderKID validation: %s", rej.reason)
			r.rejectRequest(ctx, lFunc, innerHeader, inner.Body.Tag, rej.reason, rej.failInfo, dmsID)
			return
		}
	}

	if innerTag == corecmp.BodyTagP10CR {
		r.handleP10CR(ctx, lFunc, innerHeader, inner.Body, dmsID, enrollOpts, signerCert)
		return
	}
	variant := enrollmentVariantInitial
	if innerTag == corecmp.BodyTagKUR {
		variant = enrollmentVariantUpdate
	}
	r.handleEnrollment(ctx, lFunc, innerHeader, inner.Body, dmsID, enrollOpts, variant, signerCert)
}

// nestedInnerMessage pairs a decoded inner PKIMessage with its original DER
// (needed to re-dispatch a batched message through the full pipeline).
type nestedInnerMessage struct {
	msg corecmp.RawPKIMessageFull
	der []byte
}

// decodeNestedMessages extracts every inner PKIMessage from a nested body.
// The nested body is `[20] EXPLICIT PKIMessages` (a SEQUENCE OF PKIMessage),
// so nestedBytes is the PKIMessages SEQUENCE.
func decodeNestedMessages(nestedBytes []byte) ([]nestedInnerMessage, error) {
	var msgs asn1.RawValue
	if _, err := asn1.Unmarshal(nestedBytes, &msgs); err != nil {
		return nil, fmt.Errorf("PKIMessages: %w", err)
	}
	if msgs.Class != asn1.ClassUniversal || msgs.Tag != asn1.TagSequence {
		return nil, fmt.Errorf("nested body is not a SEQUENCE OF PKIMessage (class=%d tag=%d)", msgs.Class, msgs.Tag)
	}
	var out []nestedInnerMessage
	remaining := msgs.Bytes
	for len(remaining) > 0 {
		var elem asn1.RawValue
		var err error
		remaining, err = asn1.Unmarshal(remaining, &elem)
		if err != nil {
			return nil, fmt.Errorf("inner PKIMessage %d: %w", len(out), err)
		}
		var inner corecmp.RawPKIMessageFull
		if _, err := asn1.Unmarshal(elem.FullBytes, &inner); err != nil {
			return nil, fmt.Errorf("inner PKIMessage %d: %w", len(out), err)
		}
		out = append(out, nestedInnerMessage{msg: inner, der: elem.FullBytes})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("nested body contains no PKIMessage")
	}
	return out, nil
}

// handleNestedBatch processes a batch nested message (RFC 9483 §5.2.2.2): two
// or more independent PKIMessages submitted together by a PKI management
// entity. Requirements enforced before ANY inner message is acted on:
//
//   - transactionIDs must be fresh: unique among the inner messages and
//     distinct from the outer header's (→ transactionIdInUse);
//   - senderNonces likewise (→ badSenderNonce);
//   - every inner message's OWN protection must verify — the outer protection
//     "MUST NOT indicate verification or approval of the bundled requests"
//     (→ badMessageCheck).
//
// Each inner message is then run through the complete HandleCMP pipeline
// (envelope validation, protection, dispatch) exactly as if it had been posted
// on its own, and the responses are returned in request order inside a nested
// response body whose outer header echoes the outer request header.
func (r *cmpHttpRoutes) handleNestedBatch(ctx *gin.Context, lFunc *logrus.Entry, header corecmp.RequestPKIHeader, inners []nestedInnerMessage, dmsID string) {
	lFunc = lFunc.WithField("op", "nested-batch").WithField("batchSize", len(inners))

	enrollOpts, err := r.svc.LWCGetEnrollmentOptions(ctx.Request.Context(), dmsID)
	if err != nil {
		lFunc.Errorf("nested batch: could not load enrollment options for DMS '%s': %v", dmsID, err)
		r.rejectWithError(ctx, &header, corecmp.PKIStatus(corecmp.PKIStatusRejection),
			"could not load DMS configuration", dmsID, corecmp.PKIFailureInfoSystemFailure)
		return
	}
	requireProtection := requireClientCertProtection(enrollOpts)

	seenTxIDs := map[string]bool{hex.EncodeToString(header.TransactionID): true}
	seenNonces := map[string]bool{hex.EncodeToString(header.SenderNonce): true}
	innerHeaders := make([]corecmp.RequestPKIHeader, len(inners))
	for i, inner := range inners {
		ih, err := corecmp.DecodeRequestHeader(inner.msg.Header.FullBytes)
		if err != nil {
			lFunc.Warnf("nested batch: malformed inner PKIHeader %d: %v", i, err)
			r.rejectWithError(ctx, &header, corecmp.PKIStatus(corecmp.PKIStatusRejection),
				fmt.Sprintf("malformed PKIHeader in batched message %d", i), dmsID, corecmp.PKIFailureInfoBadDataFormat)
			return
		}
		innerHeaders[i] = ih

		tx := hex.EncodeToString(ih.TransactionID)
		if seenTxIDs[tx] {
			lFunc.Warnf("nested batch: transactionID of inner message %d is not fresh (RFC 9483 §5.2.2.2)", i)
			r.rejectWithError(ctx, &header, corecmp.PKIStatus(corecmp.PKIStatusRejection),
				"batched messages must carry fresh, unique transactionIDs (RFC 9483 §5.2.2.2)",
				dmsID, corecmp.PKIFailureInfoTransactionIDInUse)
			return
		}
		seenTxIDs[tx] = true

		nonce := hex.EncodeToString(ih.SenderNonce)
		if seenNonces[nonce] {
			lFunc.Warnf("nested batch: senderNonce of inner message %d is not fresh (RFC 9483 §5.2.2.2)", i)
			r.rejectWithError(ctx, &header, corecmp.PKIStatus(corecmp.PKIStatusRejection),
				"batched messages must carry fresh, unique senderNonces (RFC 9483 §5.2.2.2)",
				dmsID, corecmp.PKIFailureInfoBadSenderNonce)
			return
		}
		seenNonces[nonce] = true
	}

	// RFC 9483 §5.2.2.2: the outer protection does not vouch for the bundled
	// requests, so every inner message must verify on its own. Checked for the
	// WHOLE batch before any message is processed — a batch with one forged
	// member is rejected atomically rather than partially executed.
	for i := range inners {
		if _, err := verifyRequestProtection(inners[i].msg, innerHeaders[i].ProtectionAlg, requireProtection); err != nil {
			lFunc.Warnf("nested batch: protection verification of inner message %d failed: %v", i, err)
			failBit := protectionRejectFailInfo(err)
			r.rejectWithError(ctx, &header, corecmp.PKIStatus(corecmp.PKIStatusRejection),
				fmt.Sprintf("protection verification failed for batched message %d: %v", i, err),
				dmsID, failBit)
			return
		}
	}

	// Process each inner message through the full pipeline and collect the
	// response PKIMessages in request order.
	var responsesDER []byte
	for i, inner := range inners {
		respDER := r.processBatchedMessage(ctx, inner.der, dmsID)
		if len(respDER) == 0 {
			lFunc.Errorf("nested batch: no response produced for inner message %d", i)
			r.rejectWithError(ctx, &header, corecmp.PKIStatus(corecmp.PKIStatusRejection),
				fmt.Sprintf("could not process batched message %d", i), dmsID, corecmp.PKIFailureInfoSystemFailure)
			return
		}
		responsesDER = append(responsesDER, respDER...)
	}

	nestedBody, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      responsesDER,
	})
	if err != nil {
		lFunc.Errorf("nested batch: marshal response PKIMessages: %v", err)
		r.rejectWithError(ctx, &header, corecmp.PKIStatus(corecmp.PKIStatusRejection),
			"cannot build nested response", dmsID, corecmp.PKIFailureInfoSystemFailure)
		return
	}
	lFunc.Infof("nested batch: processed %d inner messages", len(inners))
	r.sendRawBody(ctx, lFunc, header, corecmp.BodyTagNested, nestedBody, dmsID)
}

// processBatchedMessage re-dispatches one batched inner PKIMessage through the
// full HandleCMP pipeline against an in-memory response recorder and returns
// the response DER. The inner request context is built fresh (not cloned from
// the outer request) so the outer envelope's signer identity cannot leak into
// the inner message's authentication; cmpNestedInnerKey blocks recursive
// nesting.
func (r *cmpHttpRoutes) processBatchedMessage(parent *gin.Context, innerDER []byte, dmsID string) []byte {
	recorder := httptest.NewRecorder()
	innerCtx, _ := gin.CreateTestContext(recorder)

	reqCtx := context.WithValue(context.Background(), cmpNestedInnerKey, true)
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost,
		parent.Request.URL.String(), bytes.NewReader(innerDER))
	if err != nil {
		return nil
	}
	req.Header.Set("Content-Type", "application/pkixcmp")
	innerCtx.Request = req
	innerCtx.Params = gin.Params{{Key: "id", Value: dmsID}}

	r.HandleCMP(innerCtx)
	if recorder.Code != http.StatusOK {
		return nil
	}
	return recorder.Body.Bytes()
}

// parseFirstExtraCert parses the leaf certificate from a PKIMessage extraCerts
// field, tolerating the encodings Go's asn1 can produce for the [1] EXPLICIT
// SEQUENCE OF Certificate (the whole entry, its first inner element, or the raw
// content). Returns nil when no certificate can be parsed.
func parseFirstExtraCert(extraCerts []asn1.RawValue) *x509.Certificate {
	if len(extraCerts) == 0 {
		return nil
	}
	cert, err := corecmp.ParseLeafExtraCert(extraCerts[0])
	if err != nil {
		return nil
	}
	return cert
}
