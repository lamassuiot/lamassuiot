package cmp

import (
	"context"
	"crypto/x509"
	"encoding/asn1"
	"fmt"

	"github.com/gin-gonic/gin"
	identityextractors "github.com/lamassuiot/lamassuiot/backend/v3/pkg/routes/middlewares/identity-extractors"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/sirupsen/logrus"
)

// This file implements the CMP nested message operation (nested [20], RFC 4210
// §5.1.3 / RFC 9483 §5.2.2). A nested PKIMessage is an envelope whose body is a
// SEQUENCE OF PKIMessage (PKIMessages) — used by a PKI management entity to add
// its own protection over an EE's already-protected message ("added
// protection", §5.2.2.2) or to batch several messages together (§5.2.2.1). The
// outer envelope is protection-verified by the generic protection layer before
// dispatch; this handler unwraps the inner message(s) and applies the inner
// request's own authorization rules.
//
// Support here is deliberately narrow: it covers the RFC 4210bis §5.3.11
// authorization rule that a cross-certification request (ccr) may only originate
// from a CA. An inner ccr whose OWN protection signer is not a CA is rejected
// notAuthorized regardless of the RA/CA protection wrapped around the envelope.
// Full added-protection forwarding and batching of accepted requests are not
// implemented.

// handleNested processes a nested (20) body.
func (r *cmpHttpRoutes) handleNested(ctx *gin.Context, lFunc *logrus.Entry, header requestPKIHeader, body asn1.RawValue, dmsID string) {
	lFunc = lFunc.WithField("op", "nested")

	inner, err := decodeFirstNestedMessage(body.Bytes)
	if err != nil {
		lFunc.Warnf("nested: could not decode inner PKIMessage: %v", err)
		r.rejectWithError(ctx, &header, PKIStatus(pkiStatusRejection),
			"malformed nested PKIMessage", dmsID, pkiFailureInfoBadDataFormat)
		return
	}

	innerTag := inner.Body.Tag
	lFunc = lFunc.WithField("innerBodyTag", innerTag)

	switch innerTag {
	case cmpBodyTagIR, cmpBodyTagCR, cmpBodyTagKUR:
		// RFC 9483 §5.2.2.1 "adding protection": a PKI management entity wraps its
		// own (already verified) protection around an EE's protected enrollment
		// request. The CA processes the INNER request on its own merits — verify
		// the inner EE protection, then run the normal enrollment pipeline and
		// return the resulting ip/cp/kup.
		r.handleNestedAddedProtection(ctx, lFunc, inner, dmsID, innerTag)
	case cmpBodyTagCCR:
		// RFC 4210bis §5.3.11: a ccr may only be sent by a CA. The decision is
		// made against the INNER message's own protection signer (its extraCerts),
		// not the RA/CA cert that protects the outer envelope.
		innerSigner := parseFirstExtraCert(inner.ExtraCerts)
		if innerSigner == nil || !innerSigner.IsCA {
			lFunc.Warnf("nested ccr rejected: inner request signer is not a CA (present=%v)", innerSigner != nil)
			r.rejectWithError(ctx, &header, PKIStatus(pkiStatusRejection),
				"cross-certification requests may only be sent by a CA (RFC 4210bis §5.3.11)",
				dmsID, pkiFailureInfoNotAuthorized)
			return
		}
		// A CA-signed inner ccr would require full added-protection forwarding
		// (validating the RA, honoring the inner protection, issuing and
		// re-wrapping the response), which is not implemented.
		lFunc.Warnf("nested ccr from a CA is not supported (added-protection forwarding not implemented)")
		r.rejectWithError(ctx, &header, PKIStatus(pkiStatusRejection),
			"nested cross-certification forwarding is not supported", dmsID, pkiFailureInfoSystemFailure)
	default:
		lFunc.Warnf("nested message with inner body tag %d is not supported", innerTag)
		r.rejectWithError(ctx, &header, PKIStatus(pkiStatusRejection),
			fmt.Sprintf("nested message processing is not supported for inner body tag %d", innerTag),
			dmsID, pkiFailureInfoBadRequest)
	}
}

// handleNestedAddedProtection processes an inner ir/cr/kur wrapped in an
// added-protection nested envelope (RFC 9483 §5.2.2.1). The outer envelope's RA
// protection has already been verified by the generic protection layer. Here we
// verify the INNER EE protection, bind the inner signer certificate onto the
// request context, and hand the inner request to the shared enrollment pipeline
// so the CA issues a certificate and replies with the corresponding ip/cp/kup.
func (r *cmpHttpRoutes) handleNestedAddedProtection(ctx *gin.Context, lFunc *logrus.Entry, inner *rawPKIMessageFull, dmsID string, innerTag int) {
	innerHeader, err := decodeRequestHeader(inner.Header.FullBytes)
	if err != nil {
		lFunc.Warnf("nested added-protection: malformed inner PKIHeader: %v", err)
		r.rejectWithError(ctx, nil, PKIStatus(pkiStatusRejection),
			"malformed inner PKIHeader", dmsID, pkiFailureInfoBadDataFormat)
		return
	}

	enrollOpts, err := r.svc.LWCGetEnrollmentOptions(ctx.Request.Context(), dmsID)
	if err != nil {
		lFunc.Errorf("nested added-protection: could not load enrollment options for DMS '%s': %v", dmsID, err)
		r.rejectWithError(ctx, &innerHeader, PKIStatus(pkiStatusRejection),
			"could not load DMS configuration", dmsID, pkiFailureInfoSystemFailure)
		return
	}

	// Verify the inner EE protection. The requirement mirrors the top-level
	// dispatch: CLIENT_CERTIFICATE-based auth modes require a signature-protected
	// inner message (and therefore a signer cert), while the other modes accept
	// an unprotected inner request.
	requireProtection := enrollOpts.AuthMode == models.EnrollmentAuthModeClientCertificate ||
		enrollOpts.AuthMode == models.EnrollmentAuthModeClientCertificateAndWebhook
	signerCert, err := verifyRequestProtection(*inner, innerHeader.ProtectionAlg, requireProtection)
	if err != nil {
		lFunc.Warnf("nested added-protection: inner protection verification failed: %v", err)
		failBit := pkiFailureInfoBadMessageCheck
		if algBit, ok := protectionAlgFailInfo(err); ok {
			failBit = algBit
		}
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
		reqCtx := context.WithValue(ctx.Request.Context(),
			string(identityextractors.IdentityExtractorCMPSignerCertificate), signerCert)
		ctx.Request = ctx.Request.WithContext(reqCtx)
	}

	variant := enrollmentVariantInitial
	if innerTag == cmpBodyTagKUR {
		variant = enrollmentVariantUpdate
	}
	r.handleEnrollment(ctx, lFunc, innerHeader, inner.Body, dmsID, enrollOpts, variant)
}

// decodeFirstNestedMessage extracts the first inner PKIMessage from a nested
// body. The nested body is `[20] EXPLICIT PKIMessages` (a SEQUENCE OF
// PKIMessage), so nestedBytes is the PKIMessages SEQUENCE; its first element is
// the first inner PKIMessage.
func decodeFirstNestedMessage(nestedBytes []byte) (*rawPKIMessageFull, error) {
	var msgs asn1.RawValue
	if _, err := asn1.Unmarshal(nestedBytes, &msgs); err != nil {
		return nil, fmt.Errorf("PKIMessages: %w", err)
	}
	if msgs.Class != asn1.ClassUniversal || msgs.Tag != asn1.TagSequence {
		return nil, fmt.Errorf("nested body is not a SEQUENCE OF PKIMessage (class=%d tag=%d)", msgs.Class, msgs.Tag)
	}
	if len(msgs.Bytes) == 0 {
		return nil, fmt.Errorf("nested body contains no PKIMessage")
	}
	var inner rawPKIMessageFull
	if _, err := asn1.Unmarshal(msgs.Bytes, &inner); err != nil {
		return nil, fmt.Errorf("inner PKIMessage: %w", err)
	}
	return &inner, nil
}

// parseFirstExtraCert parses the leaf certificate from a PKIMessage extraCerts
// field, tolerating the encodings Go's asn1 can produce for the [1] EXPLICIT
// SEQUENCE OF Certificate (the whole entry, its first inner element, or the raw
// content). Returns nil when no certificate can be parsed.
func parseFirstExtraCert(extraCerts []asn1.RawValue) *x509.Certificate {
	if len(extraCerts) == 0 {
		return nil
	}
	ec0 := extraCerts[0]
	if c, err := x509.ParseCertificate(ec0.FullBytes); err == nil {
		return c
	}
	var first asn1.RawValue
	if _, err := asn1.Unmarshal(ec0.Bytes, &first); err == nil {
		if c, err := x509.ParseCertificate(first.FullBytes); err == nil {
			return c
		}
	}
	if c, err := x509.ParseCertificate(ec0.Bytes); err == nil {
		return c
	}
	return nil
}
