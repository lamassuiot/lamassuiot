package cmp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"math/big"
	"net/http"
	"testing"
	"time"

	corecmp "github.com/lamassuiot/lamassuiot/core/v3/pkg/cmp"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	cmpmock "github.com/lamassuiot/lamassuiot/core/v3/pkg/services/mock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Nested message tests: added-protection header copy rules (RFC 9483 §5.2.2.1)
// and batch processing (§5.2.2.2), plus the RFC 9483 §5.3.2/§5.2.3 trusted-RA
// behaviors (revocation on behalf of another entity, raVerified-on-KUR ban).
// ---------------------------------------------------------------------------

// buildNestedMessage wraps the given inner PKIMessage DERs in a nested (20)
// PKIMessage with the given outer transactionID and senderNonce.
func buildNestedMessage(t *testing.T, txID, senderNonce []byte, innerDERs ...[]byte) []byte {
	t.Helper()

	headerDER := buildTestPKIHeaderDER(t, txID, senderNonce, nil, false)

	bodyDER, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        corecmp.BodyTagNested,
		IsCompound: true,
		Bytes:      seqDER(t, concatBytes(innerDERs...)),
	})
	require.NoError(t, err)

	msgDER, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      concatBytes(headerDER, bodyDER),
	})
	require.NoError(t, err)
	return msgDER
}

// headerOf decodes the PKIHeader of a raw PKIMessage DER.
func headerOf(t *testing.T, msgDER []byte) corecmp.RequestPKIHeader {
	t.Helper()
	var raw corecmp.RawPKIMessage
	_, err := asn1.Unmarshal(msgDER, &raw)
	require.NoError(t, err)
	h, err := corecmp.DecodeRequestHeader(raw.Header.FullBytes)
	require.NoError(t, err)
	return h
}

// nestedResponses splits a nested (20) response body into its inner PKIMessage DERs.
func nestedResponses(t *testing.T, responseDER []byte) [][]byte {
	t.Helper()
	var msg corecmp.RawPKIMessage
	_, err := asn1.Unmarshal(responseDER, &msg)
	require.NoError(t, err)
	require.Equal(t, corecmp.BodyTagNested, msg.Body.Tag, "response must be a nested body")

	var seq asn1.RawValue
	_, err = asn1.Unmarshal(msg.Body.Bytes, &seq)
	require.NoError(t, err)

	var out [][]byte
	remaining := seq.Bytes
	for len(remaining) > 0 {
		var elem asn1.RawValue
		remaining, err = asn1.Unmarshal(remaining, &elem)
		require.NoError(t, err)
		out = append(out, elem.FullBytes)
	}
	return out
}

// TestHandleCMP_NestedBatch_ProcessesAll verifies that a batch of two IRs with
// fresh transactionIDs/nonces yields a nested response containing one ip per
// inner request, each echoing its request's transactionID (RFC 9483 §5.2.2.2).
func TestHandleCMP_NestedBatch_ProcessesAll(t *testing.T) {
	issuedCert, _ := buildSelfSignedCert(t, "batch-device")

	router, _, svc := newEnrollRouter(t, models.EnrollmentOptionsLWCRFC9483{AcceptImplicit: true}, issuedCert)

	inner1, tx1, _ := buildTestIR(t, testIROptions{CN: "batch-device-1", WithImplicitConfirm: true})
	inner2, tx2, _ := buildTestIR(t, testIROptions{CN: "batch-device-2", WithImplicitConfirm: true})

	outerTx := randomTxID(t)
	nested := buildNestedMessage(t, outerTx, randomNonce(t), inner1, inner2)

	resp := postCMP(t, router, "test-dms", nested)
	require.Equal(t, http.StatusOK, resp.Code)
	require.Equal(t, corecmp.BodyTagNested, parseCMPResponseTag(t, resp.Body.Bytes()),
		"batch must be answered with a nested body")

	inners := nestedResponses(t, resp.Body.Bytes())
	require.Len(t, inners, 2, "one response per batched request")
	assert.Equal(t, corecmp.BodyTagIP, parseCMPResponseTag(t, inners[0]))
	assert.Equal(t, corecmp.BodyTagIP, parseCMPResponseTag(t, inners[1]))
	assert.Equal(t, tx1, headerOf(t, inners[0]).TransactionID, "first response echoes first request txID")
	assert.Equal(t, tx2, headerOf(t, inners[1]).TransactionID, "second response echoes second request txID")

	svc.AssertNumberOfCalls(t, "LWCEnroll", 2)
}

// TestHandleCMP_NestedBatch_RejectsTooManyInnerMessages is a DoS-hardening
// regression test: a nested body carrying more inner PKIMessages than
// cmpMaxNestedMessages must be rejected before any of them are processed —
// each batched message drives a full pipeline pass (CA/KMS calls included),
// so an unbounded batch turns one HTTP request into unbounded downstream work.
func TestHandleCMP_NestedBatch_RejectsTooManyInnerMessages(t *testing.T) {
	router, _, svc := newOptionsRouter(t, models.EnrollmentOptionsLWCRFC9483{})

	inners := make([][]byte, 0, cmpMaxNestedMessages+1)
	for i := 0; i <= cmpMaxNestedMessages; i++ {
		inner, _, _ := buildTestIR(t, testIROptions{CN: fmt.Sprintf("flood-device-%d", i)})
		inners = append(inners, inner)
	}

	outerTx := randomTxID(t)
	nested := buildNestedMessage(t, outerTx, randomNonce(t), inners...)

	resp := postCMP(t, router, "test-dms", nested)
	require.Equal(t, http.StatusOK, resp.Code)
	assert.Equal(t, corecmp.BodyTagError, parseCMPResponseTag(t, resp.Body.Bytes()),
		"a batch exceeding the inner-message cap must be rejected, not processed")

	svc.AssertNotCalled(t, "LWCEnroll", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

// TestHandleCMP_NestedBatch_DuplicateInnerTxID verifies that a batch whose
// inner messages share a transactionID is rejected atomically with
// transactionIdInUse before any request is processed.
func TestHandleCMP_NestedBatch_DuplicateInnerTxID(t *testing.T) {
	router, _, svc := newOptionsRouter(t, models.EnrollmentOptionsLWCRFC9483{})

	sharedTx := randomTxID(t)
	inner1, _, _ := buildTestIR(t, testIROptions{CN: "dup-1", TransactionID: sharedTx})
	inner2, _, _ := buildTestIR(t, testIROptions{CN: "dup-2", TransactionID: sharedTx})

	outerTx := randomTxID(t)
	nested := buildNestedMessage(t, outerTx, randomNonce(t), inner1, inner2)

	resp := postCMP(t, router, "test-dms", nested)
	require.Equal(t, http.StatusOK, resp.Code)
	assert.Equal(t, corecmp.BodyTagError, parseCMPResponseTag(t, resp.Body.Bytes()))
	fi := parseFailInfoBitString(t, resp.Body.Bytes())
	assert.True(t, bitSet(fi, corecmp.PKIFailureInfoTransactionIDInUse), "failInfo must set transactionIdInUse (21)")

	svc.AssertNotCalled(t, "LWCEnroll", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

// TestHandleCMP_NestedBatch_OuterNonceNotFresh verifies that an outer
// senderNonce reusing one of the inner nonces is rejected with badSenderNonce
// (RFC 9483 §5.2.2.2 requires the wrapping entity to use FRESH values).
func TestHandleCMP_NestedBatch_OuterNonceNotFresh(t *testing.T) {
	router, _, svc := newOptionsRouter(t, models.EnrollmentOptionsLWCRFC9483{})

	inner1, _, _ := buildTestIR(t, testIROptions{CN: "nonce-1"})
	inner2, _, _ := buildTestIR(t, testIROptions{CN: "nonce-2"})
	innerNonce := headerOf(t, inner1).SenderNonce

	outerTx := randomTxID(t)
	nested := buildNestedMessage(t, outerTx, innerNonce, inner1, inner2)

	resp := postCMP(t, router, "test-dms", nested)
	require.Equal(t, http.StatusOK, resp.Code)
	assert.Equal(t, corecmp.BodyTagError, parseCMPResponseTag(t, resp.Body.Bytes()))
	fi := parseFailInfoBitString(t, resp.Body.Bytes())
	assert.True(t, bitSet(fi, corecmp.PKIFailureInfoBadSenderNonce), "failInfo must set badSenderNonce (18)")

	svc.AssertNotCalled(t, "LWCEnroll", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

// TestHandleCMP_NestedAddedProtection_CopyRules verifies RFC 9483 §5.2.2.1:
// the outer header of an added-protection nested message MUST copy the inner
// transactionID (mismatch → badRequest) and senderNonce (mismatch →
// badSenderNonce); with both copied the inner IR is processed normally.
func TestHandleCMP_NestedAddedProtection_CopyRules(t *testing.T) {
	issuedCert, _ := buildSelfSignedCert(t, "addedprot-device")

	newSvc := func() *cmpmock.MockLightweightCMPService {
		svc := &cmpmock.MockLightweightCMPService{}
		svc.On("LWCGetEnrollmentOptions", mock.Anything, "test-dms").
			Return(resolvedOpts(models.EnrollmentOptionsLWCRFC9483{AcceptImplicit: true}), nil)
		svc.On("LWCEnroll", mock.Anything, mock.AnythingOfType("*x509.CertificateRequest"), "test-dms", mock.Anything).
			Return(issuedCert, nil)
		return svc
	}

	inner, innerTx, _ := buildTestIR(t, testIROptions{CN: "addedprot-device", WithImplicitConfirm: true})
	innerNonce := headerOf(t, inner).SenderNonce

	t.Run("both copied → processed", func(t *testing.T) {
		router, _ := newTestRouterWithStore(newSvc())
		nested := buildNestedMessage(t, innerTx, innerNonce, inner)
		resp := postCMP(t, router, "test-dms", nested)
		require.Equal(t, http.StatusOK, resp.Code)
		assert.Equal(t, corecmp.BodyTagIP, parseCMPResponseTag(t, resp.Body.Bytes()),
			"valid added protection must yield the inner request's ip")
	})

	t.Run("transactionID not copied → badRequest", func(t *testing.T) {
		router, _ := newTestRouterWithStore(newSvc())
		otherTx := randomTxID(t)
		nested := buildNestedMessage(t, otherTx, innerNonce, inner)
		resp := postCMP(t, router, "test-dms", nested)
		require.Equal(t, http.StatusOK, resp.Code)
		assert.Equal(t, corecmp.BodyTagError, parseCMPResponseTag(t, resp.Body.Bytes()))
		fi := parseFailInfoBitString(t, resp.Body.Bytes())
		assert.True(t, bitSet(fi, corecmp.PKIFailureInfoBadRequest), "failInfo must set badRequest (2)")
	})

	t.Run("senderNonce not copied → badSenderNonce", func(t *testing.T) {
		router, _ := newTestRouterWithStore(newSvc())
		nested := buildNestedMessage(t, innerTx, randomNonce(t), inner)
		resp := postCMP(t, router, "test-dms", nested)
		require.Equal(t, http.StatusOK, resp.Code)
		assert.Equal(t, corecmp.BodyTagError, parseCMPResponseTag(t, resp.Body.Bytes()))
		fi := parseFailInfoBitString(t, resp.Body.Bytes())
		assert.True(t, bitSet(fi, corecmp.PKIFailureInfoBadSenderNonce), "failInfo must set badSenderNonce (18)")
	})
}

// TestHandleCMP_NestedAddedProtection_RespectsOperationEnabledGate is a
// security regression test: RFC011's per-operation `enabled` gates (checked
// at the top of HandleCMP before dispatch) MUST also apply to an operation
// reached via an added-protection nested envelope. Before this test, wrapping
// a p10cr in a one-element nested[20] envelope reached handleP10CR directly,
// bypassing the disabled-by-default P10CR.Enabled gate entirely — an operator
// who left p10cr disabled (the documented, security-relevant default) would
// still have it processed. See handleNestedAddedProtection in cmp_nested.go.
func TestHandleCMP_NestedAddedProtection_RespectsOperationEnabledGate(t *testing.T) {
	// P10CR.Enabled defaults to false; no explicit override here.
	router, _, svc := newOptionsRouter(t, models.EnrollmentOptionsLWCRFC9483{})

	inner, innerTx := buildTestP10CR(t, testP10CROptions{CN: "nested-disabled-p10cr"})
	innerNonce := headerOf(t, inner).SenderNonce

	nested := buildNestedMessage(t, innerTx, innerNonce, inner)
	resp := postCMP(t, router, "test-dms", nested)
	require.Equal(t, http.StatusOK, resp.Code)
	assert.Equal(t, corecmp.BodyTagError, parseCMPResponseTag(t, resp.Body.Bytes()),
		"a disabled operation reached via added-protection nesting must still be rejected")
	fi := parseFailInfoBitString(t, resp.Body.Bytes())
	assert.True(t, bitSet(fi, corecmp.PKIFailureInfoNotAuthorized), "failInfo must set notAuthorized (23)")

	svc.AssertNotCalled(t, "LWCEnroll", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

// TestHandleCMP_KUR_RAVerified_Rejected verifies RFC 9483 §5.2.3: raVerified
// MUST NOT be used in a key update request — the POP for a kur is the message
// protection with the certificate being updated, which no RA can assert.
func TestHandleCMP_KUR_RAVerified_Rejected(t *testing.T) {
	router, _, svc := newOptionsRouter(t, models.EnrollmentOptionsLWCRFC9483{})

	// buildTestKUR carries no POPO; assemble a kur whose CertReqMsg has the
	// raVerified [0] POPO by re-tagging an IR body built with that POPO mode.
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	pubKeyDER, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	require.NoError(t, err)
	irBody := buildTestIRBodyDERWithPOPO(t, "kur-raverified", pubKeyDER, privKey, "raVerified")
	var irBodyRV asn1.RawValue
	_, err = asn1.Unmarshal(irBody, &irBodyRV)
	require.NoError(t, err)
	kurBody, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassContextSpecific, Tag: corecmp.BodyTagKUR, IsCompound: true, Bytes: irBodyRV.Bytes,
	})
	require.NoError(t, err)
	txID := randomTxID(t)
	headerDER := buildTestPKIHeaderDER(t, txID, randomNonce(t), nil, false)
	kurDER, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true,
		Bytes: concatBytes(headerDER, kurBody),
	})
	require.NoError(t, err)

	// kur is now unconditionally signature-protected at the wire layer
	// (RFC 9483 §4.1.3 — the message protection IS the kur's proof of
	// possession, so an unprotected kur is rejected before any CertReqMsg
	// content, including this raVerified POPO, is even inspected). Sign with
	// an arbitrary certificate so the request reaches the raVerified-specific
	// rejection this test actually exercises.
	signerCert, signerKey := buildSelfSignedCert(t, "kur-raverified-signer")
	kurDER = signCMPMessage(t, kurDER, signerCert, signerKey)

	resp := postCMP(t, router, "test-dms", kurDER)
	require.Equal(t, http.StatusOK, resp.Code)
	assert.Equal(t, corecmp.BodyTagKUP, parseCMPResponseTag(t, resp.Body.Bytes()),
		"kur rejection must arrive in a kup CertRepMessage")
	reason, fi := parseCertRepRejection(t, resp.Body.Bytes())
	assert.Contains(t, reason, "raVerified")
	assert.True(t, bitSet(fi, corecmp.PKIFailureInfoNotAuthorized), "failInfo must set notAuthorized (23)")

	svc.AssertNotCalled(t, "LWCReenroll", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

// buildRACert issues a self-signed certificate carrying id-kp-cmcRA
// (RFC 6402), marking it as a PKI management entity for the RA-initiated
// revocation path.
func buildRACert(t *testing.T, cn string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	cert, key := buildSelfSignedCert(t, cn)
	// Re-issue with the cmcRA EKU: clone the parsed cert's template fields.
	template := &x509.Certificate{
		SerialNumber:       big.NewInt(7),
		Subject:            pkix.Name{CommonName: cn},
		NotBefore:          time.Now().Add(-time.Hour),
		NotAfter:           time.Now().Add(24 * time.Hour),
		KeyUsage:           x509.KeyUsageDigitalSignature,
		SubjectKeyId:       cert.SubjectKeyId,
		UnknownExtKeyUsage: []asn1.ObjectIdentifier{{1, 3, 6, 1, 5, 5, 7, 3, 28}}, // id-kp-cmcRA
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	raCert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return raCert, key
}

// buildTestRRWithIssuer builds an rr PKIMessage whose CertTemplate carries
// BOTH issuer and serialNumber (required for the RA-initiated revocation
// path, which revokes by reference instead of matching the signer).
func buildTestRRWithIssuer(t *testing.T, issuer pkix.Name, serial *big.Int) []byte {
	t.Helper()

	txID := randomTxID(t)
	senderNonce := randomNonce(t)
	headerDER := buildTestPKIHeaderDER(t, txID, senderNonce, nil, false)

	serialDER, err := asn1.Marshal(serial)
	require.NoError(t, err)
	serialField, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassContextSpecific, Tag: 1, IsCompound: true, Bytes: serialDER,
	})
	require.NoError(t, err)

	issuerNameDER, err := asn1.Marshal(issuer.ToRDNSequence())
	require.NoError(t, err)
	issuerField, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassContextSpecific, Tag: 3, IsCompound: true, Bytes: issuerNameDER,
	})
	require.NoError(t, err)

	certTemplateDER := seqDER(t, concatBytes(serialField, issuerField))
	revDetailsDER := seqDER(t, certTemplateDER)
	revReqContentDER := seqDER(t, revDetailsDER)

	bodyDER, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        corecmp.BodyTagRR,
		IsCompound: true,
		Bytes:      revReqContentDER,
	})
	require.NoError(t, err)

	msgDER, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      concatBytes(headerDER, bodyDER),
	})
	require.NoError(t, err)
	return msgDER
}

// TestHandleCMP_RR_TrustedRA_RevokesOtherCert verifies RFC 9483 §5.3.2 at the
// controller layer: an rr signed by a certificate carrying id-kp-cmcRA whose
// CertTemplate references a DIFFERENT certificate skips the signer-match
// checks and reaches LWCRevokeCertificate with the referenced serial (the
// service layer is responsible for chain-validating the RA).
func TestHandleCMP_RR_TrustedRA_RevokesOtherCert(t *testing.T) {
	raCert, raKey := buildRACert(t, "trusted-ra")
	targetSerial := big.NewInt(0x99)

	svc := &cmpmock.MockLightweightCMPService{}
	svc.On("LWCGetEnrollmentOptions", mock.Anything, "test-dms").
		Return(resolvedOpts(models.EnrollmentOptionsLWCRFC9483{}), nil)
	svc.On("LWCRevokeCertificate", mock.Anything, mock.MatchedBy(func(in services.RevokeCertificateInput) bool {
		return in.SerialNumber == hex.EncodeToString(targetSerial.Bytes())
	}), mock.Anything).Return(nil)

	router, _ := newTestRouterWithStore(svc)
	rrDER := buildTestRRWithIssuer(t, pkix.Name{CommonName: "Some Issuing CA"}, targetSerial)
	signedRR := signCMPMessage(t, rrDER, raCert, raKey)

	resp := postCMP(t, router, "test-dms", signedRR)
	require.Equal(t, http.StatusOK, resp.Code)
	assert.Equal(t, corecmp.BodyTagRP, parseCMPResponseTag(t, resp.Body.Bytes()),
		"RA-initiated revocation must be accepted and answered with rp")

	svc.AssertExpectations(t)
}

// TestHandleCMP_RR_NonRASigner_StillMatched verifies the RA bypass does NOT
// apply to ordinary signers: an rr whose template references another cert but
// whose signer lacks id-kp-cmcRA keeps the strict signer-match and is rejected.
func TestHandleCMP_RR_NonRASigner_StillMatched(t *testing.T) {
	eeCert, eeKey := buildSelfSignedCert(t, "plain-ee")

	router, _, svc := newOptionsRouter(t, models.EnrollmentOptionsLWCRFC9483{})
	rrDER := buildTestRRWithIssuer(t, pkix.Name{CommonName: "Some Issuing CA"}, big.NewInt(0x99))
	signedRR := signCMPMessage(t, rrDER, eeCert, eeKey)

	resp := postCMP(t, router, "test-dms", signedRR)
	require.Equal(t, http.StatusOK, resp.Code)
	assert.Equal(t, corecmp.BodyTagRP, parseCMPResponseTag(t, resp.Body.Bytes()))
	fi := parseRevRepFailInfo(t, resp.Body.Bytes())
	assert.True(t, bitSet(fi, corecmp.PKIFailureInfoBadCertID), "failInfo must set badCertId (4)")

	svc.AssertNotCalled(t, "LWCRevokeCertificate", mock.Anything, mock.Anything, mock.Anything)
}

// parseRevRepFailInfo extracts the PKIFailureInfo BIT STRING from the first
// PKIStatusInfo of an rp (RevRepContent) response body.
func parseRevRepFailInfo(t *testing.T, responseDER []byte) asn1.BitString {
	t.Helper()
	var msg corecmp.RawPKIMessage
	_, err := asn1.Unmarshal(responseDER, &msg)
	require.NoError(t, err)
	require.Equal(t, corecmp.BodyTagRP, msg.Body.Tag)

	// RevRepContent ::= SEQUENCE { status SEQUENCE OF PKIStatusInfo, ... }
	var revRep asn1.RawValue
	_, err = asn1.Unmarshal(msg.Body.Bytes, &revRep)
	require.NoError(t, err)
	var statusSeqOf asn1.RawValue
	_, err = asn1.Unmarshal(revRep.Bytes, &statusSeqOf)
	require.NoError(t, err)
	var psi corecmp.PKIStatusInfo
	_, err = asn1.Unmarshal(statusSeqOf.Bytes, &psi)
	require.NoError(t, err)
	return psi.FailInfo
}
