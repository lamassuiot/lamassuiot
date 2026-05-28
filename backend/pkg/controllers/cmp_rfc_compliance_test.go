package controllers

// RFC compliance tests for CMP v3 critical fixes C1–C10.
//
// These tests encode the normative MUST/MUST NOT requirements from:
//   - RFC 9810 (CMP core, obsoletes RFC 4210/RFC 9480)
//   - RFC 9483 (Lightweight CMP Profile)
//   - RFC 9481 (CMP Algorithms)
//
// Each test cites the exact section it enforces. Tests are intentionally
// written BEFORE the implementation changes (TDD) — they must fail against
// the pre-fix codebase and pass after the matching fix lands.

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"math/big"
	"net/http"
	"testing"
	"time"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	cmpmock "github.com/lamassuiot/lamassuiot/core/v3/pkg/services/mock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Test helpers specific to the C1–C10 RFC compliance suite
// ---------------------------------------------------------------------------

// headerOpts allows callers to override every PKIHeader field that the legacy
// buildTestPKIHeaderDER hard-codes. Used by C1–C5 tests to exercise field
// values the standard builder never produces (e.g. pvno=3, short nonces).
//
// PVNO uses *int so a test can distinguish "not set" (use cmp2000 default)
// from "set to 0" (exercise unsupportedVersion path). Same idea for nil
// slices vs explicit empty/short slices.
type headerOpts struct {
	PVNO                *int
	TransactionID       []byte
	SenderNonce         []byte
	RecipNonce          []byte
	OmitTransactionID   bool
	OmitSenderNonce     bool
	WithImplicitConfirm bool
}

func intPtr(v int) *int { return &v }

// buildHeaderDERCustom encodes a PKIHeader with custom field control, used
// only by the RFC-compliance suite.
func buildHeaderDERCustom(t *testing.T, o headerOpts) []byte {
	t.Helper()

	pvno := pvnoCMP2000
	if o.PVNO != nil {
		pvno = *o.PVNO
	}
	pvnoDER, err := asn1.Marshal(pvno)
	require.NoError(t, err)

	emptyName, err := asn1.Marshal(pkix.RDNSequence{})
	require.NoError(t, err)
	senderDER, err := asn1.MarshalWithParams(asn1.RawValue{FullBytes: emptyName}, "tag:4")
	require.NoError(t, err)
	recipientDER := senderDER

	content := concatBytes(pvnoDER, senderDER, recipientDER)

	if !o.OmitTransactionID {
		txID := o.TransactionID
		if txID == nil {
			txID = make([]byte, 16)
			_, _ = rand.Read(txID)
		}
		txInner, err := asn1.Marshal(txID)
		require.NoError(t, err)
		txField, err := asn1.Marshal(asn1.RawValue{
			Class: asn1.ClassContextSpecific, Tag: 4, IsCompound: true, Bytes: txInner,
		})
		require.NoError(t, err)
		content = append(content, txField...)
	}

	if !o.OmitSenderNonce {
		nonce := o.SenderNonce
		if nonce == nil {
			nonce = make([]byte, 16)
			_, _ = rand.Read(nonce)
		}
		nonceInner, err := asn1.Marshal(nonce)
		require.NoError(t, err)
		nonceField, err := asn1.Marshal(asn1.RawValue{
			Class: asn1.ClassContextSpecific, Tag: 5, IsCompound: true, Bytes: nonceInner,
		})
		require.NoError(t, err)
		content = append(content, nonceField...)
	}

	if len(o.RecipNonce) > 0 {
		recipNonceInner, err := asn1.Marshal(o.RecipNonce)
		require.NoError(t, err)
		recipNonceField, err := asn1.Marshal(asn1.RawValue{
			Class: asn1.ClassContextSpecific, Tag: 6, IsCompound: true, Bytes: recipNonceInner,
		})
		require.NoError(t, err)
		content = append(content, recipNonceField...)
	}

	if o.WithImplicitConfirm {
		content = append(content, buildImplicitConfirmGeneralInfo(t)...)
	}

	headerDER, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: content,
	})
	require.NoError(t, err)
	return headerDER
}

// buildIRWithHeader assembles a full IR PKIMessage using a fully-controlled
// header. The body is a minimal IR with no POPO.
func buildIRWithHeader(t *testing.T, headerDER []byte, cn string) []byte {
	t.Helper()
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	pubKeyDER, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	require.NoError(t, err)

	bodyDER := buildTestIRBodyDER(t, cn, pubKeyDER)
	msgDER, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true,
		Bytes: concatBytes(headerDER, bodyDER),
	})
	require.NoError(t, err)
	return msgDER
}

// parseResponsePVNO extracts the pvno field from a response PKIMessage.
func parseResponsePVNO(t *testing.T, responseDER []byte) int {
	t.Helper()
	type rawMsg struct {
		Header asn1.RawValue
		Body   asn1.RawValue
	}
	var msg rawMsg
	_, err := asn1.Unmarshal(responseDER, &msg)
	require.NoError(t, err, "response must be a valid DER PKIMessage")

	var headerSeq asn1.RawValue
	_, err = asn1.Unmarshal(msg.Header.FullBytes, &headerSeq)
	require.NoError(t, err)

	var pvno int
	_, err = asn1.Unmarshal(headerSeq.Bytes, &pvno)
	require.NoError(t, err)
	return pvno
}

// parseResponseHeaderMessageTime extracts the optional messageTime [0]
// GeneralizedTime from a response header. Returns the zero time when absent.
func parseResponseHeaderMessageTime(t *testing.T, responseDER []byte) time.Time {
	t.Helper()
	type rawMsg struct {
		Header asn1.RawValue
		Body   asn1.RawValue
	}
	var msg rawMsg
	_, err := asn1.Unmarshal(responseDER, &msg)
	require.NoError(t, err)

	var headerSeq asn1.RawValue
	_, err = asn1.Unmarshal(msg.Header.FullBytes, &headerSeq)
	require.NoError(t, err)

	remaining := headerSeq.Bytes
	// Skip pvno, sender, recipient.
	for i := 0; i < 3; i++ {
		var f asn1.RawValue
		remaining, err = asn1.Unmarshal(remaining, &f)
		require.NoError(t, err)
	}
	for len(remaining) > 0 {
		var f asn1.RawValue
		remaining, err = asn1.Unmarshal(remaining, &f)
		require.NoError(t, err)
		if f.Class == asn1.ClassContextSpecific && f.Tag == 0 {
			var ts time.Time
			_, err = asn1.UnmarshalWithParams(f.FullBytes, &ts, "generalized,explicit,tag:0")
			require.NoError(t, err)
			return ts
		}
	}
	return time.Time{}
}

// parseFailInfoBitString extracts the PKIFailureInfo BitString from an error
// PKIMessage body and returns it. Returns an empty BitString when no failInfo
// is present.
func parseFailInfoBitString(t *testing.T, responseDER []byte) asn1.BitString {
	t.Helper()
	type rawMsg struct {
		Header asn1.RawValue
		Body   asn1.RawValue
	}
	var msg rawMsg
	_, err := asn1.Unmarshal(responseDER, &msg)
	require.NoError(t, err)
	require.Equal(t, cmpBodyTagError, msg.Body.Tag, "expected error PKIMessage")

	var errMsg asn1.RawValue
	_, err = asn1.Unmarshal(msg.Body.Bytes, &errMsg)
	require.NoError(t, err)

	// errMsg.Bytes = PKIStatusInfo SEQUENCE { status, statusString?, failInfo? }
	var psi asn1.RawValue
	_, err = asn1.Unmarshal(errMsg.Bytes, &psi)
	require.NoError(t, err)

	rest := psi.Bytes
	for len(rest) > 0 {
		var f asn1.RawValue
		rest, err = asn1.Unmarshal(rest, &f)
		require.NoError(t, err)
		if f.Tag == asn1.TagBitString && f.Class == asn1.ClassUniversal {
			var bs asn1.BitString
			_, err = asn1.Unmarshal(f.FullBytes, &bs)
			require.NoError(t, err)
			return bs
		}
	}
	return asn1.BitString{}
}

// bitSet reports whether `bit` (RFC 4210 §5.1.3 bit numbering) is set in bs.
func bitSet(bs asn1.BitString, bit int) bool {
	if bit/8 >= len(bs.Bytes) {
		return false
	}
	return bs.Bytes[bit/8]&(0x80>>uint(bit%8)) != 0
}

// parseResponseSenderKID extracts the senderKID [2] OCTET STRING from a
// response header. Returns nil when absent.
func parseResponseSenderKID(t *testing.T, responseDER []byte) []byte {
	t.Helper()
	type rawMsg struct {
		Header asn1.RawValue
		Body   asn1.RawValue
	}
	var msg rawMsg
	_, err := asn1.Unmarshal(responseDER, &msg)
	require.NoError(t, err)

	var headerSeq asn1.RawValue
	_, err = asn1.Unmarshal(msg.Header.FullBytes, &headerSeq)
	require.NoError(t, err)

	remaining := headerSeq.Bytes
	// Skip pvno, sender, recipient.
	for i := 0; i < 3; i++ {
		var f asn1.RawValue
		remaining, err = asn1.Unmarshal(remaining, &f)
		require.NoError(t, err)
	}
	for len(remaining) > 0 {
		var f asn1.RawValue
		remaining, err = asn1.Unmarshal(remaining, &f)
		require.NoError(t, err)
		if f.Class == asn1.ClassContextSpecific && f.Tag == 2 {
			// senderKID [2] EXPLICIT OCTET STRING — unwrap one level.
			var inner []byte
			if _, err := asn1.Unmarshal(f.Bytes, &inner); err == nil {
				return inner
			}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// C1 — PVNO version negotiation (RFC 9810 §7, RFC 9483 §3.1)
// ---------------------------------------------------------------------------

// TestC1_PVNO_Request2_Response2 — baseline: cmp2000 request, cmp2000 response.
// RFC 9810 §7: "the version of the response message MUST be the same as the
// received version".
func TestC1_PVNO_Request2_Response2(t *testing.T) {
	issuedCert, _ := buildSelfSignedCert(t, "device-pvno-2")

	svc := &cmpmock.MockLightweightCMPService{}
	svc.On("LWCGetEnrollmentOptions", mock.Anything, "test-dms").
		Return(&models.EnrollmentOptionsLWCRFC9483{AcceptImplicit: true}, nil)
	svc.On("LWCEnroll", mock.Anything, mock.AnythingOfType("*x509.CertificateRequest"), "test-dms").
		Return(issuedCert, nil)

	router, _ := newTestRouterWithStore(svc)
	header := buildHeaderDERCustom(t, headerOpts{
		PVNO:                intPtr(pvnoCMP2000),
		WithImplicitConfirm: true,
	})
	irDER := buildIRWithHeader(t, header, "device-pvno-2")

	resp := postCMP(t, router, "test-dms", irDER)
	require.Equal(t, http.StatusOK, resp.Code)
	assert.Equal(t, pvnoCMP2000, parseResponsePVNO(t, resp.Body.Bytes()),
		"response pvno MUST equal request pvno (cmp2000)")
}

// TestC1_PVNO_Request3_Response3 — cmp2021 request MUST get cmp2021 response.
// RFC 9810 §7 (line 3754): "If a server receives a message with a version that
// it supports, then the version of the response message MUST be the same as
// the received version."
func TestC1_PVNO_Request3_Response3(t *testing.T) {
	issuedCert, _ := buildSelfSignedCert(t, "device-pvno-3")

	svc := &cmpmock.MockLightweightCMPService{}
	svc.On("LWCGetEnrollmentOptions", mock.Anything, "test-dms").
		Return(&models.EnrollmentOptionsLWCRFC9483{AcceptImplicit: true}, nil)
	svc.On("LWCEnroll", mock.Anything, mock.AnythingOfType("*x509.CertificateRequest"), "test-dms").
		Return(issuedCert, nil)

	router, _ := newTestRouterWithStore(svc)
	header := buildHeaderDERCustom(t, headerOpts{
		PVNO:                intPtr(pvnoCMP2021),
		WithImplicitConfirm: true,
	})
	irDER := buildIRWithHeader(t, header, "device-pvno-3")

	resp := postCMP(t, router, "test-dms", irDER)
	require.Equal(t, http.StatusOK, resp.Code)
	assert.Equal(t, pvnoCMP2021, parseResponsePVNO(t, resp.Body.Bytes()),
		"response pvno MUST equal request pvno (cmp2021)")
}

// TestC1_PVNO_UnsupportedVersion_RejectedWithFailInfo — pvno outside {2,3}.
// RFC 9810 §7 (line 3756): "If a server receives a message with a version
// higher [...] than it supports, then it MUST send back an ErrorMsg with the
// unsupportedVersion bit set."
// RFC 9483 §3.5 line 946: "The pvno MUST be cmp2000(2) or cmp2021(3).
// (failInfo bit: unsupportedVersion)".
func TestC1_PVNO_UnsupportedVersion_RejectedWithFailInfo(t *testing.T) {
	svc := &cmpmock.MockLightweightCMPService{}
	svc.On("LWCGetEnrollmentOptions", mock.Anything, "test-dms").
		Return(&models.EnrollmentOptionsLWCRFC9483{}, nil)

	router, _ := newTestRouterWithStore(svc)

	for _, badPVNO := range []int{1, 0, 99} {
		bad := badPVNO
		t.Run("pvno="+string(rune('0'+badPVNO)), func(t *testing.T) {
			header := buildHeaderDERCustom(t, headerOpts{PVNO: &bad})
			irDER := buildIRWithHeader(t, header, "device-bad-pvno")

			resp := postCMP(t, router, "test-dms", irDER)
			require.Equal(t, http.StatusOK, resp.Code)
			assert.Equal(t, cmpBodyTagError, parseCMPResponseTag(t, resp.Body.Bytes()),
				"unsupported pvno MUST yield an error PKIMessage")

			bs := parseFailInfoBitString(t, resp.Body.Bytes())
			assert.True(t, bitSet(bs, pkiFailureInfoUnsupportedVersion),
				"failInfo bit unsupportedVersion (16) MUST be set per RFC 9810 §7")
		})
	}

	svc.AssertNotCalled(t, "LWCEnroll", mock.Anything, mock.Anything, mock.Anything)
}

// ---------------------------------------------------------------------------
// C2 — messageTime present on every response (RFC 9483 §3.1, line 725)
// ---------------------------------------------------------------------------

// TestC2_MessageTime_UnprotectedResponseIncludesIt — RFC 9483 §3.1 line 725:
// "MUST be the time at which the message was produced, if present." We choose
// to always emit it so the EE can synchronise its clock (line 1024).
func TestC2_MessageTime_UnprotectedResponseIncludesIt(t *testing.T) {
	issuedCert, _ := buildSelfSignedCert(t, "device-msgtime")

	svc := &cmpmock.MockLightweightCMPService{}
	svc.On("LWCGetEnrollmentOptions", mock.Anything, "test-dms").
		Return(&models.EnrollmentOptionsLWCRFC9483{AcceptImplicit: true}, nil)
	svc.On("LWCEnroll", mock.Anything, mock.AnythingOfType("*x509.CertificateRequest"), "test-dms").
		Return(issuedCert, nil)

	router, _ := newTestRouterWithStore(svc)
	irDER, _, _ := buildTestIR(t, testIROptions{CN: "device-msgtime", WithImplicitConfirm: true})

	before := time.Now().Add(-time.Minute)
	resp := postCMP(t, router, "test-dms", irDER)
	after := time.Now().Add(time.Minute)
	require.Equal(t, http.StatusOK, resp.Code)

	ts := parseResponseHeaderMessageTime(t, resp.Body.Bytes())
	require.False(t, ts.IsZero(), "messageTime MUST be present on unprotected responses")
	assert.True(t, ts.After(before) && ts.Before(after),
		"messageTime must reflect current server time")
}

// ---------------------------------------------------------------------------
// C3 — senderNonce ≥128 bits (RFC 9483 §3.5 line 959, RFC 9810 §5.1.1)
// ---------------------------------------------------------------------------

// TestC3_SenderNonce_TooShort_RejectedBadSenderNonce — RFC 9483 §3.5 line 959:
// "The senderNonce MUST be present and MUST contain at least 128 bits of data.
// (failInfo bit: badSenderNonce)".
func TestC3_SenderNonce_TooShort_RejectedBadSenderNonce(t *testing.T) {
	svc := &cmpmock.MockLightweightCMPService{}
	svc.On("LWCGetEnrollmentOptions", mock.Anything, "test-dms").
		Return(&models.EnrollmentOptionsLWCRFC9483{}, nil)

	router, _ := newTestRouterWithStore(svc)
	header := buildHeaderDERCustom(t, headerOpts{
		SenderNonce: []byte{0xAA, 0xBB}, // 16 bits — too short
	})
	irDER := buildIRWithHeader(t, header, "device-short-nonce")

	resp := postCMP(t, router, "test-dms", irDER)
	require.Equal(t, http.StatusOK, resp.Code)
	assert.Equal(t, cmpBodyTagError, parseCMPResponseTag(t, resp.Body.Bytes()))

	bs := parseFailInfoBitString(t, resp.Body.Bytes())
	assert.True(t, bitSet(bs, pkiFailureInfoBadSenderNonce),
		"failInfo bit badSenderNonce (18) MUST be set per RFC 9483 §3.5")

	svc.AssertNotCalled(t, "LWCEnroll", mock.Anything, mock.Anything, mock.Anything)
}

// TestC3_SenderNonce_Missing_Rejected — RFC 9483 §3.5: "The senderNonce MUST
// be present".
func TestC3_SenderNonce_Missing_Rejected(t *testing.T) {
	svc := &cmpmock.MockLightweightCMPService{}
	svc.On("LWCGetEnrollmentOptions", mock.Anything, "test-dms").
		Return(&models.EnrollmentOptionsLWCRFC9483{}, nil)

	router, _ := newTestRouterWithStore(svc)
	header := buildHeaderDERCustom(t, headerOpts{OmitSenderNonce: true})
	irDER := buildIRWithHeader(t, header, "device-no-nonce")

	resp := postCMP(t, router, "test-dms", irDER)
	require.Equal(t, http.StatusOK, resp.Code)
	assert.Equal(t, cmpBodyTagError, parseCMPResponseTag(t, resp.Body.Bytes()))

	bs := parseFailInfoBitString(t, resp.Body.Bytes())
	assert.True(t, bitSet(bs, pkiFailureInfoBadSenderNonce),
		"missing senderNonce MUST set badSenderNonce per RFC 9483 §3.5")
}

// ---------------------------------------------------------------------------
// C4 — transactionID ≥128 bits in first message (RFC 9483 §3.1 line 747)
// ---------------------------------------------------------------------------

// TestC4_TransactionID_TooShort_Rejected — RFC 9483 §3.1 line 747:
// "In the first message of a PKI management operation, MUST be 128 bits of
// random data".
func TestC4_TransactionID_TooShort_Rejected(t *testing.T) {
	svc := &cmpmock.MockLightweightCMPService{}
	svc.On("LWCGetEnrollmentOptions", mock.Anything, "test-dms").
		Return(&models.EnrollmentOptionsLWCRFC9483{}, nil)

	router, _ := newTestRouterWithStore(svc)
	header := buildHeaderDERCustom(t, headerOpts{
		TransactionID: []byte{0x01, 0x02, 0x03, 0x04}, // 32 bits — too short
	})
	irDER := buildIRWithHeader(t, header, "device-short-tx")

	resp := postCMP(t, router, "test-dms", irDER)
	require.Equal(t, http.StatusOK, resp.Code)
	assert.Equal(t, cmpBodyTagError, parseCMPResponseTag(t, resp.Body.Bytes()))

	bs := parseFailInfoBitString(t, resp.Body.Bytes())
	assert.True(t, bitSet(bs, pkiFailureInfoBadDataFormat),
		"short/malformed transactionID MUST set badDataFormat per RFC 9483 §3.5")
}

// TestC4_TransactionID_Missing_Rejected — RFC 9483 §3.5 line 949:
// "The transactionID MUST be present. (failInfo bit: badDataFormat)".
func TestC4_TransactionID_Missing_Rejected(t *testing.T) {
	svc := &cmpmock.MockLightweightCMPService{}
	svc.On("LWCGetEnrollmentOptions", mock.Anything, "test-dms").
		Return(&models.EnrollmentOptionsLWCRFC9483{}, nil)

	router, _ := newTestRouterWithStore(svc)
	header := buildHeaderDERCustom(t, headerOpts{OmitTransactionID: true})
	irDER := buildIRWithHeader(t, header, "device-no-tx")

	resp := postCMP(t, router, "test-dms", irDER)
	require.Equal(t, http.StatusOK, resp.Code)
	assert.Equal(t, cmpBodyTagError, parseCMPResponseTag(t, resp.Body.Bytes()))
}

// ---------------------------------------------------------------------------
// C5 — response recipNonce echoes request senderNonce (RFC 9810 §5.1.1)
// ---------------------------------------------------------------------------

// TestC5_RecipNonce_EchoesRequestSenderNonce — the response's recipNonce MUST
// equal the request's senderNonce (RFC 9810 §5.1.1 / RFC 9483 §3.1 line 753).
// This is already covered by TestBuildResponseHeader; here we verify the full
// HTTP pipeline preserves it (with a valid-length nonce so we don't hit C3).
func TestC5_RecipNonce_EchoesRequestSenderNonce(t *testing.T) {
	issuedCert, _ := buildSelfSignedCert(t, "device-c5")

	svc := &cmpmock.MockLightweightCMPService{}
	svc.On("LWCGetEnrollmentOptions", mock.Anything, "test-dms").
		Return(&models.EnrollmentOptionsLWCRFC9483{AcceptImplicit: true}, nil)
	svc.On("LWCEnroll", mock.Anything, mock.AnythingOfType("*x509.CertificateRequest"), "test-dms").
		Return(issuedCert, nil)

	router, _ := newTestRouterWithStore(svc)

	knownNonce := make([]byte, 16)
	for i := range knownNonce {
		knownNonce[i] = byte(i + 1)
	}
	header := buildHeaderDERCustom(t, headerOpts{
		SenderNonce:         knownNonce,
		WithImplicitConfirm: true,
	})
	irDER := buildIRWithHeader(t, header, "device-c5")

	resp := postCMP(t, router, "test-dms", irDER)
	require.Equal(t, http.StatusOK, resp.Code)

	respRecipNonce := extractResponseRecipNonce(t, resp.Body.Bytes())
	assert.Equal(t, knownNonce, respRecipNonce,
		"response recipNonce MUST equal request senderNonce (RFC 9810 §5.1.1)")
}

func extractResponseRecipNonce(t *testing.T, responseDER []byte) []byte {
	t.Helper()
	type rawMsg struct {
		Header asn1.RawValue
		Body   asn1.RawValue
	}
	var msg rawMsg
	_, err := asn1.Unmarshal(responseDER, &msg)
	require.NoError(t, err)

	var headerSeq asn1.RawValue
	_, err = asn1.Unmarshal(msg.Header.FullBytes, &headerSeq)
	require.NoError(t, err)

	remaining := headerSeq.Bytes
	for i := 0; i < 3; i++ {
		var f asn1.RawValue
		remaining, err = asn1.Unmarshal(remaining, &f)
		require.NoError(t, err)
	}
	for len(remaining) > 0 {
		var f asn1.RawValue
		remaining, err = asn1.Unmarshal(remaining, &f)
		require.NoError(t, err)
		if f.Class == asn1.ClassContextSpecific && f.Tag == 6 {
			var inner []byte
			if _, err := asn1.Unmarshal(f.Bytes, &inner); err == nil {
				return inner
			}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// C6 — full failInfo bit coverage (RFC 9810 §5.1.3 / RFC 9483 §3.6.4)
// ---------------------------------------------------------------------------

// TestC6_FailInfo_ProtectionVerificationFailure_BadMessageCheck — RFC 9483
// §3.6.4: protection verification failure MUST set badMessageCheck (bit 1).
func TestC6_FailInfo_ProtectionVerificationFailure_BadMessageCheck(t *testing.T) {
	signerCert, signerKey := buildSelfSignedCert(t, "signer-c6")

	svc := &cmpmock.MockLightweightCMPService{}
	svc.On("LWCGetEnrollmentOptions", mock.Anything, "test-dms").
		Return(&models.EnrollmentOptionsLWCRFC9483{}, nil)

	router, _ := newTestRouterWithStore(svc)
	irDER, _, _ := buildTestIR(t, testIROptions{CN: "device-c6-bad-sig"})
	signedIR := signCMPMessage(t, irDER, signerCert, signerKey)

	// Corrupt the protection signature itself by flipping the last byte of the
	// outer SEQUENCE — that byte is inside the protection [0] BIT STRING
	// payload (the signature octets), which is NOT covered by the signature
	// computation but IS what the server verifies against the EE pubkey.
	// Flipping it invalidates the signature without corrupting any ASN.1 tags
	// or lengths, so the message parses cleanly and the failure mode is
	// guaranteed to be "bad signature → badMessageCheck" rather than
	// "malformed → badDataFormat".
	corrupted := corruptProtectionSignature(t, signedIR)

	resp := postCMP(t, router, "test-dms", corrupted)
	require.Equal(t, http.StatusOK, resp.Code)
	require.Equal(t, cmpBodyTagError, parseCMPResponseTag(t, resp.Body.Bytes()),
		"corrupted protection signature must yield CMP error body")

	bs := parseFailInfoBitString(t, resp.Body.Bytes())
	assert.True(t, bitSet(bs, pkiFailureInfoBadMessageCheck),
		"protection verify failure MUST set badMessageCheck (1) per RFC 9483 §3.6.4")
}

// TestC6_FailInfo_POPOFailure_BadPOP — POPO verification failure MUST set
// badPOP (bit 9) per RFC 9810 §5.1.3. The response uses an ip CertRepMessage
// body (not the error body) per RFC 9483 §4.1.
func TestC6_FailInfo_POPOFailure_BadPOP(t *testing.T) {
	svc := &cmpmock.MockLightweightCMPService{}
	svc.On("LWCGetEnrollmentOptions", mock.Anything, "test-dms").
		Return(&models.EnrollmentOptionsLWCRFC9483{EnforcePOPO: true}, nil)

	router, _ := newTestRouterWithStore(svc)
	irDER, _, _ := buildTestIR(t, testIROptions{
		CN:       "device-c6-bad-popo",
		POPOMode: "badsig",
	})

	resp := postCMP(t, router, "test-dms", irDER)
	require.Equal(t, http.StatusOK, resp.Code)
	require.Equal(t, cmpBodyTagIP, parseCMPResponseTag(t, resp.Body.Bytes()),
		"POPO failure must respond with ip CertRepMessage (RFC 9483 §4.1)")

	_, bs := parseCertRepRejection(t, resp.Body.Bytes())
	assert.True(t, bitSet(bs, pkiFailureInfoBadPOP),
		"POPO failure MUST set badPOP (9) per RFC 9810 §5.1.3")

	svc.AssertNotCalled(t, "LWCEnroll", mock.Anything, mock.Anything, mock.Anything)
}

// ---------------------------------------------------------------------------
// C7 — certHash defaulting depends on cert sig alg (RFC 9481 §3.3 / RFC 9810
// §5.1.3.2)
// ---------------------------------------------------------------------------

// TestC7_ComputeCertHash_DefaultECDSAP256_SHA256 — baseline: when hashAlg is
// absent and the cert was issued under ECDSA-with-SHA256, default to SHA-256.
func TestC7_ComputeCertHash_DefaultECDSAP256_SHA256(t *testing.T) {
	certDER := buildSelfSignedECDSACert(t, elliptic.P256())
	got, err := computeCertHash(certDER, nil)
	require.NoError(t, err)
	want := sha256.Sum256(certDER)
	assert.Equal(t, want[:], got, "ECDSA-P256 cert defaults to SHA-256")
}

// TestC7_ComputeCertHash_DefaultECDSAP384_SHA384 — RFC 9481 §3.3: SHA-384 is
// the implicit default for certs signed with ECDSA-with-SHA384.
func TestC7_ComputeCertHash_DefaultECDSAP384_SHA384(t *testing.T) {
	certDER := buildSelfSignedECDSACert(t, elliptic.P384())
	got, err := computeCertHash(certDER, nil)
	require.NoError(t, err)
	want := sha512.Sum384(certDER)
	assert.Equal(t, want[:], got,
		"ECDSA-P384 cert defaults to SHA-384 per RFC 9481 §3.3")
}

// TestC7_ComputeCertHash_DefaultECDSAP521_SHA512 — SHA-512 default for P-521.
func TestC7_ComputeCertHash_DefaultECDSAP521_SHA512(t *testing.T) {
	certDER := buildSelfSignedECDSACert(t, elliptic.P521())
	got, err := computeCertHash(certDER, nil)
	require.NoError(t, err)
	want := sha512.Sum512(certDER)
	assert.Equal(t, want[:], got,
		"ECDSA-P521 cert defaults to SHA-512 per RFC 9481 §3.3")
}

func buildSelfSignedECDSACert(t *testing.T, curve elliptic.Curve) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "c7-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	return certDER
}

// ---------------------------------------------------------------------------
// C8 — protectionAlg.parameters captured; PSS / unknown algs handled (RFC 9481 §3)
// ---------------------------------------------------------------------------

// TestC8_DecodeRequestHeader_CapturesProtectionAlgParameters — the parsed
// header must preserve the full AlgorithmIdentifier (including any params)
// so PSS / future algs that depend on parameters can be verified. RFC 9483
// §3.1 line 731 requires protectionAlg type-consistency, which is only
// checkable when parameters are available.
func TestC8_DecodeRequestHeader_CapturesProtectionAlgParameters(t *testing.T) {
	// Build a header containing protectionAlg [1] with non-NULL parameters
	// (use sha256WithRSAEncryption + NULL params, but assert via the parsed
	// AlgorithmIdentifier rather than just the OID).
	pvnoDER, _ := asn1.Marshal(pvnoCMP2000)
	emptyName, _ := asn1.Marshal(pkix.RDNSequence{})
	senderDER, _ := asn1.MarshalWithParams(asn1.RawValue{FullBytes: emptyName}, "tag:4")

	algID := pkix.AlgorithmIdentifier{
		Algorithm:  asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}, // sha256WithRSA
		Parameters: asn1.NullRawValue,
	}
	algDER, err := asn1.Marshal(algID)
	require.NoError(t, err)
	protAlgField, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassContextSpecific, Tag: 1, IsCompound: true, Bytes: algDER,
	})
	require.NoError(t, err)

	txID := make([]byte, 16)
	rand.Read(txID)
	txInner, _ := asn1.Marshal(txID)
	txField, _ := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassContextSpecific, Tag: 4, IsCompound: true, Bytes: txInner,
	})

	headerContent := concatBytes(pvnoDER, senderDER, senderDER, protAlgField, txField)
	headerDER, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: headerContent,
	})
	require.NoError(t, err)

	parsed, err := decodeRequestHeader(headerDER)
	require.NoError(t, err)
	require.NotNil(t, parsed.ProtectionAlg.Algorithm, "ProtectionAlg.Algorithm must be parsed")
	assert.True(t, parsed.ProtectionAlg.Algorithm.Equal(algID.Algorithm),
		"ProtectionAlg.Algorithm OID must match input")
	assert.NotZero(t, len(parsed.ProtectionAlg.Parameters.FullBytes),
		"ProtectionAlg.Parameters must be captured (RFC 4055 PSS depends on it)")
}

// ---------------------------------------------------------------------------
// C9 — senderKID emitted on signed responses (RFC 9483 §3.1 line 740)
// ---------------------------------------------------------------------------

// TestC9_SenderKID_ProtectedResponseIncludesSKI — RFC 9483 §3.1 line 740:
// "For signature-based protection, MUST be used and contain the value of the
// SubjectKeyIdentifier if present in the CMP protection certificate".
func TestC9_SenderKID_ProtectedResponseIncludesSKI(t *testing.T) {
	issuedCert, _ := buildSelfSignedCert(t, "device-c9")
	signerCert, signerKey := buildSelfSignedCertWithSKI(t, "signer-c9")

	svc := &cmpmock.MockLightweightCMPServiceWithProtection{}
	svc.On("LWCGetEnrollmentOptions", mock.Anything, "test-dms").
		Return(&models.EnrollmentOptionsLWCRFC9483{AcceptImplicit: true}, nil)
	svc.On("LWCEnroll", mock.Anything, mock.AnythingOfType("*x509.CertificateRequest"), "test-dms").
		Return(issuedCert, nil)
	svc.On("LWCProtectionCredentials", mock.Anything, "test-dms").
		Return([]*x509.Certificate{signerCert}, crypto.Signer(signerKey), nil)

	router, _ := newTestRouterWithProtectionAndStore(svc)
	irDER, _, _ := buildTestIR(t, testIROptions{CN: "device-c9", WithImplicitConfirm: true})

	resp := postCMP(t, router, "test-dms", irDER)
	require.Equal(t, http.StatusOK, resp.Code)

	gotKID := parseResponseSenderKID(t, resp.Body.Bytes())
	require.NotNil(t, gotKID, "senderKID MUST be present on signed responses (RFC 9483 §3.1)")
	assert.Equal(t, signerCert.SubjectKeyId, gotKID,
		"senderKID MUST equal SubjectKeyIdentifier of the protection cert")
}

func buildSelfSignedCertWithSKI(t *testing.T, cn string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	pubKeyDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)
	skiHash := sha256.Sum256(pubKeyDER)
	ski := skiHash[:20]

	template := &x509.Certificate{
		SerialNumber: big.NewInt(99),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		SubjectKeyId: ski,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert, key
}

// ---------------------------------------------------------------------------
// C10 — SHA-1 (and SHA-224) rejected as MSG_SIG_ALG (RFC 9481 §2 / §3)
// ---------------------------------------------------------------------------

// TestC10_HashFromSignatureAlgOID_SHA1_Rejected — unit test: the OID-to-hash
// mapper MUST reject sha1WithRSAEncryption and ecdsaWithSHA1 / ecdsaWithSHA224.
// RFC 9481 §3 (MSG_SIG_ALG) does not list SHA-1.
func TestC10_HashFromSignatureAlgOID_SHA1_Rejected(t *testing.T) {
	rejected := []struct {
		name string
		oid  asn1.ObjectIdentifier
	}{
		{"sha1WithRSAEncryption", asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 5}},
		{"ecdsa-with-SHA1", asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 1}},
		{"ecdsa-with-SHA224", asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 1}},
	}
	for _, tc := range rejected {
		t.Run(tc.name, func(t *testing.T) {
			_, err := hashFromSignatureAlgOID(tc.oid)
			assert.Error(t, err, "%s MUST be rejected as MSG_SIG_ALG (RFC 9481 §3)", tc.name)
		})
	}
}

// TestC10_SHA1Protection_Rejected_BadAlg — end-to-end: a CMP message protected
// with sha1WithRSAEncryption MUST be rejected with badAlg.
func TestC10_SHA1Protection_Rejected_BadAlg(t *testing.T) {
	svc := &cmpmock.MockLightweightCMPService{}
	svc.On("LWCGetEnrollmentOptions", mock.Anything, "test-dms").
		Return(&models.EnrollmentOptionsLWCRFC9483{}, nil)

	router, _ := newTestRouterWithStore(svc)
	irDER, _, _ := buildTestIR(t, testIROptions{CN: "device-sha1"})

	// Inject sha1WithRSAEncryption as protectionAlg, then attach an arbitrary
	// non-empty BitString as the "signature". The handler should reject on
	// algorithm OID alone, before attempting to verify.
	sha1Alg := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 5}
	withAlg := injectProtectionAlgOID(t, irDER, sha1Alg)
	withFake := attachFakeProtection(t, withAlg, []byte{0x00, 0xDE, 0xAD, 0xBE, 0xEF})

	resp := postCMP(t, router, "test-dms", withFake)
	require.Equal(t, http.StatusOK, resp.Code)
	require.Equal(t, cmpBodyTagError, parseCMPResponseTag(t, resp.Body.Bytes()))

	bs := parseFailInfoBitString(t, resp.Body.Bytes())
	assert.True(t, bitSet(bs, pkiFailureInfoBadAlg),
		"SHA-1 protection MUST set badAlg (0) per RFC 9481 §3")
}

// attachFakeProtection appends a Protection [0] BitString and an extraCerts [1]
// SEQUENCE OF (containing a self-signed cert) to a bare PKIMessage, producing
// a fully-shaped wire form. The signature value is intentionally not valid —
// callers use this to exercise rejection paths that should trigger before any
// signature verification (e.g. algorithm-OID gating).
func attachFakeProtection(t *testing.T, msgDER []byte, sigBytes []byte) []byte {
	t.Helper()
	var rawMsg rawPKIMessage
	_, err := asn1.Unmarshal(msgDER, &rawMsg)
	require.NoError(t, err)

	cert, _ := buildSelfSignedCert(t, "fake-protect-cert")

	type fullMsg struct {
		Header     asn1.RawValue
		Body       asn1.RawValue
		Protection asn1.BitString  `asn1:"explicit,optional,tag:0,omitempty"`
		ExtraCerts []asn1.RawValue `asn1:"explicit,optional,tag:1,omitempty"`
	}
	out, err := asn1.Marshal(fullMsg{
		Header:     rawMsg.Header,
		Body:       rawMsg.Body,
		Protection: asn1.BitString{Bytes: sigBytes, BitLength: len(sigBytes) * 8},
		ExtraCerts: []asn1.RawValue{{FullBytes: cert.Raw}},
	})
	require.NoError(t, err)
	return out
}

// TestC10_HashFromSignatureAlgOID_AcceptsModern — regression: SHA-256+ MUST
// remain accepted (we are removing only SHA-1/SHA-224).
func TestC10_HashFromSignatureAlgOID_AcceptsModern(t *testing.T) {
	accepted := []struct {
		name string
		oid  asn1.ObjectIdentifier
	}{
		{"sha256WithRSA", asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}},
		{"sha384WithRSA", asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}},
		{"sha512WithRSA", asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}},
		{"ecdsa-with-SHA256", asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}},
		{"ecdsa-with-SHA384", asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}},
		{"ecdsa-with-SHA512", asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}},
		{"ed25519", asn1.ObjectIdentifier{1, 3, 101, 112}},
	}
	for _, tc := range accepted {
		t.Run(tc.name, func(t *testing.T) {
			_, err := hashFromSignatureAlgOID(tc.oid)
			assert.NoError(t, err, "%s must remain accepted as MSG_SIG_ALG", tc.name)
		})
	}
}

// Use a non-fatal reference so the test file always sees `hex` even if a test
// is pruned during edits.
var _ = hex.EncodeToString

// ---------------------------------------------------------------------------
// FailInfo wire-encoding tests — every rejectWithError call site must surface
// the RFC 9810 §5.1.3 bit that matches the failure category. RFC 9483 §3.6.4
// says error responses MUST carry a failInfo, so an error PKIMessage with an
// empty BitString is itself a violation.
// ---------------------------------------------------------------------------

// TestFailInfo_BitNumbersMatchRFC9810 — exhaustive check on the constants so
// that a refactor cannot silently renumber a bit. Bit positions are taken
// verbatim from RFC 9810 §5.1.3 / Appendix B.
func TestFailInfo_BitNumbersMatchRFC9810(t *testing.T) {
	cases := map[string]int{
		"badAlg":             0,
		"badMessageCheck":    1,
		"badRequest":         2,
		"badTime":            3,
		"badCertId":          4,
		"badDataFormat":      5,
		"incorrectData":      7,
		"badPOP":             9,
		"badRecipientNonce":  13,
		"badSenderNonce":     18,
		"badCertTemplate":    19,
		"transactionIdInUse": 21,
		"unsupportedVersion": 22,
		"systemFailure":      25,
	}
	got := map[string]int{
		"badAlg":             pkiFailureInfoBadAlg,
		"badMessageCheck":    pkiFailureInfoBadMessageCheck,
		"badRequest":         pkiFailureInfoBadRequest,
		"badTime":            pkiFailureInfoBadTime,
		"badCertId":          pkiFailureInfoBadCertId,
		"badDataFormat":      pkiFailureInfoBadDataFormat,
		"incorrectData":      pkiFailureInfoIncorrectData,
		"badPOP":             pkiFailureInfoBadPOP,
		"badRecipientNonce":  pkiFailureInfoBadRecipientNonce,
		"badSenderNonce":     pkiFailureInfoBadSenderNonce,
		"badCertTemplate":    pkiFailureInfoBadCertTemplate,
		"transactionIdInUse": pkiFailureInfoTransactionIDInUse,
		"unsupportedVersion": pkiFailureInfoUnsupportedVersion,
		"systemFailure":      pkiFailureInfoSystemFailure,
	}
	for name, expected := range cases {
		assert.Equal(t, expected, got[name],
			"%s bit MUST equal RFC 9810 §5.1.3 value %d", name, expected)
	}
}

// TestFailInfo_RecipNonceMismatch_BadRecipientNonce — RFC 9810 §5.1.3 bit 13
// (badRecipientNonce) is the dedicated failInfo for "recipNonce did not match
// the senderNonce of the previous message in the transaction".
func TestFailInfo_RecipNonceMismatch_BadRecipientNonce(t *testing.T) {
	issuedCert, _ := buildSelfSignedCert(t, "device-bad-recip")

	svc := &cmpmock.MockLightweightCMPService{}
	svc.On("LWCGetEnrollmentOptions", mock.Anything, "test-dms").
		Return(&models.EnrollmentOptionsLWCRFC9483{AcceptImplicit: false}, nil)
	svc.On("LWCEnroll", mock.Anything, mock.AnythingOfType("*x509.CertificateRequest"), "test-dms").
		Return(issuedCert, nil)

	router, store := newTestRouterWithStore(svc)
	txID := make([]byte, 16)
	rand.Read(txID)

	irDER, _, _ := buildTestIR(t, testIROptions{CN: "device-bad-recip", TransactionID: txID})
	irResp := postCMP(t, router, "test-dms", irDER)
	require.Equal(t, http.StatusOK, irResp.Code)
	require.Equal(t, cmpBodyTagIP, parseCMPResponseTag(t, irResp.Body.Bytes()))

	// Stored transaction has a real SentNonce; we send certConf with a
	// deliberately-wrong recipNonce to trigger the mismatch path.
	storedTx, ok := store.Peek(hex.EncodeToString(txID))
	require.True(t, ok)
	require.NotEmpty(t, storedTx.SentNonce)

	wrongNonce := make([]byte, 16)
	for i := range wrongNonce {
		wrongNonce[i] = 0xAA
	}
	certConfDER := buildTestCertConf(t, txID, issuedCert.Raw, wrongNonce)

	resp := postCMP(t, router, "test-dms", certConfDER)
	require.Equal(t, http.StatusOK, resp.Code)
	require.Equal(t, cmpBodyTagError, parseCMPResponseTag(t, resp.Body.Bytes()))

	bs := parseFailInfoBitString(t, resp.Body.Bytes())
	assert.True(t, bitSet(bs, pkiFailureInfoBadRecipientNonce),
		"recipNonce mismatch MUST set badRecipientNonce(13) per RFC 9810 §5.1.3 — got bits %x", bs.Bytes)
	assert.False(t, bitSet(bs, pkiFailureInfoBadRequest),
		"badRequest is NOT the right bit for nonce mismatch — there is a dedicated badRecipientNonce")
}

// TestFailInfo_DuplicateTransactionID_TransactionIDInUse — RFC 9810 §5.1.3
// bit 21 (transactionIdInUse) is the dedicated bit for an IR/CR/KUR carrying
// a transactionID that collides with an in-flight transaction.
func TestFailInfo_DuplicateTransactionID_TransactionIDInUse(t *testing.T) {
	issuedCert, _ := buildSelfSignedCert(t, "device-dup")

	svc := &cmpmock.MockLightweightCMPService{}
	svc.On("LWCGetEnrollmentOptions", mock.Anything, "test-dms").
		Return(&models.EnrollmentOptionsLWCRFC9483{AcceptImplicit: false}, nil)
	svc.On("LWCEnroll", mock.Anything, mock.AnythingOfType("*x509.CertificateRequest"), "test-dms").
		Return(issuedCert, nil)

	router, _ := newTestRouterWithStore(svc)

	txID := make([]byte, 16)
	rand.Read(txID)
	first, _, _ := buildTestIR(t, testIROptions{CN: "device-dup", TransactionID: txID})
	resp1 := postCMP(t, router, "test-dms", first)
	require.Equal(t, http.StatusOK, resp1.Code)
	require.Equal(t, cmpBodyTagIP, parseCMPResponseTag(t, resp1.Body.Bytes()),
		"first IR with this txID must succeed")

	// Second IR carrying the same transactionID — must be rejected.
	second, _, _ := buildTestIR(t, testIROptions{CN: "device-dup", TransactionID: txID})
	resp2 := postCMP(t, router, "test-dms", second)
	require.Equal(t, http.StatusOK, resp2.Code)
	require.Equal(t, cmpBodyTagError, parseCMPResponseTag(t, resp2.Body.Bytes()))

	bs := parseFailInfoBitString(t, resp2.Body.Bytes())
	assert.True(t, bitSet(bs, pkiFailureInfoTransactionIDInUse),
		"duplicate transactionID MUST set transactionIdInUse(21) per RFC 9810 §5.1.3 — got bits %x", bs.Bytes)
}

// TestFailInfo_UnknownTransactionID_BadRequest — when certConf references an
// unknown transactionID (never existed, not just expired), badRequest is the
// closest fit since the message is structurally fine but the operation isn't
// permitted in any transaction state.
func TestFailInfo_UnknownTransactionID_BadRequest(t *testing.T) {
	svc := &cmpmock.MockLightweightCMPService{}
	svc.On("LWCGetEnrollmentOptions", mock.Anything, "test-dms").
		Return(&models.EnrollmentOptionsLWCRFC9483{}, nil).Maybe()

	router, _ := newTestRouterWithStore(svc)

	txID := make([]byte, 16)
	rand.Read(txID)
	cert, _ := buildSelfSignedCert(t, "ghost-cert")
	certConfDER := buildTestCertConf(t, txID, cert.Raw, nil)

	resp := postCMP(t, router, "test-dms", certConfDER)
	require.Equal(t, http.StatusOK, resp.Code)
	require.Equal(t, cmpBodyTagError, parseCMPResponseTag(t, resp.Body.Bytes()))

	bs := parseFailInfoBitString(t, resp.Body.Bytes())
	assert.True(t, bitSet(bs, pkiFailureInfoBadRequest),
		"unknown transactionID MUST set badRequest(2) per RFC 9810 §5.1.3 — got bits %x", bs.Bytes)
}

// TestFailInfo_UnsupportedBodyTag_BadRequest — a CMP message whose body uses
// an unsupported CHOICE tag is a "transaction not permitted" failure
// (badRequest), not a malformed structure failure (badDataFormat).
func TestFailInfo_UnsupportedBodyTag_BadRequest(t *testing.T) {
	svc := &cmpmock.MockLightweightCMPService{}
	svc.On("LWCGetEnrollmentOptions", mock.Anything, "test-dms").
		Return(&models.EnrollmentOptionsLWCRFC9483{}, nil)

	router, _ := newTestRouterWithStore(svc)

	// Build an IR, then rewrite its body CHOICE tag to an unsupported value (5,
	// which is reserved but not handled by our dispatch table).
	irDER, _, _ := buildTestIR(t, testIROptions{CN: "device-bad-tag"})
	mutated := rewriteBodyTag(t, irDER, 5)

	resp := postCMP(t, router, "test-dms", mutated)
	require.Equal(t, http.StatusOK, resp.Code)
	require.Equal(t, cmpBodyTagError, parseCMPResponseTag(t, resp.Body.Bytes()))

	bs := parseFailInfoBitString(t, resp.Body.Bytes())
	assert.True(t, bitSet(bs, pkiFailureInfoBadRequest),
		"unsupported body tag MUST set badRequest(2) — got bits %x", bs.Bytes)
}

// rewriteBodyTag returns a copy of msgDER whose PKIBody CHOICE tag is replaced
// by newTag, leaving everything else unchanged.
func rewriteBodyTag(t *testing.T, msgDER []byte, newTag int) []byte {
	t.Helper()
	var rawMsg rawPKIMessage
	_, err := asn1.Unmarshal(msgDER, &rawMsg)
	require.NoError(t, err)

	newBody, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        newTag,
		IsCompound: rawMsg.Body.IsCompound,
		Bytes:      rawMsg.Body.Bytes,
	})
	require.NoError(t, err)

	out, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      concatBytes(rawMsg.Header.FullBytes, newBody),
	})
	require.NoError(t, err)
	return out
}

// TestFailInfo_MalformedPKIMessage_BadDataFormat — top-level garbage bytes
// trip the outer asn1.Unmarshal and surface badDataFormat per RFC 9483 §3.5.
func TestFailInfo_MalformedPKIMessage_BadDataFormat(t *testing.T) {
	svc := &cmpmock.MockLightweightCMPService{}
	router, _ := newTestRouterWithStore(svc)

	garbage := []byte{0xFF, 0xFE, 0xFD, 0x00, 0x01, 0x02}
	resp := postCMP(t, router, "test-dms", garbage)
	require.Equal(t, http.StatusOK, resp.Code)
	require.Equal(t, cmpBodyTagError, parseCMPResponseTag(t, resp.Body.Bytes()))

	bs := parseFailInfoBitString(t, resp.Body.Bytes())
	assert.True(t, bitSet(bs, pkiFailureInfoBadDataFormat),
		"malformed PKIMessage MUST set badDataFormat(5) per RFC 9483 §3.5 — got bits %x", bs.Bytes)
}

// TestFailInfo_CertHashMismatch_BadCertId — when the EE confirms a cert hash
// that does not match what we issued, badCertId is more precise than the
// generic badRequest: "no certificate could be found matching the provided
// criteria" (RFC 9810 §5.1.3 bit 4).
func TestFailInfo_CertHashMismatch_BadCertId(t *testing.T) {
	issuedCert, _ := buildSelfSignedCert(t, "device-hash-mismatch")

	svc := &cmpmock.MockLightweightCMPService{}
	svc.On("LWCGetEnrollmentOptions", mock.Anything, "test-dms").
		Return(&models.EnrollmentOptionsLWCRFC9483{AcceptImplicit: false}, nil)
	svc.On("LWCEnroll", mock.Anything, mock.AnythingOfType("*x509.CertificateRequest"), "test-dms").
		Return(issuedCert, nil)

	router, store := newTestRouterWithStore(svc)
	txID := make([]byte, 16)
	rand.Read(txID)

	irDER, _, _ := buildTestIR(t, testIROptions{CN: "device-hash-mismatch", TransactionID: txID})
	postCMP(t, router, "test-dms", irDER)

	storedTx, ok := store.Peek(hex.EncodeToString(txID))
	require.True(t, ok)
	sentNonce, _ := hex.DecodeString(storedTx.SentNonce)

	// Confirm a *different* certificate so the hash check fails.
	otherCert, _ := buildSelfSignedCert(t, "wrong-cert")
	certConfDER := buildTestCertConf(t, txID, otherCert.Raw, sentNonce)

	resp := postCMP(t, router, "test-dms", certConfDER)
	require.Equal(t, http.StatusOK, resp.Code)
	require.Equal(t, cmpBodyTagError, parseCMPResponseTag(t, resp.Body.Bytes()))

	bs := parseFailInfoBitString(t, resp.Body.Bytes())
	assert.True(t, bitSet(bs, pkiFailureInfoBadCertId),
		"certHash mismatch MUST set badCertId(4) — got bits %x", bs.Bytes)
}

// TestFailInfo_AllErrorResponsesCarryFailInfo — regression guard: per RFC
// 9483 §3.6.4, every error PKIMessage emitted by this server MUST contain a
// non-empty failInfo. This sweeps the canonical rejection paths and asserts
// the BitString is non-empty in each.
func TestFailInfo_AllErrorResponsesCarryFailInfo(t *testing.T) {
	cases := []struct {
		name string
		mk   func(t *testing.T, router interface{}, svc interface{}) []byte
	}{}

	// Implemented inline rather than table-driven because each scenario needs
	// its own mock wiring. The point is breadth, not parametrisation.
	_ = cases

	t.Run("garbage body → badDataFormat", func(t *testing.T) {
		svc := &cmpmock.MockLightweightCMPService{}
		router, _ := newTestRouterWithStore(svc)
		resp := postCMP(t, router, "test-dms", []byte{0xFF, 0xFE})
		bs := parseFailInfoBitString(t, resp.Body.Bytes())
		assert.NotZero(t, bs.BitLength, "error response must carry failInfo")
	})

	t.Run("unsupported pvno → unsupportedVersion", func(t *testing.T) {
		svc := &cmpmock.MockLightweightCMPService{}
		svc.On("LWCGetEnrollmentOptions", mock.Anything, "test-dms").
			Return(&models.EnrollmentOptionsLWCRFC9483{}, nil).Maybe()
		router, _ := newTestRouterWithStore(svc)
		bad := 99
		header := buildHeaderDERCustom(t, headerOpts{PVNO: &bad})
		irDER := buildIRWithHeader(t, header, "x")
		resp := postCMP(t, router, "test-dms", irDER)
		bs := parseFailInfoBitString(t, resp.Body.Bytes())
		assert.NotZero(t, bs.BitLength, "error response must carry failInfo")
	})

	t.Run("short senderNonce → badSenderNonce", func(t *testing.T) {
		svc := &cmpmock.MockLightweightCMPService{}
		svc.On("LWCGetEnrollmentOptions", mock.Anything, "test-dms").
			Return(&models.EnrollmentOptionsLWCRFC9483{}, nil).Maybe()
		router, _ := newTestRouterWithStore(svc)
		header := buildHeaderDERCustom(t, headerOpts{SenderNonce: []byte{0x01}})
		irDER := buildIRWithHeader(t, header, "x")
		resp := postCMP(t, router, "test-dms", irDER)
		bs := parseFailInfoBitString(t, resp.Body.Bytes())
		assert.NotZero(t, bs.BitLength, "error response must carry failInfo")
	})
}

// ---------------------------------------------------------------------------
// CMP v3 (cmp2021) drop-and-poll end-to-end flow
//
// RFC 9810 §5.3.22 PollReqContent / PollRepContent are unchanged between
// cmp2000 and cmp2021, but §7 (version negotiation) requires the server to
// echo the request's pvno on every response in the same transaction. The
// tests below walk a complete enrollment under pvno=3, with the IP response
// "dropped" between the initial issuance and the EE's recovery pollReq.
// They verify:
//
//   1. The IR (pvno=3) is accepted and an ISSUED row is persisted.
//   2. The pollReq (pvno=3) re-delivers the cert under pvno=3, NOT pvno=2.
//   3. The senderNonce on the redelivered IP equals the one persisted on
//      the original ISSUED row, so the subsequent certConf round-trip can
//      match recipNonce against the stored sentNonce.
//   4. certConf (pvno=3) completes the transaction with pkiConf (pvno=3).
// ---------------------------------------------------------------------------

// buildBodyTaggedSequenceContent wraps a content payload in a
// [tag] context-specific IsCompound TLV. Used to build pollReq[25],
// certConf[24] etc. bodies without going through buildTest* helpers.
func buildBodyTaggedSequenceContent(t *testing.T, tag int, content []byte) []byte {
	t.Helper()
	der, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        tag,
		IsCompound: true,
		Bytes:      content,
	})
	require.NoError(t, err)
	return der
}

// wrapAsUniversalSequence wraps a content payload in a UNIVERSAL SEQUENCE.
func wrapAsUniversalSequence(t *testing.T, content []byte) []byte {
	t.Helper()
	der, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      content,
	})
	require.NoError(t, err)
	return der
}

// buildPollReqWithHeader assembles a pollReq PKIMessage using a fully-
// controlled header. The body carries a single certReqId entry per the
// single-cert-per-transaction convention this server expects.
func buildPollReqWithHeader(t *testing.T, headerDER []byte, certReqID int) []byte {
	t.Helper()
	type pollReqEntry struct {
		CertReqID int
	}
	pollReqContent, err := asn1.Marshal([]pollReqEntry{{CertReqID: certReqID}})
	require.NoError(t, err)
	bodyDER := buildBodyTaggedSequenceContent(t, cmpBodyTagPollReq, pollReqContent)
	return wrapAsUniversalSequence(t, concatBytes(headerDER, bodyDER))
}

// buildCertConfWithHeader assembles a certConf PKIMessage using a fully-
// controlled header. The certHash is SHA-256 of certDER (default per
// RFC 9481 §3.3 — no hashAlg field included).
func buildCertConfWithHeader(t *testing.T, headerDER []byte, certDER []byte) []byte {
	t.Helper()
	hash := sha256.Sum256(certDER)
	certStatusDER, err := asn1.Marshal(struct {
		CertHash  []byte
		CertReqID int
	}{
		CertHash:  hash[:],
		CertReqID: 0,
	})
	require.NoError(t, err)
	certConfContent := wrapAsUniversalSequence(t, certStatusDER)
	bodyDER := buildBodyTaggedSequenceContent(t, cmpBodyTagCertConf, certConfContent)
	return wrapAsUniversalSequence(t, concatBytes(headerDER, bodyDER))
}

// parseResponseSenderNonce extracts the senderNonce [5] OCTET STRING from a
// response header. Used to verify the pollReq-redelivery path echoes the
// originally-persisted senderNonce so certConf can still match against it.
func parseResponseSenderNonce(t *testing.T, responseDER []byte) []byte {
	t.Helper()
	type rawMsg struct {
		Header asn1.RawValue
		Body   asn1.RawValue
	}
	var msg rawMsg
	_, err := asn1.Unmarshal(responseDER, &msg)
	require.NoError(t, err)

	var headerSeq asn1.RawValue
	_, err = asn1.Unmarshal(msg.Header.FullBytes, &headerSeq)
	require.NoError(t, err)

	remaining := headerSeq.Bytes
	for i := 0; i < 3; i++ {
		var f asn1.RawValue
		remaining, err = asn1.Unmarshal(remaining, &f)
		require.NoError(t, err)
	}
	for len(remaining) > 0 {
		var f asn1.RawValue
		remaining, err = asn1.Unmarshal(remaining, &f)
		require.NoError(t, err)
		if f.Class == asn1.ClassContextSpecific && f.Tag == 5 {
			var inner []byte
			if _, err := asn1.Unmarshal(f.Bytes, &inner); err == nil {
				return inner
			}
		}
	}
	return nil
}

// TestCMPv3_DropAndPoll_ExplicitConfirm — the canonical lost-response
// recovery flow, but every wire message uses pvno=3 (cmp2021).
//
// Walks the full transaction:
//
//	1. EE → IR (pvno=3) → server issues, replies IP (pvno=3, dropped).
//	2. EE → pollReq (pvno=3, same txID) → server redelivers cert in IP
//	   (pvno=3, with the same senderNonce as the original IP).
//	3. EE → certConf (pvno=3, recipNonce = stored sentNonce) → server
//	   replies pkiConf (pvno=3) and transitions tx to CONFIRMED.
//
// RFC 9810 §7 line 3754 anchors the pvno-echo requirement; this test
// exercises it across every step of the drop-recover flow.
func TestCMPv3_DropAndPoll_ExplicitConfirm(t *testing.T) {
	issuedCert, _ := buildSelfSignedCert(t, "v3-drop-poll-device")

	svc := &cmpmock.MockLightweightCMPService{}
	svc.On("LWCGetEnrollmentOptions", mock.Anything, "test-dms").
		Return(&models.EnrollmentOptionsLWCRFC9483{AcceptImplicit: false}, nil)
	svc.On("LWCEnroll", mock.Anything, mock.AnythingOfType("*x509.CertificateRequest"), "test-dms").
		Return(issuedCert, nil)

	router, store := newTestRouterWithStore(svc)

	txID := make([]byte, 16)
	_, err := rand.Read(txID)
	require.NoError(t, err)

	// Step 1: IR with pvno=3. The response from this call is the IP that
	// (in the dropped-response scenario) the EE never receives.
	irHeader := buildHeaderDERCustom(t, headerOpts{
		PVNO:          intPtr(pvnoCMP2021),
		TransactionID: txID,
	})
	irDER := buildIRWithHeader(t, irHeader, "v3-drop-poll-device")

	irResp := postCMP(t, router, "test-dms", irDER)
	require.Equal(t, http.StatusOK, irResp.Code)
	require.Equal(t, cmpBodyTagIP, parseCMPResponseTag(t, irResp.Body.Bytes()),
		"IR must produce an IP response")
	assert.Equal(t, pvnoCMP2021, parseResponsePVNO(t, irResp.Body.Bytes()),
		"IP response under cmp2021 IR MUST carry pvno=3 (RFC 9810 §7)")

	// The ISSUED row must exist with a persisted sentNonce — that nonce is
	// what the pollReq-recovery branch will need to echo on the redelivered
	// IP so the subsequent certConf can match recipNonce against it.
	storedTx, ok := store.Peek(hex.EncodeToString(txID))
	require.True(t, ok, "IR must persist the ISSUED row for pollReq recovery")
	require.Equal(t, storage.CMPTransactionStateIssued, storedTx.State)
	persistedSentNonce, err := hex.DecodeString(storedTx.SentNonce)
	require.NoError(t, err)
	require.Len(t, persistedSentNonce, 16, "stored sentNonce must be 128 bits")

	// At this point the IP response from step 1 is "dropped" (we simply
	// discard it). The EE moves on to the recovery branch.

	// Step 2: pollReq with pvno=3 referencing the same transactionID. The
	// server must redeliver the cert in an IP body — NOT a pollRep —
	// because the row is ISSUED, not PENDING.
	pollHeader := buildHeaderDERCustom(t, headerOpts{
		PVNO:          intPtr(pvnoCMP2021),
		TransactionID: txID,
	})
	pollDER := buildPollReqWithHeader(t, pollHeader, 0)

	pollResp := postCMP(t, router, "test-dms", pollDER)
	require.Equal(t, http.StatusOK, pollResp.Code)
	require.Equal(t, cmpBodyTagIP, parseCMPResponseTag(t, pollResp.Body.Bytes()),
		"ISSUED-state pollReq must deliver the cert via IP, not pollRep")
	assert.Equal(t, pvnoCMP2021, parseResponsePVNO(t, pollResp.Body.Bytes()),
		"pollReq under cmp2021 MUST receive a cmp2021 response (RFC 9810 §7)")

	// CRITICAL: the senderNonce on the redelivered IP must equal the
	// original sentNonce so the EE-side certConf with recipNonce can match.
	// Generating a fresh nonce per pollRep without persisting it would
	// silently desync DB from wire and break every subsequent certConf.
	redeliveredSenderNonce := parseResponseSenderNonce(t, pollResp.Body.Bytes())
	assert.Equal(t, persistedSentNonce, redeliveredSenderNonce,
		"pollReq redelivery MUST echo the originally-persisted sentNonce — "+
			"otherwise certConf recipNonce will mismatch")

	// Tx is still ISSUED — pollReq does not consume it.
	storedAfterPoll, ok := store.Peek(hex.EncodeToString(txID))
	require.True(t, ok, "pollReq delivery must not delete the ISSUED row")
	assert.Equal(t, storage.CMPTransactionStateIssued, storedAfterPoll.State,
		"pollReq must not transition tx state in explicit-confirm mode")

	// Step 3: certConf with pvno=3, recipNonce = the persisted sentNonce.
	certConfHeader := buildHeaderDERCustom(t, headerOpts{
		PVNO:          intPtr(pvnoCMP2021),
		TransactionID: txID,
		RecipNonce:    persistedSentNonce,
	})
	certConfDER := buildCertConfWithHeader(t, certConfHeader, issuedCert.Raw)

	confResp := postCMP(t, router, "test-dms", certConfDER)
	require.Equal(t, http.StatusOK, confResp.Code)
	require.Equal(t, cmpBodyTagPKIConf, parseCMPResponseTag(t, confResp.Body.Bytes()),
		"certConf with valid certHash + recipNonce MUST yield pkiConf")
	assert.Equal(t, pvnoCMP2021, parseResponsePVNO(t, confResp.Body.Bytes()),
		"pkiConf MUST carry pvno=3 to match the cmp2021 transaction")

	// Tx is now CONFIRMED.
	finalTx, ok := store.Peek(hex.EncodeToString(txID))
	require.True(t, ok)
	assert.Equal(t, storage.CMPTransactionStateConfirmed, finalTx.State,
		"successful certConf must transition tx to CONFIRMED")

	svc.AssertExpectations(t)
}

// TestCMPv3_DropAndPoll_ImplicitConfirm — same drop-recover scenario but
// the DMS accepts implicit confirmation and the EE includes the
// id-it-implicitConfirm OID. In implicit mode no certConf round-trip is
// expected; the pollReq-redelivered IP is the terminal message and the
// server transitions the tx to CONFIRMED on delivery (RFC 4210 §5.2.8).
func TestCMPv3_DropAndPoll_ImplicitConfirm(t *testing.T) {
	issuedCert, _ := buildSelfSignedCert(t, "v3-drop-poll-implicit")

	svc := &cmpmock.MockLightweightCMPService{}
	svc.On("LWCGetEnrollmentOptions", mock.Anything, "test-dms").
		Return(&models.EnrollmentOptionsLWCRFC9483{AcceptImplicit: true}, nil)
	svc.On("LWCEnroll", mock.Anything, mock.AnythingOfType("*x509.CertificateRequest"), "test-dms").
		Return(issuedCert, nil)

	router, store := newTestRouterWithStore(svc)

	txID := make([]byte, 16)
	_, err := rand.Read(txID)
	require.NoError(t, err)

	// Step 1: IR with pvno=3 + implicitConfirm. Original IP dropped.
	irHeader := buildHeaderDERCustom(t, headerOpts{
		PVNO:                intPtr(pvnoCMP2021),
		TransactionID:       txID,
		WithImplicitConfirm: true,
	})
	irDER := buildIRWithHeader(t, irHeader, "v3-drop-poll-implicit")

	irResp := postCMP(t, router, "test-dms", irDER)
	require.Equal(t, http.StatusOK, irResp.Code)
	require.Equal(t, cmpBodyTagIP, parseCMPResponseTag(t, irResp.Body.Bytes()))
	assert.Equal(t, pvnoCMP2021, parseResponsePVNO(t, irResp.Body.Bytes()))

	// Row is born CONFIRMED in implicit-confirm mode — RFC 4210 §5.2.8 says
	// the transaction is complete upon IP delivery. The row persists in
	// CONFIRMED so a lost-IP pollReq can still recover the cert (see the
	// pollReq case below), and the confirmation monitor never touches it.
	stored, ok := store.Peek(hex.EncodeToString(txID))
	require.True(t, ok, "implicit-confirm IR must persist a row for pollReq recovery")
	require.Equal(t, storage.CMPTransactionStateConfirmed, stored.State,
		"implicit-confirm row is finalised at IP delivery, not at pollReq")

	// Step 2: pollReq with pvno=3 + implicitConfirm (same as IR). The
	// server redelivers the cert and, because the DMS grants implicit
	// confirmation, transitions the row to CONFIRMED right away.
	pollHeader := buildHeaderDERCustom(t, headerOpts{
		PVNO:                intPtr(pvnoCMP2021),
		TransactionID:       txID,
		WithImplicitConfirm: true,
	})
	pollDER := buildPollReqWithHeader(t, pollHeader, 0)

	pollResp := postCMP(t, router, "test-dms", pollDER)
	require.Equal(t, http.StatusOK, pollResp.Code)
	require.Equal(t, cmpBodyTagIP, parseCMPResponseTag(t, pollResp.Body.Bytes()),
		"implicit-confirm pollReq against ISSUED row must deliver the cert via IP")
	assert.Equal(t, pvnoCMP2021, parseResponsePVNO(t, pollResp.Body.Bytes()),
		"redelivered IP MUST carry pvno=3 to match the cmp2021 transaction")

	// Row stays CONFIRMED — already finalised at IR time. pollReq just
	// re-delivered the cert; it never demotes nor re-runs the finalisation.
	finalTx, ok := store.Peek(hex.EncodeToString(txID))
	require.True(t, ok)
	assert.Equal(t, storage.CMPTransactionStateConfirmed, finalTx.State,
		"implicit-confirm row must stay CONFIRMED across pollReq replays")

	svc.AssertExpectations(t)
}

// TestCMPv3_PollReq_PVNOMismatch_ResponseEchoesPollPVNO — RFC 9810 §7 line
// 3754: "the version of the response message MUST be the same as the
// received version". If the EE somehow sends an IR with pvno=2 and then a
// pollReq with pvno=3 (legal per the spec — only the request matters), the
// server MUST honour the pollReq's declared version in its response.
//
// This documents the wire behaviour at the pvno boundary even though a
// well-behaved EE would keep pvno consistent across a single transaction.
func TestCMPv3_PollReq_PVNOMismatch_ResponseEchoesPollPVNO(t *testing.T) {
	issuedCert, _ := buildSelfSignedCert(t, "v3-pvno-mismatch")

	svc := &cmpmock.MockLightweightCMPService{}
	svc.On("LWCGetEnrollmentOptions", mock.Anything, "test-dms").
		Return(&models.EnrollmentOptionsLWCRFC9483{AcceptImplicit: false}, nil)
	svc.On("LWCEnroll", mock.Anything, mock.AnythingOfType("*x509.CertificateRequest"), "test-dms").
		Return(issuedCert, nil)

	router, store := newTestRouterWithStore(svc)

	txID := make([]byte, 16)
	_, _ = rand.Read(txID)

	// Step 1: IR with pvno=2.
	irHeader := buildHeaderDERCustom(t, headerOpts{
		PVNO:          intPtr(pvnoCMP2000),
		TransactionID: txID,
	})
	irDER := buildIRWithHeader(t, irHeader, "v3-pvno-mismatch")
	irResp := postCMP(t, router, "test-dms", irDER)
	require.Equal(t, http.StatusOK, irResp.Code)
	assert.Equal(t, pvnoCMP2000, parseResponsePVNO(t, irResp.Body.Bytes()))

	_, ok := store.Peek(hex.EncodeToString(txID))
	require.True(t, ok)

	// Step 2: pollReq with pvno=3 — server MUST echo pvno=3 on the redelivery.
	pollHeader := buildHeaderDERCustom(t, headerOpts{
		PVNO:          intPtr(pvnoCMP2021),
		TransactionID: txID,
	})
	pollDER := buildPollReqWithHeader(t, pollHeader, 0)
	pollResp := postCMP(t, router, "test-dms", pollDER)
	require.Equal(t, http.StatusOK, pollResp.Code)
	assert.Equal(t, pvnoCMP2021, parseResponsePVNO(t, pollResp.Body.Bytes()),
		"pollReq pvno is what determines the response pvno (RFC 9810 §7)")
}
