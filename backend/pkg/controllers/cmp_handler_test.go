package controllers

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	cmpmock "github.com/lamassuiot/lamassuiot/core/v3/pkg/services/mock"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Test infrastructure
// ---------------------------------------------------------------------------

func newTestRouter(svc services.LightweightCMPService) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	logger := logrus.NewEntry(logrus.New())
	routes := NewCMPHttpRoutes(logger, svc)
	r.POST("/.well-known/cmp/p/:id", routes.HandleCMP)
	return r
}

// postCMP sends a DER-encoded PKIMessage to the test router and returns the response.
func postCMP(t *testing.T, router *gin.Engine, dmsID string, derMsg []byte) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost,
		fmt.Sprintf("/.well-known/cmp/p/%s", dmsID),
		bytes.NewReader(derMsg))
	req.Header.Set("Content-Type", "application/pkixcmp")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}


// ---------------------------------------------------------------------------
// PKIMessage builder helpers
// ---------------------------------------------------------------------------

// testIROptions controls what is included in a test IR PKIMessage.
type testIROptions struct {
	CN                  string
	TransactionID       []byte
	WithImplicitConfirm bool
}

// buildTestIR constructs a minimal valid DER-encoded PKIMessage with an IR body.
func buildTestIR(t *testing.T, opts testIROptions) (derMsg []byte, txID []byte, privKey *ecdsa.PrivateKey) {
	t.Helper()

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	pubKeyDER, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	require.NoError(t, err)

	cn := opts.CN
	if cn == "" {
		cn = "test-device"
	}

	txID = opts.TransactionID
	if len(txID) == 0 {
		txID = make([]byte, 16)
		_, err = rand.Read(txID)
		require.NoError(t, err)
	}

	senderNonce := make([]byte, 16)
	_, err = rand.Read(senderNonce)
	require.NoError(t, err)

	headerDER := buildTestPKIHeaderDER(t, txID, senderNonce, opts.WithImplicitConfirm)
	bodyDER := buildTestIRBodyDER(t, cn, pubKeyDER)

	msgDER, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      concatBytes(headerDER, bodyDER),
	})
	require.NoError(t, err)

	return msgDER, txID, privKey
}

// buildTestCertConf constructs a minimal DER-encoded certConf PKIMessage.
func buildTestCertConf(t *testing.T, txID []byte, certDER []byte) []byte {
	t.Helper()

	senderNonce := make([]byte, 16)
	rand.Read(senderNonce)

	headerDER := buildTestPKIHeaderDER(t, txID, senderNonce, false)

	hash := sha256.Sum256(certDER)
	certStatusDER, err := asn1.Marshal(struct {
		CertHash  []byte
		CertReqID int
	}{
		CertHash:  hash[:],
		CertReqID: 0,
	})
	require.NoError(t, err)

	certConfContent, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      certStatusDER,
	})
	require.NoError(t, err)

	// PKIBody certConf [24]
	bodyDER, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        cmpBodyTagCertConf,
		IsCompound: true,
		Bytes:      certConfContent,
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

// buildTestPKIHeaderDER encodes a minimal PKIHeader SEQUENCE.
func buildTestPKIHeaderDER(t *testing.T, txID, senderNonce []byte, withImplicitConfirm bool) []byte {
	t.Helper()

	pvnoDER, err := asn1.Marshal(pvnoCMP2000)
	require.NoError(t, err)

	// Use an empty DirectoryName GeneralName [4] for sender/recipient.
	emptyName, err := asn1.Marshal(pkix.RDNSequence{})
	require.NoError(t, err)
	// DirectoryName is GeneralName [4] EXPLICIT Name
	senderDER, err := asn1.MarshalWithParams(asn1.RawValue{FullBytes: emptyName}, "tag:4")
	require.NoError(t, err)
	recipientDER := senderDER

	// transactionID [4] EXPLICIT OCTET STRING
	txIDInner, err := asn1.Marshal(txID)
	require.NoError(t, err)
	txIDField, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        4,
		IsCompound: true,
		Bytes:      txIDInner,
	})
	require.NoError(t, err)

	// senderNonce [5] EXPLICIT OCTET STRING
	nonceInner, err := asn1.Marshal(senderNonce)
	require.NoError(t, err)
	nonceField, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        5,
		IsCompound: true,
		Bytes:      nonceInner,
	})
	require.NoError(t, err)

	headerContent := concatBytes(pvnoDER, senderDER, recipientDER, txIDField, nonceField)

	if withImplicitConfirm {
		headerContent = append(headerContent, buildImplicitConfirmGeneralInfo(t)...)
	}

	headerDER, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      headerContent,
	})
	require.NoError(t, err)
	return headerDER
}

// buildImplicitConfirmGeneralInfo encodes generalInfo[8] with id-it-implicitConfirm.
func buildImplicitConfirmGeneralInfo(t *testing.T) []byte {
	t.Helper()

	// InfoTypeAndValue ::= SEQUENCE { infoType OID }  (value absent = implicit NULL per RFC 4210)
	infoTypeAndValue, err := asn1.Marshal(struct {
		OID asn1.ObjectIdentifier
	}{
		OID: oidImplicitConfirm,
	})
	require.NoError(t, err)

	// Wrap in SEQUENCE OF InfoTypeAndValue
	genInfoSeq, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      infoTypeAndValue,
	})
	require.NoError(t, err)

	// generalInfo [8] EXPLICIT
	genInfoField, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        8,
		IsCompound: true,
		Bytes:      genInfoSeq,
	})
	require.NoError(t, err)
	return genInfoField
}

// buildTestIRBodyDER encodes a minimal IR PKIBody.
func buildTestIRBodyDER(t *testing.T, cn string, pubKeyDER []byte) []byte {
	t.Helper()

	subjectDER := buildSubjectCN(t, cn)

	subjectField, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        5,
		IsCompound: true,
		Bytes:      subjectDER,
	})
	require.NoError(t, err)

	// [6] must carry the CONTENT of the SubjectPublicKeyInfo SEQUENCE
	// (without the outer SEQUENCE tag), because decodeFirstCertReq calls
	// wrapSequenceDER on field.Bytes which re-adds the tag.
	var spkiRaw asn1.RawValue
	_, err = asn1.Unmarshal(pubKeyDER, &spkiRaw)
	require.NoError(t, err)

	pubKeyField, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        6,
		IsCompound: true,
		Bytes:      spkiRaw.Bytes, // content only, not full SEQUENCE DER
	})
	require.NoError(t, err)

	certTemplateDER, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      concatBytes(subjectField, pubKeyField),
	})
	require.NoError(t, err)

	certReqIDDER, err := asn1.Marshal(0)
	require.NoError(t, err)

	certRequestDER, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      concatBytes(certReqIDDER, certTemplateDER),
	})
	require.NoError(t, err)

	certReqMsgDER, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      certRequestDER,
	})
	require.NoError(t, err)

	certReqMsgsDER, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      certReqMsgDER,
	})
	require.NoError(t, err)

	bodyDER, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        cmpBodyTagIR,
		IsCompound: true,
		Bytes:      certReqMsgsDER,
	})
	require.NoError(t, err)

	return bodyDER
}

// buildSubjectCN encodes an RDNSequence with a single CN attribute.
func buildSubjectCN(t *testing.T, cn string) []byte {
	t.Helper()
	atv, err := asn1.Marshal(struct {
		Type  asn1.ObjectIdentifier
		Value interface{}
	}{
		Type:  asn1.ObjectIdentifier{2, 5, 4, 3},
		Value: asn1.RawValue{Tag: asn1.TagUTF8String, Bytes: []byte(cn)},
	})
	require.NoError(t, err)

	rdnDER, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSet,
		IsCompound: true,
		Bytes:      atv,
	})
	require.NoError(t, err)

	rdnSeqDER, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      rdnDER,
	})
	require.NoError(t, err)
	return rdnSeqDER
}

// buildSelfSignedCert generates a self-signed certificate for use in tests.
func buildSelfSignedCert(t *testing.T, cn string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)
	return cert, key
}

// signCMPMessage adds ECDSA-SHA256 protection to a pre-built PKIMessage DER.
func signCMPMessage(t *testing.T, msgDER []byte, signerCert *x509.Certificate, signerKey crypto.Signer) []byte {
	t.Helper()

	var rawMsg rawPKIMessage
	_, err := asn1.Unmarshal(msgDER, &rawMsg)
	require.NoError(t, err)

	payload, err := marshalProtectedPayload(rawMsg.Header.FullBytes, rawMsg.Body.FullBytes)
	require.NoError(t, err)

	digest := sha256.Sum256(payload)
	sig, err := signerKey.Sign(rand.Reader, digest[:], crypto.SHA256)
	require.NoError(t, err)

	type fullMsg struct {
		Header     asn1.RawValue
		Body       asn1.RawValue
		Protection asn1.BitString  `asn1:"explicit,optional,tag:0,omitempty"`
		ExtraCerts []asn1.RawValue `asn1:"explicit,optional,tag:1,omitempty"`
	}
	protected := fullMsg{
		Header: rawMsg.Header,
		Body:   rawMsg.Body,
		Protection: asn1.BitString{
			Bytes:     sig,
			BitLength: len(sig) * 8,
		},
		ExtraCerts: []asn1.RawValue{{FullBytes: signerCert.Raw}},
	}

	out, err := asn1.Marshal(protected)
	require.NoError(t, err)
	return out
}

// parseCMPResponseTag returns the body CHOICE tag from a DER-encoded PKIMessage.
func parseCMPResponseTag(t *testing.T, body []byte) int {
	t.Helper()
	var msg rawPKIMessage
	_, err := asn1.Unmarshal(body, &msg)
	require.NoError(t, err, "response must be a valid DER PKIMessage")
	return msg.Body.Tag
}

// parseCMPErrorReason scans the error body for the first UTF8String.
func parseCMPErrorReason(t *testing.T, body []byte) string {
	t.Helper()
	var msg rawPKIMessage
	_, err := asn1.Unmarshal(body, &msg)
	require.NoError(t, err)
	if msg.Body.Tag != cmpBodyTagError {
		return ""
	}
	return scanFirstUTF8String(msg.Body.Bytes)
}

func scanFirstUTF8String(der []byte) string {
	remaining := der
	for len(remaining) > 0 {
		var v asn1.RawValue
		rest, err := asn1.Unmarshal(remaining, &v)
		if err != nil {
			return ""
		}
		remaining = rest
		if v.Tag == asn1.TagUTF8String && v.Class == asn1.ClassUniversal {
			return string(v.Bytes)
		}
		if v.IsCompound {
			if s := scanFirstUTF8String(v.Bytes); s != "" {
				return s
			}
		}
	}
	return ""
}

// parseExtraCertsCount counts the certs in the extraCerts field [1] of a PKIMessage.
func parseExtraCertsCount(t *testing.T, responseDER []byte) int {
	t.Helper()
	type fullPKIMsg struct {
		Header     asn1.RawValue
		Body       asn1.RawValue
		Protection asn1.RawValue   `asn1:"optional,explicit,tag:0"`
		ExtraCerts []asn1.RawValue `asn1:"optional,explicit,tag:1"`
	}
	var msg fullPKIMsg
	_, err := asn1.Unmarshal(responseDER, &msg)
	require.NoError(t, err)
	return len(msg.ExtraCerts)
}

// concatBytes concatenates byte slices.
func concatBytes(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// ---------------------------------------------------------------------------
// Cycle 1: implicitConfirm skips the transaction store
// ---------------------------------------------------------------------------

// TestHandleCMP_ImplicitConfirm_NoCertConf verifies that when the DMS is
// configured with IMPLICIT confirmation mode and the EE includes
// id-it-implicitConfirm in generalInfo, the handler does NOT store a pending
// transaction — so a follow-up certConf for the same transactionID returns a
// CMP error body (tag 23).
func TestHandleCMP_ImplicitConfirm_NoCertConf(t *testing.T) {
	issuedCert, _ := buildSelfSignedCert(t, "test-device")

	svc := &cmpmock.MockLightweightCMPService{}
	svc.On("LWCGetEnrollmentOptions", mock.Anything, "test-dms").
		Return(&models.EnrollmentOptionsLWCRFC9483{
			ConfirmationMode: models.CMPConfirmationModeImplicit,
		}, nil)
	svc.On("LWCEnroll", mock.Anything, mock.AnythingOfType("*x509.CertificateRequest"), "test-dms").
		Return(issuedCert, nil)

	router := newTestRouter(svc)
	txID := make([]byte, 16)
	rand.Read(txID)

	// Step 1: IR with id-it-implicitConfirm OID
	irDER, _, _ := buildTestIR(t, testIROptions{
		CN:                  "test-device",
		TransactionID:       txID,
		WithImplicitConfirm: true,
	})
	irResp := postCMP(t, router, "test-dms", irDER)
	require.Equal(t, http.StatusOK, irResp.Code)
	assert.Equal(t, cmpBodyTagIP, parseCMPResponseTag(t, irResp.Body.Bytes()),
		"ir with implicitConfirm must receive IP response")

	// Step 2: certConf for the same txID — MUST fail because tx was not stored.
	certConfDER := buildTestCertConf(t, txID, issuedCert.Raw)
	confResp := postCMP(t, router, "test-dms", certConfDER)
	require.Equal(t, http.StatusOK, confResp.Code)
	assert.Equal(t, cmpBodyTagError, parseCMPResponseTag(t, confResp.Body.Bytes()),
		"certConf after implicit confirmation must return CMP error")
	assert.Contains(t, parseCMPErrorReason(t, confResp.Body.Bytes()), "unknown transactionID")

	svc.AssertExpectations(t)
}

// TestHandleCMP_ExplicitConfirm_CertConfSucceeds verifies the baseline: without
// implicitConfirm the transaction is stored and certConf returns pkiConf.
func TestHandleCMP_ExplicitConfirm_CertConfSucceeds(t *testing.T) {
	issuedCert, _ := buildSelfSignedCert(t, "test-device-explicit")

	svc := &cmpmock.MockLightweightCMPService{}
	svc.On("LWCEnroll", mock.Anything, mock.AnythingOfType("*x509.CertificateRequest"), "test-dms").
		Return(issuedCert, nil)

	router := newTestRouter(svc)
	txID := make([]byte, 16)
	rand.Read(txID)

	irDER, _, _ := buildTestIR(t, testIROptions{CN: "test-device-explicit", TransactionID: txID})
	irResp := postCMP(t, router, "test-dms", irDER)
	require.Equal(t, http.StatusOK, irResp.Code)
	assert.Equal(t, cmpBodyTagIP, parseCMPResponseTag(t, irResp.Body.Bytes()))

	certConfDER := buildTestCertConf(t, txID, issuedCert.Raw)
	confResp := postCMP(t, router, "test-dms", certConfDER)
	require.Equal(t, http.StatusOK, confResp.Code)
	assert.Equal(t, cmpBodyTagPKIConf, parseCMPResponseTag(t, confResp.Body.Bytes()),
		"certConf with correct hash must receive pkiConf")

	svc.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// Cycle 2 & 3: EE signature-based protection verification
// ---------------------------------------------------------------------------

// TestHandleCMP_ProtectionVerification_ValidSignature verifies that a properly
// signed IR is accepted and LWCEnroll is called.
func TestHandleCMP_ProtectionVerification_ValidSignature(t *testing.T) {
	issuedCert, _ := buildSelfSignedCert(t, "device-sig-valid")
	signerCert, signerKey := buildSelfSignedCert(t, "device-signer")

	svc := &cmpmock.MockLightweightCMPService{}
	svc.On("LWCEnroll", mock.Anything, mock.AnythingOfType("*x509.CertificateRequest"), "test-dms").
		Return(issuedCert, nil)

	router := newTestRouter(svc)
	irDER, _, _ := buildTestIR(t, testIROptions{CN: "device-sig-valid"})
	signedIR := signCMPMessage(t, irDER, signerCert, signerKey)

	resp := postCMP(t, router, "test-dms", signedIR)
	require.Equal(t, http.StatusOK, resp.Code)
	assert.Equal(t, cmpBodyTagIP, parseCMPResponseTag(t, resp.Body.Bytes()),
		"valid protection signature must yield IP response")

	svc.AssertExpectations(t)
}

// TestHandleCMP_ProtectionVerification_InvalidSignature verifies that a
// tampered protection signature is rejected with a CMP error body (tag 23).
func TestHandleCMP_ProtectionVerification_InvalidSignature(t *testing.T) {
	signerCert, _ := buildSelfSignedCert(t, "device-signer")
	// wrongKey does not match signerCert.PublicKey — signature will be invalid.
	_, wrongKey := buildSelfSignedCert(t, "wrong-key")

	svc := &cmpmock.MockLightweightCMPService{}
	// LWCEnroll must NOT be called when signature verification fails.

	router := newTestRouter(svc)
	irDER, _, _ := buildTestIR(t, testIROptions{CN: "device-bad-sig"})
	// signerCert goes into ExtraCerts, but wrongKey signs — mismatch → invalid.
	tamperedIR := signCMPMessage(t, irDER, signerCert, wrongKey)

	resp := postCMP(t, router, "test-dms", tamperedIR)
	require.Equal(t, http.StatusOK, resp.Code)
	assert.Equal(t, cmpBodyTagError, parseCMPResponseTag(t, resp.Body.Bytes()),
		"tampered signature must return CMP error body")
	assert.Contains(t, parseCMPErrorReason(t, resp.Body.Bytes()), "protection",
		"error reason must mention protection failure")

	svc.AssertNotCalled(t, "LWCEnroll", mock.Anything, mock.Anything, mock.Anything)
}

// TestHandleCMP_ProtectionVerification_NoProtection verifies that a message
// without any protection is accepted (mTLS handles auth; protection is optional).
func TestHandleCMP_ProtectionVerification_NoProtection(t *testing.T) {
	issuedCert, _ := buildSelfSignedCert(t, "device-no-prot")

	svc := &cmpmock.MockLightweightCMPService{}
	svc.On("LWCGetEnrollmentOptions", mock.Anything, "test-dms").
		Return(&models.EnrollmentOptionsLWCRFC9483{ConfirmationMode: models.CMPConfirmationModeExplicit}, nil)
	svc.On("LWCEnroll", mock.Anything, mock.AnythingOfType("*x509.CertificateRequest"), "test-dms").
		Return(issuedCert, nil)

	router := newTestRouter(svc)
	irDER, _, _ := buildTestIR(t, testIROptions{CN: "device-no-prot"})

	resp := postCMP(t, router, "test-dms", irDER)
	require.Equal(t, http.StatusOK, resp.Code)
	assert.Equal(t, cmpBodyTagIP, parseCMPResponseTag(t, resp.Body.Bytes()),
		"unprotected message must be accepted when no signature is present")
}

// ---------------------------------------------------------------------------
// Cycle 4: extraCerts full chain in protected responses
// ---------------------------------------------------------------------------

// TestHandleCMP_Response_ExtraCertsContainsChain verifies that when the DMS
// has a protection certificate configured, the CMP response includes the full
// chain in extraCerts (not just the leaf).
func TestHandleCMP_Response_ExtraCertsContainsChain(t *testing.T) {
	issuedCert, _ := buildSelfSignedCert(t, "device-chain-test")
	leafCert, leafKey := buildSelfSignedCert(t, "cmp-protection-leaf")
	issuerCert, _ := buildSelfSignedCert(t, "cmp-protection-issuer")

	svc := &cmpmock.MockLightweightCMPServiceWithProtection{}
	svc.On("LWCEnroll", mock.Anything, mock.AnythingOfType("*x509.CertificateRequest"), "test-dms").
		Return(issuedCert, nil)
	// Protection provider returns a 2-cert chain: [leaf, issuer].
	svc.On("LWCProtectionCredentials", "test-dms").
		Return([]*x509.Certificate{leafCert, issuerCert}, crypto.Signer(leafKey), nil)

	router := newTestRouter(svc)
	irDER, _, _ := buildTestIR(t, testIROptions{CN: "device-chain-test"})

	resp := postCMP(t, router, "test-dms", irDER)
	require.Equal(t, http.StatusOK, resp.Code)

	extraCertsCount := parseExtraCertsCount(t, resp.Body.Bytes())
	assert.Equal(t, 2, extraCertsCount, "extraCerts must contain the full chain (leaf + issuer)")

	svc.AssertExpectations(t)
}

