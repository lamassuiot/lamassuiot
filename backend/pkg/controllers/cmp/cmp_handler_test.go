package cmp

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	cmpwfx "github.com/lamassuiot/lamassuiot/backend/v3/pkg/integrations/wfx"
	corecmp "github.com/lamassuiot/lamassuiot/core/v3/pkg/cmp"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	cmpmock "github.com/lamassuiot/lamassuiot/core/v3/pkg/services/mock"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// newTestRouter sets up a Gin test engine with the CMP handler bound to
// /.well-known/cmp/p/:id. A minimal in-memory transaction store is always
// attached because NewCMPHttpRoutes now requires one (audit A5 — running
// without a store silently disabled duplicate-tx detection in production).
// Tests that don't exercise the store path simply ignore it.
func newTestRouter(svc *cmpmock.MockLightweightCMPService) *gin.Engine {
	store := newInMemoryCMPStore()
	wrapped := &mockServiceWithStore{MockLightweightCMPService: svc, store: store}
	gin.SetMode(gin.TestMode)
	r := gin.New()
	logger := logrus.NewEntry(logrus.New())
	routes, err := NewCMPHttpRoutes(logger, wrapped)
	if err != nil {
		panic(err)
	}
	r.POST("/.well-known/cmp/p/:id", routes.HandleCMP)
	return r
}

type captureWFXReporter struct {
	mu          sync.Mutex
	transitions []cmpwfx.CMPTransition
}

func (r *captureWFXReporter) Emit(_ context.Context, transition cmpwfx.CMPTransition) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	cloned := transition
	if transition.Metadata != nil {
		cloned.Metadata = make(map[string]any, len(transition.Metadata))
		for key, value := range transition.Metadata {
			cloned.Metadata[key] = value
		}
	}
	r.transitions = append(r.transitions, cloned)
	return "job-1", nil
}

func (r *captureWFXReporter) TransitionByState(state cmpwfx.CMPState) (cmpwfx.CMPTransition, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, transition := range r.transitions {
		if transition.State == state {
			return transition, true
		}
	}
	return cmpwfx.CMPTransition{}, false
}

type mockServiceWithStoreAndWFX struct {
	*cmpmock.MockLightweightCMPService
	store storage.CMPTransactionRepo
	wfx   cmpwfx.CMPReporter
}

func (m *mockServiceWithStoreAndWFX) GetCMPTransactionRepo() storage.CMPTransactionRepo {
	return m.store
}

func (m *mockServiceWithStoreAndWFX) GetCMPWFXReporter() cmpwfx.CMPReporter { return m.wfx }

func cmpMessageB64String(der []byte) string {
	return base64.StdEncoding.EncodeToString(der)
}

// mockProtectionServiceWithStore combines LightweightCMPProtectionProvider and
// cmpTransactionStorer for tests that exercise protected responses.
type mockProtectionServiceWithStore struct {
	*cmpmock.MockLightweightCMPServiceWithProtection
	store storage.CMPTransactionRepo
}

func (m *mockProtectionServiceWithStore) GetCMPTransactionRepo() storage.CMPTransactionRepo {
	return m.store
}

// buildPOPOSigningKey builds a POPOSigningKey [1] for a CertReqMsg.
// POPOSigningKey ::= SEQUENCE { algorithmIdentifier AlgorithmIdentifier, signature BIT STRING }
// The signature is ECDSA-SHA256 over certRequestDER.
// If corrupt is true, the signature bytes are intentionally mangled.
func buildPOPOSigningKey(t *testing.T, certRequestDER []byte, privKey *ecdsa.PrivateKey, corrupt bool) []byte {
	t.Helper()

	// Sign certRequestDER with ECDSA-SHA256.
	digest := sha256.Sum256(certRequestDER)
	sig, err := privKey.Sign(rand.Reader, digest[:], crypto.SHA256)
	require.NoError(t, err)

	if corrupt {
		// Flip some bytes to make it invalid.
		sig[0] ^= 0xFF
		sig[len(sig)-1] ^= 0xFF
	}

	// AlgorithmIdentifier for ecdsaWithSHA256
	algID, err := asn1.Marshal(pkix.AlgorithmIdentifier{
		Algorithm: asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2},
	})
	require.NoError(t, err)

	// BIT STRING signature
	sigBits, err := asn1.Marshal(asn1.BitString{Bytes: sig, BitLength: len(sig) * 8})
	require.NoError(t, err)

	// POPOSigningKey is [1] IMPLICIT SEQUENCE { algId, signature }
	// The context-specific tag 1 wraps the content of the SEQUENCE.
	popoDER, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        1,
		IsCompound: true,
		Bytes:      concatBytes(algID, sigBits),
	})
	require.NoError(t, err)

	return popoDER
}

// injectProtectionAlgInHeader inserts protectionAlg [1] EXPLICIT AlgorithmIdentifier
// into a DER-encoded PKIHeader SEQUENCE, right after the first 3 TLVs (pvno, sender,
// recipient). If protectionAlg [1] is already present, the header is returned unchanged.
func injectProtectionAlgInHeader(t *testing.T, headerDER []byte, algOID asn1.ObjectIdentifier) []byte {
	t.Helper()

	var headerSeq asn1.RawValue
	_, err := asn1.Unmarshal(headerDER, &headerSeq)
	require.NoError(t, err)

	// Peel off the first 3 mandatory fields.
	remaining := headerSeq.Bytes
	var firstThree []byte
	for i := 0; i < 3; i++ {
		var field asn1.RawValue
		rest, e := asn1.Unmarshal(remaining, &field)
		require.NoError(t, e)
		firstThree = append(firstThree, field.FullBytes...)
		remaining = rest
	}

	// Check if protectionAlg [1] is already present.
	if len(remaining) > 0 {
		var peek asn1.RawValue
		_, _ = asn1.Unmarshal(remaining, &peek)
		if peek.Class == asn1.ClassContextSpecific && peek.Tag == 1 {
			return headerDER // already has protectionAlg
		}
	}

	// Build protectionAlg [1] EXPLICIT AlgorithmIdentifier
	algID, err := asn1.Marshal(pkix.AlgorithmIdentifier{Algorithm: algOID})
	require.NoError(t, err)
	protAlgField, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        1,
		IsCompound: true,
		Bytes:      algID,
	})
	require.NoError(t, err)

	newContent := concatBytes(firstThree, protAlgField, remaining)
	newHeaderDER, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      newContent,
	})
	require.NoError(t, err)
	return newHeaderDER
}

// injectSenderInHeader replaces the sender [1] field of a DER-encoded PKIHeader
// with a directoryName GeneralName carrying the given subject's RDNSequence.
// The PKIHeader has three mandatory fields (pvno, sender, recipient); we peel
// the first one, swap the second, and keep the remainder.
// injectSenderKIDInHeader inserts senderKID [2] EXPLICIT OCTET STRING into a
// DER-encoded PKIHeader, in tag order (after messageTime[0]/protectionAlg[1] if
// present). Mirrors what a real EE sets per RFC 9483 §3.1. No-op if ski is empty
// or senderKID [2] is already present.
func injectSenderKIDInHeader(t *testing.T, headerDER []byte, ski []byte) []byte {
	t.Helper()
	if len(ski) == 0 {
		return headerDER
	}

	var headerSeq asn1.RawValue
	_, err := asn1.Unmarshal(headerDER, &headerSeq)
	require.NoError(t, err)

	remaining := headerSeq.Bytes
	var prefix []byte
	// Keep the 3 mandatory fields (pvno, sender, recipient).
	for i := 0; i < 3; i++ {
		var field asn1.RawValue
		rest, e := asn1.Unmarshal(remaining, &field)
		require.NoError(t, e)
		prefix = append(prefix, field.FullBytes...)
		remaining = rest
	}
	// Keep any optional [0] messageTime / [1] protectionAlg so senderKID lands in
	// the correct tag order; bail if [2] already present.
	for len(remaining) > 0 {
		var peek asn1.RawValue
		_, e := asn1.Unmarshal(remaining, &peek)
		require.NoError(t, e)
		if peek.Class == asn1.ClassContextSpecific && peek.Tag == 2 {
			return headerDER
		}
		if peek.Class == asn1.ClassContextSpecific && (peek.Tag == 0 || peek.Tag == 1) {
			prefix = append(prefix, peek.FullBytes...)
			remaining = remaining[len(peek.FullBytes):]
			continue
		}
		break
	}

	octetStr, err := asn1.Marshal(ski) // []byte -> OCTET STRING
	require.NoError(t, err)
	kidField, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        2,
		IsCompound: true,
		Bytes:      octetStr,
	})
	require.NoError(t, err)

	newContent := concatBytes(prefix, kidField, remaining)
	newHeaderDER, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      newContent,
	})
	require.NoError(t, err)
	return newHeaderDER
}

func injectSenderInHeader(t *testing.T, headerDER []byte, subject pkix.Name) []byte {
	t.Helper()

	var headerSeq asn1.RawValue
	_, err := asn1.Unmarshal(headerDER, &headerSeq)
	require.NoError(t, err)

	// pvno (first TLV) — keep as-is.
	remaining := headerSeq.Bytes
	var pvnoField asn1.RawValue
	remaining, err = asn1.Unmarshal(remaining, &pvnoField)
	require.NoError(t, err)

	// sender (second TLV) — discard original, build replacement.
	var oldSender asn1.RawValue
	remaining, err = asn1.Unmarshal(remaining, &oldSender)
	require.NoError(t, err)

	// Build new sender as directoryName [4] EXPLICIT Name (= RDNSequence).
	rdnDER, err := asn1.Marshal(subject.ToRDNSequence())
	require.NoError(t, err)
	newSenderDER, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        4,
		IsCompound: true,
		Bytes:      rdnDER,
	})
	require.NoError(t, err)

	newContent := concatBytes(pvnoField.FullBytes, newSenderDER, remaining)
	newHeaderDER, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      newContent,
	})
	require.NoError(t, err)
	return newHeaderDER
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

// parseResponseBodyTag returns the PKIBody CHOICE tag of a CMP response.
// Useful for asserting whether the server replied with ip/cp (1/3), pollRep (26),
// or an error (23).
func parseResponseBodyTag(t *testing.T, responseDER []byte) int {
	t.Helper()
	type rawMsg struct {
		Header asn1.RawValue
		Body   asn1.RawValue
	}
	var msg rawMsg
	_, err := asn1.Unmarshal(responseDER, &msg)
	require.NoError(t, err)
	return msg.Body.Tag
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

// TestHandleCMP_ConfirmModes exercises the confirmation state machine across
// both enrollment operations (ir → IP → LWCEnroll; kur → KUP → LWCReenroll)
// and both confirmation modes (RFC 4210 §5.2.8):
//
//   - explicit: the DMS is not implicit and the EE omits id-it-implicitConfirm,
//     so the flow requires a certConf (tag 24) → pkiConf (tag 19) round-trip.
//   - implicit: the DMS is implicit and the EE includes id-it-implicitConfirm,
//     so the cert is usable immediately; the row is nonetheless born CONFIRMED
//     and persisted for lost-response recovery via pollReq (the confirmation
//     monitor never touches CONFIRMED rows).
func TestHandleCMP_ConfirmModes(t *testing.T) {
	tests := []struct {
		name     string
		op       string // "ir" | "kur"
		implicit bool
		cn       string
	}{
		{name: "IR_ExplicitConfirm", op: "ir", implicit: false, cn: "test-device-explicit"},
		{name: "IR_ImplicitConfirm", op: "ir", implicit: true, cn: "test-device"},
		{name: "KUR_ExplicitConfirm", op: "kur", implicit: false, cn: "device-reenroll"},
		{name: "KUR_ImplicitConfirm", op: "kur", implicit: true, cn: "device-reenroll-implicit"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			issuedCert, _ := buildSelfSignedCert(t, tc.cn)
			opts := models.EnrollmentOptionsLWCRFC9483{AcceptImplicit: tc.implicit}

			var router *gin.Engine
			var store *inMemoryCMPStore
			var svc *cmpmock.MockLightweightCMPService
			var wantTag int
			var reqDER []byte
			txID := randomTxID(t)
			reqOpts := testIROptions{CN: tc.cn, TransactionID: txID, WithImplicitConfirm: tc.implicit}

			if tc.op == "kur" {
				router, store, svc = newReenrollRouter(t, opts, issuedCert)
				wantTag = corecmp.BodyTagKUP
				// kur is unconditionally signature-protected (RFC 9483 §4.1.3:
				// the message protection IS the proof of possession) — sign
				// with an arbitrary certificate; the mock's LWCReenroll
				// expectation matches any signer.
				signerCert, signerKey := buildSelfSignedCert(t, tc.cn+"-signer")
				reqDER = signCMPMessage(t, buildTestKUR(t, reqOpts), signerCert, signerKey)
			} else {
				router, store, svc = newEnrollRouter(t, opts, issuedCert)
				wantTag = corecmp.BodyTagIP
				reqDER, _, _ = buildTestIR(t, reqOpts)
			}

			resp := postCMP(t, router, "test-dms", reqDER)
			require.Equal(t, http.StatusOK, resp.Code)
			assert.Equal(t, wantTag, parseCMPResponseTag(t, resp.Body.Bytes()),
				"initial response must carry the operation's cert-response tag")

			if tc.implicit {
				// Row is born CONFIRMED and persists for pollReq recovery.
				storedTx, found := store.Peek(hex.EncodeToString(txID))
				assert.True(t, found, "implicit confirm must persist a row for pollReq recovery")
				if found {
					assert.Equal(t, models.CMPTransactionStateConfirmed, storedTx.State)
					assert.NotNil(t, storedTx.Certificate)
				}
			} else {
				// Explicit confirm: certConf with the correct hash → pkiConf. The
				// recipNonce must echo the server-chosen senderNonce (RFC 4210 §5.1.1).
				sentNonce := peekSentNonce(t, store, txID)
				certConfDER := buildTestCertConf(t, txID, issuedCert.Raw, sentNonce)
				confResp := postCMP(t, router, "test-dms", certConfDER)
				require.Equal(t, http.StatusOK, confResp.Code)
				assert.Equal(t, corecmp.BodyTagPKIConf, parseCMPResponseTag(t, confResp.Body.Bytes()),
					"certConf with correct hash must receive pkiConf")
			}

			svc.AssertExpectations(t)
		})
	}
}

func TestHandleCMP_WFXStoresCMPPayloads(t *testing.T) {
	issuedCert, _ := buildSelfSignedCert(t, "device-wfx-payloads")

	svc := &cmpmock.MockLightweightCMPService{}
	svc.On("LWCGetEnrollmentOptions", mock.Anything, "test-dms").
		Return(resolvedOpts(models.EnrollmentOptionsLWCRFC9483{AcceptImplicit: false}), nil)
	svc.On("LWCEnroll", mock.Anything, mock.AnythingOfType("*x509.CertificateRequest"), "test-dms", mock.Anything).
		Return(issuedCert, nil)

	reporter := &captureWFXReporter{}
	router, store := newTestRouterWithStoreAndWFX(svc, reporter)
	txID := randomTxID(t)

	irDER, _, _ := buildTestIR(t, testIROptions{CN: "device-wfx-payloads", TransactionID: txID})
	irResp := postCMP(t, router, "test-dms", irDER)
	require.Equal(t, http.StatusOK, irResp.Code)

	sentNonce := peekSentNonce(t, store, txID)
	certConfDER := buildTestCertConf(t, txID, issuedCert.Raw, sentNonce)
	confResp := postCMP(t, router, "test-dms", certConfDER)
	require.Equal(t, http.StatusOK, confResp.Code)

	receivedTransition, ok := reporter.TransitionByState(cmpwfx.CMPStateReceived)
	require.True(t, ok, "received transition must be emitted")
	assert.Equal(t, cmpMessageB64String(irDER), receivedTransition.Metadata[cmpMetadataRequestB64])

	respondedTransition, ok := reporter.TransitionByState(cmpwfx.CMPStateResponded)
	require.True(t, ok, "responded transition must be emitted")
	assert.Equal(t, cmpMessageB64String(irResp.Body.Bytes()), respondedTransition.Metadata[cmpMetadataResponseB64])

	confirmedTransition, ok := reporter.TransitionByState(cmpwfx.CMPStateConfirmed)
	require.True(t, ok, "confirmed transition must be emitted")
	assert.Equal(t, cmpMessageB64String(certConfDER), confirmedTransition.Metadata[cmpMetadataCertConfB64])
	assert.Equal(t, cmpMessageB64String(confResp.Body.Bytes()), confirmedTransition.Metadata[cmpMetadataPKIConfB64])

	svc.AssertExpectations(t)
}

func TestHandleCMP_Protection(t *testing.T) {
	tests := []struct {
		name        string
		authMode    models.CMPAuthMode
		protMode    string // "none" | "valid" | "wrongkey" | "mac"
		cn          string
		accepted    bool
		reasonMatch string // expected substring in the error reason (rejected only)
	}{
		// Cycle 2/3: permissive auth_mode, signature-based protection.
		{name: "ProtectionVerification_ValidSignature", protMode: "valid", cn: "device-sig-valid", accepted: true},
		{name: "ProtectionVerification_InvalidSignature", protMode: "wrongkey", cn: "device-bad-sig", accepted: false, reasonMatch: "protection"},
		{name: "ProtectionVerification_NoProtection", protMode: "none", cn: "device-no-prot", accepted: true},
		// Cycle 5: auth_mode=CLIENT_CERTIFICATE makes protection mandatory.
		{name: "EnforceProtection_RejectsUnprotected", authMode: models.CMPAuthModeClientCertificate, protMode: "none", cn: "device-no-prot-enforced", accepted: false, reasonMatch: "protection"},
		{name: "EnforceProtection_AcceptsSignedRequest", authMode: models.CMPAuthModeClientCertificate, protMode: "valid", cn: "device-enforce-ok", accepted: true},
		// Cycle 6: MAC-based protection is always rejected.
		{name: "MACProtection_Rejected", protMode: "mac", cn: "device-mac", accepted: false, reasonMatch: "MAC"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			opts := models.EnrollmentOptionsLWCRFC9483{AuthMode: tc.authMode}

			var router *gin.Engine
			var svc *cmpmock.MockLightweightCMPService
			if tc.accepted {
				issuedCert, _ := buildSelfSignedCert(t, tc.cn)
				router, _, svc = newEnrollRouter(t, opts, issuedCert)
			} else {
				router, _, svc = newOptionsRouter(t, opts)
			}

			irDER, _, _ := buildTestIR(t, testIROptions{CN: tc.cn})

			var msg []byte
			switch tc.protMode {
			case "none":
				msg = irDER
			case "valid":
				signerCert, signerKey := buildSelfSignedCert(t, "device-signer")
				msg = signCMPMessage(t, irDER, signerCert, signerKey)
			case "wrongkey":
				signerCert, _ := buildSelfSignedCert(t, "device-signer")
				// wrongKey does not match signerCert.PublicKey — signature invalid.
				_, wrongKey := buildSelfSignedCert(t, "wrong-key")
				msg = signCMPMessage(t, irDER, signerCert, wrongKey)
			case "mac":
				// A genuine MAC-protected message carries a protection value; we
				// attach a fake one so the message reaches the MAC-algorithm gate
				// rather than the "protection value absent" structural check.
				withAlg := injectProtectionAlgOID(t, irDER, corecmp.OIDPasswordBasedMAC())
				msg = attachFakeProtection(t, withAlg, []byte{0x00, 0xDE, 0xAD, 0xBE, 0xEF})
			default:
				t.Fatalf("unknown protMode %q", tc.protMode)
			}

			resp := postCMP(t, router, "test-dms", msg)
			require.Equal(t, http.StatusOK, resp.Code)

			if tc.accepted {
				assert.Equal(t, corecmp.BodyTagIP, parseCMPResponseTag(t, resp.Body.Bytes()),
					"accepted protection state must yield an IP response")
				svc.AssertExpectations(t)
				return
			}

			assert.Equal(t, corecmp.BodyTagError, parseCMPResponseTag(t, resp.Body.Bytes()),
				"rejected protection state must yield a CMP error body")
			assert.Contains(t, parseCMPErrorReason(t, resp.Body.Bytes()), tc.reasonMatch,
				"error reason must reference the protection failure")
			svc.AssertNotCalled(t, "LWCEnroll", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
		})
	}
}

// TestHandleCMP_Response_ExtraCertsContainsChain verifies that when the DMS
// implements LightweightCMPProtectionProvider and returns a multi-cert chain,
// ALL certificates (leaf + intermediates/root) are placed in the response
// extraCerts field. This allows EE clients to verify the RA’s signature
// without needing to pre-configure the entire trust chain locally.
func TestHandleCMP_Response_ExtraCertsContainsChain(t *testing.T) {
	issuedCert, _ := buildSelfSignedCert(t, "device-chain-test")
	leafCert, leafKey := buildSelfSignedCert(t, "cmp-protection-leaf")
	issuerCert, _ := buildSelfSignedCert(t, "cmp-protection-issuer")

	svc := &cmpmock.MockLightweightCMPServiceWithProtection{}
	svc.On("LWCGetEnrollmentOptions", mock.Anything, "test-dms").
		Return(resolvedOpts(models.EnrollmentOptionsLWCRFC9483{}), nil)
	svc.On("LWCEnroll", mock.Anything, mock.AnythingOfType("*x509.CertificateRequest"), "test-dms", mock.Anything).
		Return(issuedCert, nil)
	// Protection provider returns a 2-cert chain: [leaf, issuer].
	svc.On("LWCProtectionCredentials", mock.Anything, "test-dms").
		Return([]*x509.Certificate{leafCert, issuerCert}, crypto.Signer(leafKey), nil)

	router, _ := newTestRouterWithProtectionAndStore(svc)
	irDER, _, _ := buildTestIR(t, testIROptions{CN: "device-chain-test"})

	resp := postCMP(t, router, "test-dms", irDER)
	require.Equal(t, http.StatusOK, resp.Code)

	extraCertsCount := parseExtraCertsCount(t, resp.Body.Bytes())
	assert.Equal(t, 2, extraCertsCount, "extraCerts must contain the full chain (leaf + issuer)")

	svc.AssertExpectations(t)
}

// buildTestKUR constructs a minimal KUR PKIMessage (tag 7) from IR options.
func buildTestKUR(t *testing.T, opts testIROptions) []byte {
	t.Helper()

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	pubKeyDER, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	require.NoError(t, err)

	cn := opts.CN
	if cn == "" {
		cn = "test-device-kur"
	}
	txID := opts.TransactionID
	if len(txID) == 0 {
		txID = make([]byte, 16)
		rand.Read(txID)
	}

	senderNonce := randomNonce(t)

	headerDER := buildTestPKIHeaderDER(t, txID, senderNonce, nil, opts.WithImplicitConfirm)

	// KUR body uses the same CertReqMessages structure as IR, but with tag 7.
	bodyContent := buildTestIRBodyContent(t, cn, pubKeyDER)
	bodyDER, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        corecmp.BodyTagKUR,
		IsCompound: true,
		Bytes:      bodyContent,
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

// buildTestIRBodyContent returns the inner CertReqMessages SEQUENCE bytes
// (without the outer body CHOICE tag wrapper) so callers can wrap it in IR (0)
// or KUR (7).
func buildTestIRBodyContent(t *testing.T, cn string, pubKeyDER []byte) []byte {
	t.Helper()
	return wrapCertReqMsgs(t, buildCertRequestDER(t, cn, pubKeyDER))
}

// TestHandleCMP_DuplicateTransactionID verifies the replay-attack prevention
// mechanism (RFC 4210 §3.1 "transactionIdInUse"): a second IR carrying the
// same transactionID is rejected while the first is still pending certConf.
// This prevents duplicate certificate issuance from retransmitted requests.
func TestHandleCMP_DuplicateTransactionID(t *testing.T) {
	issuedCert, _ := buildSelfSignedCert(t, "device-dup-tx")

	router, _, _ := newEnrollRouter(t, models.EnrollmentOptionsLWCRFC9483{AcceptImplicit: false}, issuedCert)
	txID := randomTxID(t)

	// First IR succeeds.
	ir1, _, _ := buildTestIR(t, testIROptions{CN: "device-dup-tx", TransactionID: txID})
	resp1 := postCMP(t, router, "test-dms", ir1)
	require.Equal(t, http.StatusOK, resp1.Code)
	assert.Equal(t, corecmp.BodyTagIP, parseCMPResponseTag(t, resp1.Body.Bytes()))

	// Second IR with same txID rejected.
	ir2, _, _ := buildTestIR(t, testIROptions{CN: "device-dup-tx-2", TransactionID: txID})
	resp2 := postCMP(t, router, "test-dms", ir2)
	require.Equal(t, http.StatusOK, resp2.Code)
	assert.Equal(t, corecmp.BodyTagError, parseCMPResponseTag(t, resp2.Body.Bytes()),
		"duplicate transactionID must be rejected")
	assert.Contains(t, parseCMPErrorReason(t, resp2.Body.Bytes()), "transactionID already in use")
}

// TestHandleCMP_CertConf_WrongHash verifies the integrity check in certConf
// processing (RFC 4210 §5.2.8): when the SHA-256 certHash in the client’s
// certConf message does NOT match the hash of the issued certificate stored
// server-side, the handler returns a CMP error with "certHash mismatch".
// This detects certificate corruption or man-in-the-middle attacks.
func TestHandleCMP_CertConf_WrongHash(t *testing.T) {
	issuedCert, _ := buildSelfSignedCert(t, "device-wrong-hash")
	wrongCert, _ := buildSelfSignedCert(t, "wrong-cert")

	router, store, _ := newEnrollRouter(t, models.EnrollmentOptionsLWCRFC9483{AcceptImplicit: false}, issuedCert)
	txID := randomTxID(t)

	irDER, _, _ := buildTestIR(t, testIROptions{CN: "device-wrong-hash", TransactionID: txID})
	irResp := postCMP(t, router, "test-dms", irDER)
	require.Equal(t, http.StatusOK, irResp.Code)
	assert.Equal(t, corecmp.BodyTagIP, parseCMPResponseTag(t, irResp.Body.Bytes()))

	storedTx, ok := store.Peek(hex.EncodeToString(txID))
	require.True(t, ok)

	// Build certConf with hash of wrongCert — mismatch.
	sentNonce, _ := hex.DecodeString(storedTx.SentNonce)
	certConfDER := buildTestCertConf(t, txID, wrongCert.Raw, sentNonce)
	confResp := postCMP(t, router, "test-dms", certConfDER)
	require.Equal(t, http.StatusOK, confResp.Code)
	assert.Equal(t, corecmp.BodyTagError, parseCMPResponseTag(t, confResp.Body.Bytes()),
		"wrong certHash must be rejected")
	assert.Contains(t, parseCMPErrorReason(t, confResp.Body.Bytes()), "certHash mismatch")
}

// TestHandleCMP_UnsupportedBodyTag verifies that any body CHOICE tag not
// handled by the dispatcher (i.e. not ir/cr/kur/rr/certConf) returns a CMP
// error body (tag 23) with "unsupported body tag". This covers
// forward-compatibility: new RFC body types are safely rejected until
// explicitly implemented.
func TestHandleCMP_UnsupportedBodyTag(t *testing.T) {
	router, _, _ := newOptionsRouter(t, models.EnrollmentOptionsLWCRFC9483{})

	// Build a message with body tag 99 (completely unsupported).
	txID := randomTxID(t)
	senderNonce := randomNonce(t)
	headerDER := buildTestPKIHeaderDER(t, txID, senderNonce, nil, false)

	bodyDER, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        99,
		IsCompound: true,
		Bytes:      []byte{0x05, 0x00}, // NULL payload
	})
	require.NoError(t, err)

	msgDER, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      concatBytes(headerDER, bodyDER),
	})
	require.NoError(t, err)

	resp := postCMP(t, router, "test-dms", msgDER)
	require.Equal(t, http.StatusOK, resp.Code)
	assert.Equal(t, corecmp.BodyTagError, parseCMPResponseTag(t, resp.Body.Bytes()),
		"unsupported body tag must return CMP error")
	assert.Contains(t, parseCMPErrorReason(t, resp.Body.Bytes()), "unsupported body tag")
}

// TestHandleCMP_CertConf_RecipNonceMismatch verifies RFC 4210 §5.1.1 nonce
// replay protection: the EE’s certConf MUST echo the server’s previous
// senderNonce as recipNonce. When the nonces do not match, the handler
// rejects with "recipNonce mismatch", preventing replay of captured responses.
func TestHandleCMP_CertConf_RecipNonceMismatch(t *testing.T) {
	issuedCert, _ := buildSelfSignedCert(t, "device-nonce-mismatch")

	router, _, _ := newEnrollRouter(t, models.EnrollmentOptionsLWCRFC9483{AcceptImplicit: false}, issuedCert)
	txID := randomTxID(t)

	irDER, _, _ := buildTestIR(t, testIROptions{CN: "device-nonce-mismatch", TransactionID: txID})
	irResp := postCMP(t, router, "test-dms", irDER)
	require.Equal(t, http.StatusOK, irResp.Code)
	assert.Equal(t, corecmp.BodyTagIP, parseCMPResponseTag(t, irResp.Body.Bytes()))

	// Build certConf with a random (wrong) recipNonce.
	wrongNonce := randomNonce(t)
	certConfDER := buildTestCertConf(t, txID, issuedCert.Raw, wrongNonce)
	confResp := postCMP(t, router, "test-dms", certConfDER)
	require.Equal(t, http.StatusOK, confResp.Code)
	assert.Equal(t, corecmp.BodyTagError, parseCMPResponseTag(t, confResp.Body.Bytes()),
		"wrong recipNonce must be rejected")
	assert.Contains(t, parseCMPErrorReason(t, confResp.Body.Bytes()), "recipNonce mismatch")
}

// TestHandleCMP_RR_Success verifies the happy-path revocation request flow
// (RFC 4210 §5.3.9): a valid rr (tag 11) carrying a known serial number and
// CRL reason triggers LWCRevokeCertificate and returns an rp (tag 12)
// response with PKIStatus=accepted (0).
func TestHandleCMP_RR_Success(t *testing.T) {
	svc := &cmpmock.MockLightweightCMPService{}
	svc.On("LWCGetEnrollmentOptions", mock.Anything, "test-dms").
		Return(resolvedOpts(models.EnrollmentOptionsLWCRFC9483{}), nil)
	svc.On("LWCRevokeCertificate", mock.Anything, mock.MatchedBy(func(input services.RevokeCertificateInput) bool {
		return input.APS == "test-dms" && input.Reason == models.RevocationReason(1) // KeyCompromise
	}), mock.Anything).Return(nil)

	router, _ := newTestRouterWithStore(svc)

	serial := big.NewInt(0x1234ABCD)
	reason := 1 // KeyCompromise
	rrDER, _, _ := buildTestRRSelfRevocation(t, "rr-requester", serial, &reason)

	resp := postCMP(t, router, "test-dms", rrDER)
	require.Equal(t, http.StatusOK, resp.Code)
	assert.Equal(t, corecmp.BodyTagRP, parseCMPResponseTag(t, resp.Body.Bytes()),
		"valid rr must receive rp response")

	svc.AssertExpectations(t)
}

// TestHandleCMP_RR_ServiceError verifies that when the downstream
// LWCRevokeCertificate returns an error (e.g. certificate not found, already
// revoked), the CMP handler propagates it as a CMP error body (tag 23)
// containing the service error text.
func TestHandleCMP_RR_ServiceError(t *testing.T) {
	svc := &cmpmock.MockLightweightCMPService{}
	svc.On("LWCGetEnrollmentOptions", mock.Anything, "test-dms").
		Return(resolvedOpts(models.EnrollmentOptionsLWCRFC9483{}), nil)
	svc.On("LWCRevokeCertificate", mock.Anything, mock.Anything, mock.Anything).
		Return(fmt.Errorf("certificate not found"))

	router, _ := newTestRouterWithStore(svc)

	serial := big.NewInt(0xDEAD)
	reason := 0
	rrDER, _, _ := buildTestRRSelfRevocation(t, "rr-requester", serial, &reason)

	resp := postCMP(t, router, "test-dms", rrDER)
	require.Equal(t, http.StatusOK, resp.Code)
	// RFC 9483 §4.2: the response to an rr is always an rp body, even on
	// failure — the rejection is conveyed via the rp PKIStatusInfo, never via a
	// generic error body.
	assert.Equal(t, corecmp.BodyTagRP, parseCMPResponseTag(t, resp.Body.Bytes()),
		"failed revocation must return an rp body with rejection status")
	var rpMsg corecmp.RawPKIMessage
	_, err := asn1.Unmarshal(resp.Body.Bytes(), &rpMsg)
	require.NoError(t, err)
	assert.Contains(t, scanFirstUTF8String(rpMsg.Body.Bytes), "certificate not found",
		"rp statusString must carry the revocation failure reason")
}

// TestHandleCMP_RR_DefaultReason verifies that when the rr body’s
// crlEntryDetails extensions are absent (no CRL reason OID), the revocation
// reason defaults to 0 (Unspecified) per RFC 5280 §5.3.1.
func TestHandleCMP_RR_DefaultReason(t *testing.T) {
	svc := &cmpmock.MockLightweightCMPService{}
	svc.On("LWCGetEnrollmentOptions", mock.Anything, "test-dms").
		Return(resolvedOpts(models.EnrollmentOptionsLWCRFC9483{}), nil)
	svc.On("LWCRevokeCertificate", mock.Anything, mock.MatchedBy(func(input services.RevokeCertificateInput) bool {
		return input.Reason == models.RevocationReason(0) // Unspecified
	}), mock.Anything).Return(nil)

	router, _ := newTestRouterWithStore(svc)

	serial := big.NewInt(42)
	rrDER, _, _ := buildTestRRSelfRevocation(t, "rr-requester", serial, nil) // no crlEntryDetails

	resp := postCMP(t, router, "test-dms", rrDER)
	require.Equal(t, http.StatusOK, resp.Code)
	assert.Equal(t, corecmp.BodyTagRP, parseCMPResponseTag(t, resp.Body.Bytes()))

	svc.AssertExpectations(t)
}

// buildTestRR constructs a DER-encoded PKIMessage with an rr (tag 11) body
// carrying a CertTemplate with the given serial number and a CRL reason extension.
func buildTestRR(t *testing.T, serial *big.Int, reason int) []byte {
	t.Helper()

	txID := randomTxID(t)
	senderNonce := randomNonce(t)

	headerDER := buildTestPKIHeaderDER(t, txID, senderNonce, nil, false)
	bodyDER := buildTestRRBodyDER(t, serial, &reason)

	msgDER, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      concatBytes(headerDER, bodyDER),
	})
	require.NoError(t, err)
	return msgDER
}

// buildTestRRNoReason constructs an rr PKIMessage without crlEntryDetails.
func buildTestRRNoReason(t *testing.T, serial *big.Int) []byte {
	t.Helper()

	txID := randomTxID(t)
	senderNonce := randomNonce(t)

	headerDER := buildTestPKIHeaderDER(t, txID, senderNonce, nil, false)
	bodyDER := buildTestRRBodyDER(t, serial, nil)

	msgDER, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      concatBytes(headerDER, bodyDER),
	})
	require.NoError(t, err)
	return msgDER
}

// buildTestRRBodyDER encodes an rr PKIBody (tag 11).
// RevReqContent ::= SEQUENCE OF RevDetails
// RevDetails    ::= SEQUENCE { certDetails CertTemplate, crlEntryDetails Extensions OPTIONAL }
// CertTemplate fields: serialNumber [1]
func buildTestRRBodyDER(t *testing.T, serial *big.Int, reason *int) []byte {
	t.Helper()

	// Encode serialNumber as INTEGER.
	serialDER, err := asn1.Marshal(serial)
	require.NoError(t, err)
	// Wrap as CertTemplate [1] IMPLICIT serialNumber.
	serialField, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        1,
		IsCompound: true,
		Bytes:      serialDER,
	})
	require.NoError(t, err)

	certTemplateContent := serialField

	certTemplateDER, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      certTemplateContent,
	})
	require.NoError(t, err)

	revDetailsContent := certTemplateDER

	// Optionally add crlEntryDetails Extensions.
	if reason != nil {
		extDER := buildCRLReasonExtension(t, *reason)
		revDetailsContent = append(revDetailsContent, extDER...)
	}

	revDetailsDER, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      revDetailsContent,
	})
	require.NoError(t, err)

	// SEQUENCE OF RevDetails (single entry)
	revReqContentDER, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      revDetailsDER,
	})
	require.NoError(t, err)

	// PKIBody rr [11]
	bodyDER, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        corecmp.BodyTagRR,
		IsCompound: true,
		Bytes:      revReqContentDER,
	})
	require.NoError(t, err)
	return bodyDER
}

// TestHandleCMP_POPO exercises the Proof-of-Possession handling for IR bodies
// across every POPOMode. Accepted cases (valid POPOSigningKey, or absent POPO
// when EnforcePOPO=false) must yield an ip carrying the cert and reach
// LWCEnroll; rejected cases must yield an ip CertRepMessage whose statusString
// references "proof of possession", carry the expected failInfo bit, and never
// reach LWCEnroll.
func TestHandleCMP_POPO(t *testing.T) {
	tests := []struct {
		name        string
		enforcePOPO bool
		popoMode    string
		cn          string
		accepted    bool
		failInfoBit int
	}{
		// Cycle 13: valid POPOSigningKey signature → accepted.
		{name: "ValidSignature", enforcePOPO: true, popoMode: "signature", cn: "device-popo-valid", accepted: true},
		// Cycle 14: corrupt signature → badPOP (9).
		{name: "InvalidSignature", enforcePOPO: true, popoMode: "badsig", cn: "device-popo-badsig", accepted: false, failInfoBit: corecmp.PKIFailureInfoBadPOP},
		// Cycle 15: POPO absent + EnforcePOPO=true → badPOP (9).
		{name: "Absent_Enforced", enforcePOPO: true, popoMode: "", cn: "device-popo-absent", accepted: false, failInfoBit: corecmp.PKIFailureInfoBadPOP},
		// Cycle 16: POPO absent + EnforcePOPO=false → accepted (mTLS proves possession).
		{name: "Absent_NotEnforced", enforcePOPO: false, popoMode: "", cn: "device-popo-notenforced", accepted: true},
		// Cycle 17: raVerified asserted by an EE → notAuthorized (23).
		{name: "RAVerified", enforcePOPO: true, popoMode: "raVerified", cn: "device-popo-raverified", accepted: false, failInfoBit: corecmp.PKIFailureInfoNotAuthorized},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// RFC011: IR.ProofOfPossession.Required is what actually gates ir/cr
			// POPO enforcement now (EnforcePOPO is the pre-RFC011 legacy flag,
			// kept here for documentation/back-compat but no longer consulted
			// for ir/cr).
			opts := models.EnrollmentOptionsLWCRFC9483{
				EnforcePOPO:    tc.enforcePOPO,
				AcceptImplicit: true,
				IR:             models.CMPIRSettings{ProofOfPossession: models.CMPProofOfPossession{Required: tc.enforcePOPO}},
			}

			var router *gin.Engine
			var svc *cmpmock.MockLightweightCMPService
			if tc.accepted {
				issuedCert, _ := buildSelfSignedCert(t, tc.cn)
				router, _, svc = newEnrollRouter(t, opts, issuedCert)
			} else {
				router, _, svc = newOptionsRouter(t, opts)
			}

			irDER, _, _ := buildTestIR(t, testIROptions{
				CN:                  tc.cn,
				WithImplicitConfirm: true,
				POPOMode:            tc.popoMode,
			})

			resp := postCMP(t, router, "test-dms", irDER)
			require.Equal(t, http.StatusOK, resp.Code)
			// Both accepted and rejected IR results are delivered inside an ip
			// CertRepMessage (rejections are surfaced per-CertResponse, not as a
			// top-level error body).
			assert.Equal(t, corecmp.BodyTagIP, parseCMPResponseTag(t, resp.Body.Bytes()))

			if tc.accepted {
				svc.AssertExpectations(t)
				return
			}

			reason, fi := parseCertRepRejection(t, resp.Body.Bytes())
			assert.Contains(t, reason, "proof of possession", "statusString must reference POPO")
			assert.True(t, bitSet(fi, tc.failInfoBit), "failInfo must set the expected bit")
			svc.AssertNotCalled(t, "LWCEnroll", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
		})
	}
}

// TestHandleCMP_KUR_POPO covers the three KUR/EnforcePOPO combinations.
func TestHandleCMP_KUR_POPO(t *testing.T) {
	tests := []struct {
		name        string
		enforcePOPO bool
		signed      bool
		cn          string
		accepted    bool
	}{
		// Cycle 18: EnforcePOPO=true + unprotected → rejected (no proof of possession).
		{name: "EnforcePOPO_RejectsUnprotected", enforcePOPO: true, signed: false, cn: "device-kur-popo-reject", accepted: false},
		// Cycle 19: EnforcePOPO=true + valid protection → accepted.
		{name: "EnforcePOPO_AcceptsProtected", enforcePOPO: true, signed: true, cn: "device-kur-popo-ok", accepted: true},
		// Security regression test: a kur's signature-based protection IS its
		// proof of possession (RFC 9483 §4.1.3) and is a FIXED protocol
		// invariant — unlike ir/cr/p10cr, it is never gated by EnforcePOPO or
		// the DMS auth_mode (mirroring rr). Before this test, EnforcePOPO=false
		// let an entirely unsigned kur reach LWCReenroll, which used the
		// request's own CertTemplate CommonName to pick a target device with
		// zero authentication — a full device-identity takeover via one
		// unauthenticated request. See cmp.go's requireProtection override.
		{name: "NoPOPO_StillRequiresProtection", enforcePOPO: false, signed: false, cn: "device-kur-nopopo", accepted: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			opts := models.EnrollmentOptionsLWCRFC9483{EnforcePOPO: tc.enforcePOPO, AcceptImplicit: true}

			var router *gin.Engine
			var svc *cmpmock.MockLightweightCMPService
			if tc.accepted {
				issuedCert, _ := buildSelfSignedCert(t, tc.cn)
				router, _, svc = newReenrollRouter(t, opts, issuedCert)
			} else {
				router, _, svc = newOptionsRouter(t, opts)
			}

			kurDER := buildTestKUR(t, testIROptions{
				CN:                  tc.cn,
				WithImplicitConfirm: true,
			})

			msg := kurDER
			if tc.signed {
				signerCert, signerKey := buildSelfSignedCert(t, "device-kur-signer")
				msg = signCMPMessage(t, kurDER, signerCert, signerKey)
			}

			resp := postCMP(t, router, "test-dms", msg)
			require.Equal(t, http.StatusOK, resp.Code)

			if tc.accepted {
				assert.Equal(t, corecmp.BodyTagKUP, parseCMPResponseTag(t, resp.Body.Bytes()),
					"accepted KUR must be answered with a kup body")
				svc.AssertExpectations(t)
				return
			}

			assert.Equal(t, corecmp.BodyTagError, parseCMPResponseTag(t, resp.Body.Bytes()),
				"unprotected KUR must be rejected")
			assert.Contains(t, parseCMPErrorReason(t, resp.Body.Bytes()), "protection",
				"error must reference the message-protection requirement")
			svc.AssertNotCalled(t, "LWCReenroll", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
		})
	}
}

// buildCRLReasonExtension encodes an Extensions SEQUENCE containing id-ce-CRLReasons.
func buildCRLReasonExtension(t *testing.T, reason int) []byte {
	t.Helper()

	// The extnValue is an OCTET STRING wrapping an ENUMERATED.
	enumDER, err := asn1.Marshal(asn1.Enumerated(reason))
	require.NoError(t, err)
	extnValueDER, err := asn1.Marshal(enumDER) // OCTET STRING wrapping the DER
	require.NoError(t, err)

	oidCRLReason := asn1.ObjectIdentifier{2, 5, 29, 21}
	oidDER, err := asn1.Marshal(oidCRLReason)
	require.NoError(t, err)

	// Extension ::= SEQUENCE { extnID OID, extnValue OCTET STRING }
	extSeqDER, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      concatBytes(oidDER, extnValueDER),
	})
	require.NoError(t, err)

	// Extensions ::= SEQUENCE OF Extension
	extsDER, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      extSeqDER,
	})
	require.NoError(t, err)

	return extsDER
}

// TestHandleCMP_PollReq_WhileIssued_DeliversCert verifies that a pollReq
// against an ISSUED row delivers the cert in an ip/cp body. The row stays in
// the store afterwards so certConf can still operate.
func TestHandleCMP_PollReq_WhileIssued_DeliversCert(t *testing.T) {
	issuedCert, _ := buildSelfSignedCert(t, "recovery-device-001")

	router, store, _ := newOptionsRouter(t, models.EnrollmentOptionsLWCRFC9483{})

	txID := randomTxID(t)
	require.NoError(t, store.Insert(context.Background(), models.CMPTransaction{
		TransactionID: hex.EncodeToString(txID),
		DMSID:         "test-dms",
		State:         models.CMPTransactionStateIssued,
		Certificate:   (*models.X509Certificate)(issuedCert),
		ExpiresAt:     time.Now().Add(5 * time.Minute),
		CreatedAt:     time.Now(),
	}))

	pollDER := buildTestPollReq(t, txID, 0)
	resp := postCMP(t, router, "test-dms", pollDER)

	require.Equal(t, http.StatusOK, resp.Code)
	tag := parseResponseBodyTag(t, resp.Body.Bytes())
	assert.Contains(t, []int{corecmp.BodyTagIP, corecmp.BodyTagCP}, tag,
		"ISSUED-state pollReq must deliver via ip or cp")
	status, hasCKP := parseIPBodyStatus(t, resp.Body.Bytes())
	assert.Equal(t, corecmp.PKIStatusAccepted, status, "delivered cert response must be accepted (0)")
	assert.True(t, hasCKP, "delivered response must carry CertifiedKeyPair with the cert")

	// Row remains so certConf can verify against it.
	_, still := store.Peek(hex.EncodeToString(txID))
	assert.True(t, still, "pollReq delivery must not delete the row")
}

// TestHandleCMP_PollReq_UnknownTxID_ReturnsError verifies that a pollReq
// referring to no known transaction is rejected with an error PKIMessage
// rather than a stalled response or a 500.
func TestHandleCMP_PollReq_UnknownTxID_ReturnsError(t *testing.T) {
	router, _, _ := newOptionsRouter(t, models.EnrollmentOptionsLWCRFC9483{})

	unknownTxID := randomTxID(t)

	pollDER := buildTestPollReq(t, unknownTxID, 0)
	resp := postCMP(t, router, "test-dms", pollDER)

	require.Equal(t, http.StatusOK, resp.Code)
	assert.Equal(t, corecmp.BodyTagError, parseResponseBodyTag(t, resp.Body.Bytes()),
		"unknown transactionID on pollReq must yield a CMP error body")
}

// TestHandleCMP_PollReq_IssueFailed_ReturnsErrorWithReason verifies that an
// ISSUE_FAILED row (kept for forward-compatibility with future async
// reintroduction) surfaces the failure reason in an error PKIMessage.
func TestHandleCMP_PollReq_IssueFailed_ReturnsErrorWithReason(t *testing.T) {
	router, store, _ := newOptionsRouter(t, models.EnrollmentOptionsLWCRFC9483{})

	txID := randomTxID(t)
	require.NoError(t, store.Insert(context.Background(), models.CMPTransaction{
		TransactionID: hex.EncodeToString(txID),
		DMSID:         "test-dms",
		State:         models.CMPTransactionStateIssueFailed,
		ErrorMessage:  "CA returned: profile constraint violated",
		ExpiresAt:     time.Now().Add(5 * time.Minute),
		CreatedAt:     time.Now(),
	}))

	pollDER := buildTestPollReq(t, txID, 0)
	resp := postCMP(t, router, "test-dms", pollDER)

	require.Equal(t, http.StatusOK, resp.Code)
	assert.Equal(t, corecmp.BodyTagError, parseResponseBodyTag(t, resp.Body.Bytes()),
		"ISSUE_FAILED state must produce a CMP error body, not pollRep")
}

// TestHandleCMP_PollReq_Revoked_ReturnsCertRevoked verifies that polling a
// transaction whose certificate was rolled back (certConf window elapsed →
// confirmation monitor revoked it, or revoked via the API) yields a precise
// certRevoked error rather than the generic unknown-state systemFailure.
// Regression: a phased-workflow EE whose approval window expired between polls
// used to receive "internal error: unknown transaction state".
func TestHandleCMP_PollReq_Revoked_ReturnsCertRevoked(t *testing.T) {
	revokedCert, _ := buildSelfSignedCert(t, "revoked-device-001")

	router, store, _ := newOptionsRouter(t, models.EnrollmentOptionsLWCRFC9483{})

	txID := randomTxID(t)
	require.NoError(t, store.Insert(context.Background(), models.CMPTransaction{
		TransactionID: hex.EncodeToString(txID),
		DMSID:         "test-dms",
		State:         models.CMPTransactionStateRevoked,
		Certificate:   (*models.X509Certificate)(revokedCert),
		ExpiresAt:     time.Now().Add(5 * time.Minute),
		CreatedAt:     time.Now(),
	}))

	pollDER := buildTestPollReq(t, txID, 0)
	resp := postCMP(t, router, "test-dms", pollDER)

	require.Equal(t, http.StatusOK, resp.Code)
	assert.Equal(t, corecmp.BodyTagError, parseResponseBodyTag(t, resp.Body.Bytes()),
		"REVOKED state must produce a CMP error body, not pollRep")
	fi := parseFailInfoBitString(t, resp.Body.Bytes())
	assert.True(t, bitSet(fi, corecmp.PKIFailureInfoCertRevoked),
		"failInfo must set certRevoked (10), not systemFailure")
}

// TestHandleCMP_PhasedWorkflow_DefersIssuance verifies that a DMS configured
// with the phased (admin-gated) workflow does NOT issue inline: the IR is
// parked as a PENDING transaction carrying the CSR, the EE receives an IP
// "waiting" response, and LWCEnroll is never called (issuance is deferred
// until an administrator approves). RFC 9483 §4.4 / RFC 4210 §5.3.22.
func TestHandleCMP_PhasedWorkflow_DefersIssuance(t *testing.T) {
	svc := &cmpmock.MockLightweightCMPService{}
	svc.On("LWCGetEnrollmentOptions", mock.Anything, "test-dms").
		Return(resolvedOpts(models.EnrollmentOptionsLWCRFC9483{
			Workflow: models.CMPWorkflowPhased,
		}), nil)
	// NOTE: LWCEnroll is intentionally NOT registered — if the phased path
	// wrongly issues inline, the mock panics on an unexpected call.

	router, store := newTestRouterWithStore(svc)
	txID := randomTxID(t)

	irDER, _, _ := buildTestIR(t, testIROptions{CN: "phased-device", TransactionID: txID})
	resp := postCMP(t, router, "test-dms", irDER)
	require.Equal(t, http.StatusOK, resp.Code)
	assert.Equal(t, corecmp.BodyTagIP, parseCMPResponseTag(t, resp.Body.Bytes()),
		"phased IR must receive an IP (waiting) response")

	storedTx, found := store.Peek(hex.EncodeToString(txID))
	require.True(t, found, "phased workflow must persist a PENDING transaction row")
	assert.Equal(t, models.CMPTransactionStatePending, storedTx.State,
		"phased transaction must be PENDING (not ISSUED) until approved")
	assert.Nil(t, storedTx.Certificate, "no certificate is issued before approval")
	assert.NotNil(t, storedTx.CSR, "the CSR must be stored so approval can issue later")

	svc.AssertExpectations(t)
	svc.AssertNotCalled(t, "LWCEnroll", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

// TestHandleCMP_PhasedWorkflow_PollReqWhilePendingReturnsPollRep verifies that
// while a phased transaction is awaiting approval, a pollReq receives a
// pollRep(checkAfter) telling the EE to retry — the standard polling loop.
func TestHandleCMP_PhasedWorkflow_PollReqWhilePendingReturnsPollRep(t *testing.T) {
	router, store, svc := newOptionsRouter(t, models.EnrollmentOptionsLWCRFC9483{Workflow: models.CMPWorkflowPhased})
	txID := randomTxID(t)

	// Park a PENDING transaction via the phased IR path.
	irDER, _, _ := buildTestIR(t, testIROptions{CN: "phased-poll-device", TransactionID: txID})
	require.Equal(t, http.StatusOK, postCMP(t, router, "test-dms", irDER).Code)
	if tx, ok := store.Peek(hex.EncodeToString(txID)); ok {
		require.Equal(t, models.CMPTransactionStatePending, tx.State)
	}

	// pollReq while still PENDING → pollRep.
	pollDER := buildTestPollReq(t, txID, 0)
	resp := postCMP(t, router, "test-dms", pollDER)
	require.Equal(t, http.StatusOK, resp.Code)
	assert.Equal(t, corecmp.BodyTagPollRep, parseResponseBodyTag(t, resp.Body.Bytes()),
		"pollReq on a PENDING (awaiting-approval) transaction must return pollRep")

	svc.AssertExpectations(t)
}

// TestHandleCMP_CertConf_WhilePendingIsRejected verifies that a certConf naming
// a transaction that has no issued certificate yet is rejected with a CMP error
// body rather than crashing the handler.
//
// Regression test: handleCertConf used to read tx.Certificate.Raw without
// checking it, and tx.Certificate is nil while State == PENDING. Because the EE
// chooses its own transactionID, an ir that parks a PENDING row (phased-approval
// workflow here) followed by a certConf for the same transactionID reached that
// dereference and panicked — every intervening check passes trivially, since a
// PENDING row's SentNonce and CertSerialNumber are still empty.
func TestHandleCMP_CertConf_WhilePendingIsRejected(t *testing.T) {
	router, store, _ := newOptionsRouter(t, models.EnrollmentOptionsLWCRFC9483{Workflow: models.CMPWorkflowPhased})
	txID := randomTxID(t)

	// Park a PENDING transaction via the phased IR path.
	irDER, _, _ := buildTestIR(t, testIROptions{CN: "pending-certconf-device", TransactionID: txID})
	require.Equal(t, http.StatusOK, postCMP(t, router, "test-dms", irDER).Code)
	tx, ok := store.Peek(hex.EncodeToString(txID))
	require.True(t, ok, "phased ir must park a transaction")
	require.Equal(t, models.CMPTransactionStatePending, tx.State)
	require.Nil(t, tx.Certificate, "a PENDING transaction must not carry a certificate")

	// certConf for that PENDING transaction. The cert bytes are arbitrary: the
	// point is that the server has nothing to compare them against yet. An empty
	// recipNonce is what a real client would send here, since no ip/cp with a
	// senderNonce was ever returned.
	confCert, _ := buildSelfSignedCert(t, "pending-certconf-device")
	confDER := buildTestCertConf(t, txID, confCert.Raw, nil)

	resp := postCMP(t, router, "test-dms", confDER)

	require.Equal(t, http.StatusOK, resp.Code)
	assert.Equal(t, corecmp.BodyTagError, parseCMPResponseTag(t, resp.Body.Bytes()),
		"certConf on a transaction with no issued certificate must be answered with an error body")
	bs := parseFailInfoBitString(t, resp.Body.Bytes())
	assert.True(t, bitSet(bs, corecmp.PKIFailureInfoBadRequest),
		"failInfo must set badRequest (2)")

	// The transaction must be left untouched for the pending approval to complete.
	after, ok := store.Peek(hex.EncodeToString(txID))
	require.True(t, ok)
	assert.Equal(t, models.CMPTransactionStatePending, after.State,
		"a rejected certConf must not advance the transaction state")
}

// TestHandleCMP_CertConf_Duplicate_CertConfirmed verifies that a certConf for
// an already-confirmed transaction is answered with an error body carrying
// failInfo certConfirmed (11) rather than a second pkiConf (RFC 9483 §4.1.1 /
// RFC 4210 §5.3.18). The EE still learns the certificate is confirmed, so a
// client retrying a lost pkiConf is not left blind.
func TestHandleCMP_CertConf_Duplicate_CertConfirmed(t *testing.T) {
	issuedCert, _ := buildSelfSignedCert(t, "dup-certconf-device")

	router, store, _ := newEnrollRouter(t, models.EnrollmentOptionsLWCRFC9483{}, issuedCert)
	irDER, txID, _ := buildTestIR(t, testIROptions{CN: "dup-certconf-device"})
	resp := postCMP(t, router, "test-dms", irDER)
	require.Equal(t, http.StatusOK, resp.Code)
	require.Equal(t, corecmp.BodyTagIP, parseCMPResponseTag(t, resp.Body.Bytes()))

	sentNonce := peekSentNonce(t, store, txID)

	// First certConf → pkiConf.
	confDER := buildTestCertConf(t, txID, issuedCert.Raw, sentNonce)
	confResp := postCMP(t, router, "test-dms", confDER)
	require.Equal(t, http.StatusOK, confResp.Code)
	require.Equal(t, corecmp.BodyTagPKIConf, parseCMPResponseTag(t, confResp.Body.Bytes()),
		"first certConf must be answered with pkiConf")

	// Byte-identical replay → error(certConfirmed).
	dupResp := postCMP(t, router, "test-dms", confDER)
	require.Equal(t, http.StatusOK, dupResp.Code)
	assert.Equal(t, corecmp.BodyTagError, parseCMPResponseTag(t, dupResp.Body.Bytes()),
		"duplicate certConf must be answered with an error body")
	bs := parseFailInfoBitString(t, dupResp.Body.Bytes())
	assert.True(t, bitSet(bs, corecmp.PKIFailureInfoCertConfirmed),
		"failInfo must set certConfirmed (11)")
}

// buildTestIRBodyDERWithRegToken builds a minimal ir body carrying an
// id-regCtrl-regToken control (RFC 4211 §6.1) after the CertTemplate, with no
// POPO (mirrors the "legacy" no-POPO shape already used elsewhere in this
// package's tests).
func buildTestIRBodyDERWithRegToken(t *testing.T, cn string, pubKeyDER []byte, regToken string) []byte {
	t.Helper()

	// controls ::= SEQUENCE OF AttributeTypeAndValue { type, value }
	tokenValueDER, err := asn1.MarshalWithParams(regToken, "utf8")
	require.NoError(t, err)
	attrDER, err := asn1.Marshal(struct {
		Type  asn1.ObjectIdentifier
		Value asn1.RawValue
	}{
		Type:  corecmp.OIDRegCtrlRegToken(),
		Value: asn1.RawValue{FullBytes: tokenValueDER},
	})
	require.NoError(t, err)
	controlsDER := seqDER(t, attrDER)

	certRequestDER := buildCertRequestDER(t, cn, pubKeyDER, controlsDER)
	return ctxDER(t, corecmp.BodyTagIR, wrapCertReqMsgs(t, certRequestDER))
}

func buildTestIRWithRegToken(t *testing.T, cn, regToken string) []byte {
	t.Helper()
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	pubKeyDER, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	require.NoError(t, err)

	txID := randomTxID(t)
	senderNonce := randomNonce(t)

	headerDER := buildTestPKIHeaderDER(t, txID, senderNonce, nil, true)
	bodyDER := buildTestIRBodyDERWithRegToken(t, cn, pubKeyDER, regToken)
	msgDER, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true,
		Bytes: concatBytes(headerDER, bodyDER),
	})
	require.NoError(t, err)
	return msgDER
}

// TestHandleCMP_RegToken_OneTimeUse verifies RFC 4211 §6.1: a regToken value
// is accepted the first time it is presented and rejected (badRequest) the
// second time, even across two independent transactions.
func TestHandleCMP_RegToken_OneTimeUse(t *testing.T) {
	issuedCert1, _ := buildSelfSignedCert(t, "regtoken-device-1")
	issuedCert2, _ := buildSelfSignedCert(t, "regtoken-device-2")

	svc := &cmpmock.MockLightweightCMPService{}
	svc.On("LWCGetEnrollmentOptions", mock.Anything, "test-dms").
		Return(resolvedOpts(models.EnrollmentOptionsLWCRFC9483{
			AcceptImplicit: true,
			IR:             models.CMPIRSettings{RegistrationToken: models.CMPControl{Mode: models.CMPControlModeOptional}},
		}), nil)
	svc.On("LWCEnroll", mock.Anything, mock.AnythingOfType("*x509.CertificateRequest"), "test-dms", mock.Anything).
		Return(issuedCert1, nil).Once()

	router, _ := newTestRouterWithStore(svc)

	firstIR := buildTestIRWithRegToken(t, "regtoken-device-1", "SuperSecretRegToken")
	resp := postCMP(t, router, "test-dms", firstIR)
	require.Equal(t, http.StatusOK, resp.Code)
	assert.Equal(t, corecmp.BodyTagIP, parseCMPResponseTag(t, resp.Body.Bytes()),
		"first use of a regToken must be accepted")

	svc.On("LWCEnroll", mock.Anything, mock.AnythingOfType("*x509.CertificateRequest"), "test-dms", mock.Anything).
		Return(issuedCert2, nil).Maybe()

	secondIR := buildTestIRWithRegToken(t, "regtoken-device-2", "SuperSecretRegToken")
	resp2 := postCMP(t, router, "test-dms", secondIR)
	require.Equal(t, http.StatusOK, resp2.Code)
	assert.Equal(t, corecmp.BodyTagIP, parseCMPResponseTag(t, resp2.Body.Bytes()),
		"reuse of a regToken must be rejected via ip CertRepMessage")
	reason, fi := parseCertRepRejection(t, resp2.Body.Bytes())
	assert.Contains(t, reason, "regToken")
	assert.True(t, bitSet(fi, corecmp.PKIFailureInfoBadRequest), "failInfo must set badRequest (2)")

	svc.AssertExpectations(t)
}

// TestHandleCMP_RejectsOversizedBody is a DoS-hardening regression test: a
// request body larger than cmpMaxRequestBodyBytes must be rejected without
// the handler ever buffering the whole thing (http.MaxBytesReader aborts the
// read once the limit is crossed).
func TestHandleCMP_RejectsOversizedBody(t *testing.T) {
	router, _, svc := newOptionsRouter(t, models.EnrollmentOptionsLWCRFC9483{})

	oversized := make([]byte, cmpMaxRequestBodyBytes+1)
	resp := postCMP(t, router, "test-dms", oversized)
	require.Equal(t, http.StatusOK, resp.Code)
	assert.Equal(t, corecmp.BodyTagError, parseCMPResponseTag(t, resp.Body.Bytes()),
		"an oversized request body must be rejected")

	svc.AssertNotCalled(t, "LWCGetEnrollmentOptions", mock.Anything, mock.Anything)
}
