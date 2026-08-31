package cmp

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"math/big"
	"net/http"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	core "github.com/lamassuiot/lamassuiot/core/v3"
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

// Coverage for RFC 9483 §4.1.6 central key generation (CKG) dispatch: an ir
// whose CertTemplate carries an empty public key must be routed to
// handleKGAEnrollment (cmp_enrollment.go), not the normal issue-from-CSR path.
// Before this test, handleKGAEnrollment had no dedicated coverage at all —
// only its ASN.1 building blocks (inspectKGATemplateKey, marshalKGACertRepBody)
// were unit-tested, and the "empty key -> CKG" dispatch decision itself, and
// the resulting EnvelopedData's decryptability by the real recipient, were
// never exercised end-to-end.

// mockKGAService extends the standard mock service with
// LWCIssueKGAHelperCertificate, satisfying services.LightweightCMPKeyGenerator
// — required by handleKGAEnrollment to mint its ephemeral KGA-signer helper
// certificate. No other test file in this package needs it (the existing
// encrCert/challengeResp POPO tests only exercise the RSA/KTRI technique via
// the request's own recipient certificate, which doesn't call this method).
type mockKGAService struct {
	*cmpmock.MockLightweightCMPService
	store storage.CMPTransactionRepo
}

func (m *mockKGAService) GetCMPTransactionRepo() storage.CMPTransactionRepo { return m.store }

func (m *mockKGAService) LWCEnroll(ctx context.Context, csr *x509.CertificateRequest, aps string, signerCert *x509.Certificate) (*x509.Certificate, error) {
	args := m.Called(ctx, csr, aps, signerCert)
	template, _ := args.Get(0).(*x509.Certificate)
	if template == nil || args.Error(1) != nil {
		return template, args.Error(1)
	}
	issuerKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	issuedTemplate := *template
	issuedTemplate.SignatureAlgorithm = x509.UnknownSignatureAlgorithm
	issuer := &x509.Certificate{
		SerialNumber: big.NewInt(100),
		Subject:      pkix.Name{CommonName: "test-kga-issuer"},
		PublicKey:    &issuerKey.PublicKey,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &issuedTemplate, issuer, csr.PublicKey, issuerKey)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(certDER)
}

// LWCProtectionCredentials satisfies services.LightweightCMPProtectionProvider
// so handleKGAEnrollment's KTRI branch can be tested against a DMS that has
// configured normal response-protection credentials — see
// TestHandleCMP_KGA_KTRI_ProtectedWithDMSCredentials.
func (m *mockKGAService) LWCProtectionCredentials(ctx context.Context, aps string) ([]*x509.Certificate, crypto.Signer, error) {
	args := m.Called(ctx, aps)
	certs, _ := args.Get(0).([]*x509.Certificate)
	signer, _ := args.Get(1).(crypto.Signer)
	return certs, signer, args.Error(2)
}

// LWCValidateKGARecipient satisfies services.LightweightCMPKGARecipientValidator.
// The existing tests in this file exercise KGA dispatch/crypto behavior, not
// the recipient trust boundary, so this always accepts — mirroring how
// LWCValidateCCRRequester's cross-cert equivalent is stubbed permissively in
// other test files.
func (m *mockKGAService) LWCValidateKGARecipient(ctx context.Context, aps string, recipient *x509.Certificate) error {
	return nil
}

func (m *mockKGAService) LWCIssueKGAHelperCertificate(ctx context.Context, aps string, csr *x509.CertificateRequest, purpose services.KGAHelperPurpose) (*x509.Certificate, []*x509.Certificate, error) {
	args := m.Called(ctx, aps, csr, purpose)
	cert, _ := args.Get(0).(*x509.Certificate)
	chain, _ := args.Get(1).([]*x509.Certificate)
	if cert == nil && args.Error(2) == nil {
		issuerKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, nil, err
		}
		ski := sha1.Sum(csr.RawSubjectPublicKeyInfo)
		template := &x509.Certificate{
			SerialNumber:       big.NewInt(2),
			Subject:            csr.Subject,
			NotBefore:          time.Now().Add(-time.Hour),
			NotAfter:           time.Now().Add(24 * time.Hour),
			KeyUsage:           x509.KeyUsageDigitalSignature,
			SubjectKeyId:       ski[:],
			UnknownExtKeyUsage: []asn1.ObjectIdentifier{{1, 3, 6, 1, 5, 5, 7, 3, 32}},
		}
		issuer := &x509.Certificate{
			SerialNumber: big.NewInt(101),
			Subject:      pkix.Name{CommonName: "test-kga-helper-issuer"},
			PublicKey:    &issuerKey.PublicKey,
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(24 * time.Hour),
			IsCA:         true,
			KeyUsage:     x509.KeyUsageCertSign,
		}
		certDER, err := x509.CreateCertificate(rand.Reader, template, issuer, csr.PublicKey, issuerKey)
		if err != nil {
			return nil, nil, err
		}
		cert, err = x509.ParseCertificate(certDER)
		if err != nil {
			return nil, nil, err
		}
	}
	return cert, chain, args.Error(2)
}

// buildKeyUsageCert builds a self-signed RSA certificate with the given
// KeyUsage bits and a SubjectKeyId (computed like buildSelfSignedCert),
// suitable either as a CMP signature-protection signer or as a canned KGA
// helper certificate.
func buildKeyUsageCert(t *testing.T, cn string, keyUsage x509.KeyUsage, unknownEKUs ...asn1.ObjectIdentifier) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)
	ski := sha1.Sum(pubDER)
	template := &x509.Certificate{
		SerialNumber:       big.NewInt(1),
		Subject:            pkix.Name{CommonName: cn},
		NotBefore:          time.Now().Add(-time.Hour),
		NotAfter:           time.Now().Add(24 * time.Hour),
		KeyUsage:           keyUsage,
		SubjectKeyId:       ski[:],
		UnknownExtKeyUsage: unknownEKUs,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)
	return cert, key
}

// buildEmptyRSASPKIDER encodes a SubjectPublicKeyInfo carrying an RSA
// AlgorithmIdentifier with a zero-length subjectPublicKey — the RFC 9483
// §4.1.6 "generate this key for me" signal recognised by inspectKGATemplateKey.
func buildEmptyRSASPKIDER(t *testing.T) []byte {
	t.Helper()
	algID, err := asn1.Marshal(struct {
		Algorithm  asn1.ObjectIdentifier
		Parameters asn1.RawValue
	}{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}, Parameters: asn1.NullRawValue})
	require.NoError(t, err)
	bitStr, err := asn1.Marshal(asn1.BitString{Bytes: nil, BitLength: 0})
	require.NoError(t, err)
	return seqDER(t, algID, bitStr)
}

// buildTestKGAIR builds an ir PKIMessage whose CertTemplate carries an empty
// RSA public key and no POPO — per RFC 9483 §4.1.6, a CKG request has neither
// a usable key nor a POPO to verify.
func buildTestKGAIR(t *testing.T, txID []byte, cn string) []byte {
	t.Helper()
	senderNonce := randomNonce(t)
	headerDER := buildTestPKIHeaderDER(t, txID, senderNonce, nil, false)
	certRequestDER := buildCertRequestDER(t, cn, buildEmptyRSASPKIDER(t))
	bodyDER := ctxDER(t, corecmp.BodyTagIR, wrapCertReqMsgs(t, certRequestDER))
	msgDER, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      concatBytes(headerDER, bodyDER),
	})
	require.NoError(t, err)
	return msgDER
}

// extractKGAEnvelopedDataDER parses an ip/cp/kup CertRepMessage produced by
// marshalKGACertRepBody: CertifiedKeyPair ::= SEQUENCE { certOrEncCert [0]
// Certificate (plain — CKG doesn't need the cert itself encrypted), privateKey
// [0] EXPLICIT EncryptedKey CHOICE { envelopedData [0] } }. This differs from
// extractEnvelopedDataDER (cmp_enrollment_variants_test.go), which extracts
// the encrCert POPO response's certOrEncCert ENCRYPTED [1] alternative — CKG
// encrypts the private key in a separate field, not the certificate.
func extractKGAEnvelopedDataDER(t *testing.T, responseDER []byte) (certDER, envDataDER []byte) {
	t.Helper()
	var msg corecmp.RawPKIMessage
	_, err := asn1.Unmarshal(responseDER, &msg)
	require.NoError(t, err)

	var certRepMsg asn1.RawValue
	_, err = asn1.Unmarshal(msg.Body.Bytes, &certRepMsg)
	require.NoError(t, err)
	var responseSeqOf asn1.RawValue
	_, err = asn1.Unmarshal(certRepMsg.Bytes, &responseSeqOf)
	require.NoError(t, err)
	var firstResp asn1.RawValue
	_, err = asn1.Unmarshal(responseSeqOf.Bytes, &firstResp)
	require.NoError(t, err)

	// certReqId INTEGER, then PKIStatusInfo SEQUENCE, then CertifiedKeyPair.
	var certReqID int
	rest, err := asn1.Unmarshal(firstResp.Bytes, &certReqID)
	require.NoError(t, err)
	var statusInfo asn1.RawValue
	rest, err = asn1.Unmarshal(rest, &statusInfo)
	require.NoError(t, err)
	var certifiedKeyPair asn1.RawValue
	_, err = asn1.Unmarshal(rest, &certifiedKeyPair)
	require.NoError(t, err)

	var certOrEncCert asn1.RawValue
	ckpRest, err := asn1.Unmarshal(certifiedKeyPair.Bytes, &certOrEncCert)
	require.NoError(t, err)
	require.Equal(t, 0, certOrEncCert.Tag, "certOrEncCert must be the plain certificate [0] alternative for CKG")

	var privateKeyField asn1.RawValue
	_, err = asn1.Unmarshal(ckpRest, &privateKeyField)
	require.NoError(t, err)
	require.Equal(t, 0, privateKeyField.Tag, "privateKey [0] EXPLICIT field must be present for a CKG response")

	// privateKeyField.Bytes is the EncryptedKey CHOICE (envelopedData [0]).
	var encKeyChoice asn1.RawValue
	_, err = asn1.Unmarshal(privateKeyField.Bytes, &encKeyChoice)
	require.NoError(t, err)
	require.Equal(t, 0, encKeyChoice.Tag, "EncryptedKey must choose the envelopedData [0] alternative")

	envDataDER, err = asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: encKeyChoice.Bytes,
	})
	require.NoError(t, err)
	return certOrEncCert.Bytes, envDataDER
}

func TestHandleCMP_KGA_EmptyPublicKey_RSA_TriggersCentralKeyGeneration(t *testing.T) {
	svc := &cmpmock.MockLightweightCMPService{}
	opts := resolveTestCMPOpts(models.CMPEnrollmentSettings{ServerKeyGenEnabled: true})
	svc.On("LWCGetEnrollmentOptions", mock.Anything, "test-dms").Return(&opts, nil)

	issuedCert, _ := buildSelfSignedCert(t, "kga-device")
	svc.On("LWCEnroll", mock.Anything, mock.AnythingOfType("*x509.CertificateRequest"), "test-dms", mock.Anything).Return(issuedCert, nil)

	wrapped := &mockKGAService{MockLightweightCMPService: svc, store: newInMemoryCMPStore()}
	wrapped.On("LWCIssueKGAHelperCertificate", mock.Anything, "test-dms",
		mock.AnythingOfType("*x509.CertificateRequest"), services.KGAHelperSigner).
		Return((*x509.Certificate)(nil), []*x509.Certificate{}, nil)
	// No DMS protection credentials configured for this test — the response
	// protection falls back to the KGA signer (see the identity-specific
	// TestHandleCMP_KGA_KTRI_ProtectedWithDMSCredentials for the configured case).
	wrapped.On("LWCProtectionCredentials", mock.Anything, "test-dms").
		Return([]*x509.Certificate(nil), crypto.Signer(nil), nil)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	routes, err := NewCMPHttpRoutes(logrus.NewEntry(logrus.New()), wrapped)
	require.NoError(t, err)
	router.POST("/.well-known/cmp/p/:id", routes.HandleCMP)

	// The recipient (message-protection signer) cert needs keyEncipherment for
	// the RSA/KTRI central-key-generation technique (RFC 9483 §4.1.6.1) — CKG
	// requires a signature-protected request, and the signer cert doubles as
	// the CMS recipient the generated key is wrapped to.
	recipientCert, recipientKey := buildKeyUsageCert(t, "kga-recipient",
		x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment)

	msgDER := buildTestKGAIR(t, randomTxID(t), "kga-device")
	signedDER := signCMPMessage(t, msgDER, recipientCert, recipientKey)

	resp := postCMP(t, router, "test-dms", signedDER)
	require.Equal(t, http.StatusOK, resp.Code)
	assert.Equal(t, corecmp.BodyTagIP, parseCMPResponseTag(t, resp.Body.Bytes()),
		"CKG must be answered inline with ip, carrying the issued cert + wrapped key")

	certDER, envDataDER := extractKGAEnvelopedDataDER(t, resp.Body.Bytes())

	decodedCert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)
	assert.Equal(t, issuedCert.SerialNumber, decodedCert.SerialNumber,
		"the plain (unencrypted) certOrEncCert must be the certificate LWCEnroll issued")

	parsed, err := corecmp.ParseMessage(resp.Body.Bytes())
	require.NoError(t, err)
	clientResult, err := corecmp.DecodeKGAResponse(parsed, corecmp.KGADecryptOptions{Recipient: recipientKey})
	require.NoError(t, err)
	assert.Equal(t, issuedCert.SerialNumber, clientResult.Certificate.SerialNumber)
	clientPublicDER, err := x509.MarshalPKIXPublicKey(clientResult.PrivateKey.Public())
	require.NoError(t, err)
	assert.Equal(t, clientResult.Certificate.RawSubjectPublicKeyInfo, clientPublicDER,
		"the client-decoded private key must match the issued certificate")

	// The generated private key is delivered as CMS SignedData(AsymmetricKeyPackage)
	// wrapped in EnvelopedData; decrypting with the recipient's own key proves
	// the KTRI wrapping actually targeted this recipient. Full signature-chain
	// verification of the inner SignedData is covered by the backend KGA package's
	// tests — this asserts the externally observable behavior this dispatch
	// path is responsible for: decryptability and a well-formed payload.
	plaintext := decryptKTRIEnvelopedData(t, envDataDER, recipientKey)
	var innerSignedData asn1.RawValue
	_, err = asn1.Unmarshal(plaintext, &innerSignedData)
	require.NoError(t, err, "decrypted KGA payload must be a well-formed CMS SignedData (RFC 9483 §4.1.6)")
	assert.Equal(t, asn1.TagSequence, innerSignedData.Tag)
	assert.NotEmpty(t, innerSignedData.Bytes)

	svc.AssertExpectations(t)
	wrapped.AssertExpectations(t)
}

// TestHandleCMP_KGA_CR_ThreadsOperationContext is a security regression test:
// handleKGAEnrollment must tag its issuance context with the CMP operation
// that drove the request (RFC011's LamassuContextKeyCMPOperation signal),
// exactly like the non-KGA path (issueAndStore) already does. Before this
// fix, a cr-tagged CKG request reached LWCEnroll with no such value set,
// which cmpOperationFromContext defaults to "ir" — silently applying ir's
// (less restrictive) per-operation policy instead of CR's
// RequireExistingDevice / MaximumActiveCertificates / CertificateBehavior /
// AllowedProfileIDs to a cr request.
func TestHandleCMP_KGA_CR_ThreadsOperationContext(t *testing.T) {
	svc := &cmpmock.MockLightweightCMPService{}
	opts := resolveTestCMPOpts(models.CMPEnrollmentSettings{ServerKeyGenEnabled: true})
	svc.On("LWCGetEnrollmentOptions", mock.Anything, "test-dms").Return(&opts, nil)

	issuedCert, _ := buildSelfSignedCert(t, "kga-cr-device")
	svc.On("LWCEnroll", mock.MatchedBy(func(ctx context.Context) bool {
		return ctx.Value(core.LamassuContextKeyCMPOperation) == "cr"
	}), mock.AnythingOfType("*x509.CertificateRequest"), "test-dms", mock.Anything).Return(issuedCert, nil)

	wrapped := &mockKGAService{MockLightweightCMPService: svc, store: newInMemoryCMPStore()}
	wrapped.On("LWCIssueKGAHelperCertificate", mock.Anything, "test-dms",
		mock.AnythingOfType("*x509.CertificateRequest"), services.KGAHelperSigner).
		Return((*x509.Certificate)(nil), []*x509.Certificate{}, nil)
	wrapped.On("LWCProtectionCredentials", mock.Anything, "test-dms").
		Return([]*x509.Certificate(nil), crypto.Signer(nil), nil)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	routes, err := NewCMPHttpRoutes(logrus.NewEntry(logrus.New()), wrapped)
	require.NoError(t, err)
	router.POST("/.well-known/cmp/p/:id", routes.HandleCMP)

	recipientCert, recipientKey := buildKeyUsageCert(t, "kga-cr-recipient",
		x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment)

	// A cr-tagged empty-pubkey (CKG) request — same shape as buildTestKGAIR
	// but tagged cr (2) instead of ir (0).
	txID := randomTxID(t)
	senderNonce := randomNonce(t)
	headerDER := buildTestPKIHeaderDER(t, txID, senderNonce, nil, false)
	certRequestDER := buildCertRequestDER(t, "kga-cr-device", buildEmptyRSASPKIDER(t))
	bodyDER := ctxDER(t, corecmp.BodyTagCR, wrapCertReqMsgs(t, certRequestDER))
	msgDER, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true,
		Bytes: concatBytes(headerDER, bodyDER),
	})
	require.NoError(t, err)
	signedDER := signCMPMessage(t, msgDER, recipientCert, recipientKey)

	resp := postCMP(t, router, "test-dms", signedDER)
	require.Equal(t, http.StatusOK, resp.Code)
	assert.Equal(t, corecmp.BodyTagCP, parseCMPResponseTag(t, resp.Body.Bytes()),
		"cr-tagged CKG must be answered with cp")

	svc.AssertExpectations(t)
	wrapped.AssertExpectations(t)
}

func TestHandleCMP_KGA_EmptyPublicKey_RequiresProtection(t *testing.T) {
	svc := &cmpmock.MockLightweightCMPService{}
	opts := resolveTestCMPOpts(models.CMPEnrollmentSettings{ServerKeyGenEnabled: true})
	svc.On("LWCGetEnrollmentOptions", mock.Anything, "test-dms").Return(&opts, nil)

	wrapped := &mockKGAService{MockLightweightCMPService: svc, store: newInMemoryCMPStore()}
	// The rejection response itself goes through sendRawBody, which also
	// resolves DMS protection credentials; unconfigured here, same as every
	// other test that doesn't care about response protection identity.
	wrapped.On("LWCProtectionCredentials", mock.Anything, "test-dms").
		Return([]*x509.Certificate(nil), crypto.Signer(nil), nil)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	routes, err := NewCMPHttpRoutes(logrus.NewEntry(logrus.New()), wrapped)
	require.NoError(t, err)
	router.POST("/.well-known/cmp/p/:id", routes.HandleCMP)

	// Unsigned request: central key generation must be rejected rather than
	// silently proceeding without an identified recipient to wrap the key to.
	msgDER := buildTestKGAIR(t, randomTxID(t), "kga-device")

	resp := postCMP(t, router, "test-dms", msgDER)
	require.Equal(t, http.StatusOK, resp.Code)
	// Rejections of this kind are carried inline in an ip/cp CertRepMessage
	// with a rejection PKIStatus (RFC 9483 §4.1), not a generic error body —
	// so the check is on the rejection reason/status, not the body tag.
	status, hasCertifiedKeyPair := parseIPBodyStatus(t, resp.Body.Bytes())
	assert.NotEqual(t, 0, status, "an unprotected CKG request must be rejected, not accepted (PKIStatus 0)")
	assert.False(t, hasCertifiedKeyPair, "an unprotected CKG request must not carry an issued cert/key")
	reason, _ := parseCertRepRejection(t, resp.Body.Bytes())
	assert.Contains(t, reason, "signature-protected")

	svc.AssertNotCalled(t, "LWCEnroll", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	wrapped.AssertNotCalled(t, "LWCIssueKGAHelperCertificate", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

// TestHandleCMP_KGA_DisabledByDefault is a regression test for the
// ServerKeyGenEnabled gate: a DMS that hasn't explicitly opted in to central
// key generation (the Go zero value, false) must reject an otherwise
// well-formed, correctly signature-protected CKG request rather than
// generating and delivering a server-side key. Before this gate existed, any
// signature-protected request with an empty CertTemplate public key
// unconditionally triggered central key generation, with no DMS-level way to
// disable it.
func TestHandleCMP_KGA_DisabledByDefault(t *testing.T) {
	svc := &cmpmock.MockLightweightCMPService{}
	opts := resolveTestCMPOpts(models.CMPEnrollmentSettings{}) // ServerKeyGenEnabled left at its zero value (false)
	svc.On("LWCGetEnrollmentOptions", mock.Anything, "test-dms").Return(&opts, nil)

	wrapped := &mockKGAService{MockLightweightCMPService: svc, store: newInMemoryCMPStore()}
	wrapped.On("LWCProtectionCredentials", mock.Anything, "test-dms").
		Return([]*x509.Certificate(nil), crypto.Signer(nil), nil)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	routes, err := NewCMPHttpRoutes(logrus.NewEntry(logrus.New()), wrapped)
	require.NoError(t, err)
	router.POST("/.well-known/cmp/p/:id", routes.HandleCMP)

	recipientCert, recipientKey := buildKeyUsageCert(t, "kga-recipient",
		x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment)
	msgDER := buildTestKGAIR(t, randomTxID(t), "kga-device")
	signedDER := signCMPMessage(t, msgDER, recipientCert, recipientKey)

	resp := postCMP(t, router, "test-dms", signedDER)
	require.Equal(t, http.StatusOK, resp.Code)

	status, hasCertifiedKeyPair := parseIPBodyStatus(t, resp.Body.Bytes())
	assert.NotEqual(t, 0, status, "CKG must be rejected when ServerKeyGenEnabled is false")
	assert.False(t, hasCertifiedKeyPair)
	reason, failInfo := parseCertRepRejection(t, resp.Body.Bytes())
	assert.Contains(t, reason, "not enabled")
	assert.Equal(t, 1, failInfo.At(corecmp.PKIFailureInfoNotAuthorized), "rejection must map to PKIFailureInfo notAuthorized")

	svc.AssertNotCalled(t, "LWCEnroll", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	wrapped.AssertNotCalled(t, "LWCIssueKGAHelperCertificate", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

// senderCommonName decodes a response PKIMessage's PKIHeader.sender
// (GeneralName, directoryName alternative) back into its CommonName.
func senderCommonName(t *testing.T, responseDER []byte) string {
	t.Helper()
	var msg corecmp.Message
	_, err := asn1.Unmarshal(responseDER, &msg)
	require.NoError(t, err)
	require.Equal(t, 4, msg.Header.Sender.Tag, "PKIHeader.sender must use the directoryName GeneralName alternative")
	var rdn pkix.RDNSequence
	_, err = asn1.Unmarshal(msg.Header.Sender.Bytes, &rdn)
	require.NoError(t, err)
	var name pkix.Name
	name.FillFromRDNSequence(&rdn)
	return name.CommonName
}

// TestHandleCMP_KGA_KTRI_ProtectedWithDMSCredentials is a regression test for
// a real interop bug: handleKGAEnrollment used to sign the OUTER PKIMessage
// response protection with the ephemeral "Lamassu CMP KGA Signer" helper
// certificate instead of the DMS's own registered protection credentials —
// for KTRI (RSA recipient), which (like buildEncryptedCertRepBody's own KTRI
// branch) needs no separate ECDH-partner identity, so there was never a
// reason to deviate from the DMS's usual response signer. Any client that
// pins the expected response identity (e.g. `openssl cmp -srvcert`, which
// checks the sender DN against the pinned certificate's subject) rejected the
// response with "unexpected sender" even though the exchange was otherwise
// entirely correct. This asserts the response is signed by — and its sender
// DN names — the DMS's protection certificate, not the KGA helper cert.
func TestHandleCMP_KGA_KTRI_ProtectedWithDMSCredentials(t *testing.T) {
	svc := &cmpmock.MockLightweightCMPService{}
	opts := resolveTestCMPOpts(models.CMPEnrollmentSettings{ServerKeyGenEnabled: true})
	svc.On("LWCGetEnrollmentOptions", mock.Anything, "test-dms").Return(&opts, nil)

	issuedCert, _ := buildSelfSignedCert(t, "kga-device")
	svc.On("LWCEnroll", mock.Anything, mock.AnythingOfType("*x509.CertificateRequest"), "test-dms", mock.Anything).Return(issuedCert, nil)

	wrapped := &mockKGAService{MockLightweightCMPService: svc, store: newInMemoryCMPStore()}
	wrapped.On("LWCIssueKGAHelperCertificate", mock.Anything, "test-dms",
		mock.AnythingOfType("*x509.CertificateRequest"), services.KGAHelperSigner).
		Return((*x509.Certificate)(nil), []*x509.Certificate{}, nil)

	dmsProtectionCert, dmsProtectionKey := buildKeyUsageCert(t, "cmp-ra-protection", x509.KeyUsageDigitalSignature)
	wrapped.On("LWCProtectionCredentials", mock.Anything, "test-dms").
		Return([]*x509.Certificate{dmsProtectionCert}, crypto.Signer(dmsProtectionKey), nil)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	routes, err := NewCMPHttpRoutes(logrus.NewEntry(logrus.New()), wrapped)
	require.NoError(t, err)
	router.POST("/.well-known/cmp/p/:id", routes.HandleCMP)

	recipientCert, recipientKey := buildKeyUsageCert(t, "kga-recipient",
		x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment)

	msgDER := buildTestKGAIR(t, randomTxID(t), "kga-device")
	signedDER := signCMPMessage(t, msgDER, recipientCert, recipientKey)

	resp := postCMP(t, router, "test-dms", signedDER)
	require.Equal(t, http.StatusOK, resp.Code)
	assert.Equal(t, corecmp.BodyTagIP, parseCMPResponseTag(t, resp.Body.Bytes()))

	assert.Equal(t, "cmp-ra-protection", senderCommonName(t, resp.Body.Bytes()),
		"KTRI CKG response must be protected by the DMS's normal credentials, not the ephemeral KGA helper cert")

	// The KGA-signed key delivery itself must remain unaffected by which
	// identity protects the outer PKIMessage.
	_, envDataDER := extractKGAEnvelopedDataDER(t, resp.Body.Bytes())
	plaintext := decryptKTRIEnvelopedData(t, envDataDER, recipientKey)
	var innerSignedData asn1.RawValue
	_, err = asn1.Unmarshal(plaintext, &innerSignedData)
	require.NoError(t, err, "decrypted KGA payload must still be a well-formed CMS SignedData")

	svc.AssertExpectations(t)
	wrapped.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// CKG transaction-store integration
//
// Regression tests: handleKGAEnrollment used to issue a certificate and deliver
// a generated key WITHOUT ever inserting a CMPTransaction row. That silently
// broke the rest of the protocol for every CKG enrollment — a legitimate
// certConf was rejected as "unknown transactionID", the confirmation-timeout
// monitor could never revoke an unconfirmed CKG certificate (it stayed active
// forever), and a replayed transactionID minted a second key pair and cert.
// ---------------------------------------------------------------------------

// newKGATestRouter builds a CKG-enabled router over an in-memory store, plus a
// recipient certificate valid for the RSA/KTRI technique.
func newKGATestRouter(t *testing.T, opts models.CMPEnrollmentSettings, issuedCert *x509.Certificate) (*gin.Engine, *inMemoryCMPStore, *x509.Certificate, *rsa.PrivateKey) {
	t.Helper()

	opts.ServerKeyGenEnabled = true
	resolved := resolveTestCMPOpts(opts)

	svc := &cmpmock.MockLightweightCMPService{}
	svc.On("LWCGetEnrollmentOptions", mock.Anything, "test-dms").Return(&resolved, nil)
	svc.On("LWCEnroll", mock.Anything, mock.AnythingOfType("*x509.CertificateRequest"), "test-dms", mock.Anything).Return(issuedCert, nil)

	store := newInMemoryCMPStore()
	wrapped := &mockKGAService{MockLightweightCMPService: svc, store: store}
	wrapped.On("LWCIssueKGAHelperCertificate", mock.Anything, "test-dms",
		mock.AnythingOfType("*x509.CertificateRequest"), services.KGAHelperSigner).
		Return((*x509.Certificate)(nil), []*x509.Certificate{}, nil)
	wrapped.On("LWCProtectionCredentials", mock.Anything, "test-dms").
		Return([]*x509.Certificate(nil), crypto.Signer(nil), nil)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	routes, err := NewCMPHttpRoutes(logrus.NewEntry(logrus.New()), wrapped)
	require.NoError(t, err)
	router.POST("/.well-known/cmp/p/:id", routes.HandleCMP)

	recipientCert, recipientKey := buildKeyUsageCert(t, "kga-recipient",
		x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment)
	return router, store, recipientCert, recipientKey
}

// TestHandleCMP_KGA_PersistsTransactionAndAcceptsCertConf is the primary
// regression test: a CKG enrollment must persist an ISSUED row flagged as
// central key generation, and the EE's follow-up certConf must then be accepted
// with pkiConf instead of rejected as an unknown transactionID.
func TestHandleCMP_KGA_PersistsTransactionAndAcceptsCertConf(t *testing.T) {
	issuedCert, _ := buildSelfSignedCert(t, "kga-device")
	router, store, recipientCert, recipientKey := newKGATestRouter(t, models.CMPEnrollmentSettings{}, issuedCert)

	txID := randomTxID(t)
	signedDER := signCMPMessage(t, buildTestKGAIR(t, txID, "kga-device"), recipientCert, recipientKey)
	resp := postCMP(t, router, "test-dms", signedDER)
	require.Equal(t, http.StatusOK, resp.Code)
	require.Equal(t, corecmp.BodyTagIP, parseCMPResponseTag(t, resp.Body.Bytes()))

	// The certificate the EE actually received. LWCEnroll mints a fresh cert bound
	// to the server-generated key (using issuedCert only as a template), so this —
	// not issuedCert — is what certConf must hash.
	deliveredCertDER, _ := extractKGAEnvelopedDataDER(t, resp.Body.Bytes())

	txHex := hex.EncodeToString(txID)
	tx, ok := store.Peek(txHex)
	require.True(t, ok, "a CKG enrollment must persist a transaction row")
	assert.Equal(t, models.CMPTransactionStateIssued, tx.State,
		"explicit-confirm CKG must park the row as ISSUED awaiting certConf")
	assert.True(t, tx.CentralKeyGeneration, "the row must be flagged as central key generation")
	require.NotNil(t, tx.Certificate, "the issued certificate must be stored so certConf can verify certHash")
	assert.Equal(t, deliveredCertDER, tx.Certificate.Raw,
		"the stored certificate must be byte-identical to the one delivered, else certHash can never match")
	require.NotEmpty(t, tx.SentNonce,
		"the response senderNonce must be persisted, else no certConf can ever match it")

	// The nonce on the wire must equal the persisted one, otherwise certConf's
	// recipNonce check can never pass.
	sentNonce := peekSentNonce(t, store, txID)
	confDER := buildTestCertConf(t, txID, deliveredCertDER, sentNonce)
	confResp := postCMP(t, router, "test-dms", confDER)
	require.Equal(t, http.StatusOK, confResp.Code)
	assert.Equal(t, corecmp.BodyTagPKIConf, parseCMPResponseTag(t, confResp.Body.Bytes()),
		"certConf for a CKG transaction must be answered with pkiConf")

	after, ok := store.Peek(txHex)
	require.True(t, ok)
	assert.Equal(t, models.CMPTransactionStateConfirmed, after.State,
		"a verified certConf must transition the CKG row to CONFIRMED")
}

// TestHandleCMP_KGA_DuplicateTransactionIDRejected verifies a replayed CKG
// request does not mint a second key pair and certificate.
func TestHandleCMP_KGA_DuplicateTransactionIDRejected(t *testing.T) {
	issuedCert, _ := buildSelfSignedCert(t, "kga-device")
	router, _, recipientCert, recipientKey := newKGATestRouter(t, models.CMPEnrollmentSettings{}, issuedCert)

	txID := randomTxID(t)
	signedDER := signCMPMessage(t, buildTestKGAIR(t, txID, "kga-device"), recipientCert, recipientKey)

	first := postCMP(t, router, "test-dms", signedDER)
	require.Equal(t, http.StatusOK, first.Code)
	require.Equal(t, corecmp.BodyTagIP, parseCMPResponseTag(t, first.Body.Bytes()))

	// Byte-identical replay of the same transactionID.
	second := postCMP(t, router, "test-dms", signedDER)
	require.Equal(t, http.StatusOK, second.Code)
	assert.Equal(t, corecmp.BodyTagError, parseCMPResponseTag(t, second.Body.Bytes()),
		"a replayed CKG transactionID must be rejected, not issued a second key pair")
	bs := parseFailInfoBitString(t, second.Body.Bytes())
	assert.True(t, bitSet(bs, corecmp.PKIFailureInfoTransactionIDInUse),
		"failInfo must set transactionIdInUse (21)")
}

// TestHandleCMP_KGA_PollReqRefused verifies that the CKG response is not
// "recovered" via pollReq. The generated private key is never persisted, so
// re-deriving the response would hand the EE a certificate it holds no key for —
// worse than an error, since the EE would install an unusable identity.
func TestHandleCMP_KGA_PollReqRefused(t *testing.T) {
	issuedCert, _ := buildSelfSignedCert(t, "kga-device")
	router, store, recipientCert, recipientKey := newKGATestRouter(t, models.CMPEnrollmentSettings{}, issuedCert)

	txID := randomTxID(t)
	signedDER := signCMPMessage(t, buildTestKGAIR(t, txID, "kga-device"), recipientCert, recipientKey)
	require.Equal(t, http.StatusOK, postCMP(t, router, "test-dms", signedDER).Code)

	tx, ok := store.Peek(hex.EncodeToString(txID))
	require.True(t, ok)
	require.Equal(t, models.CMPTransactionStateIssued, tx.State)

	pollResp := postCMP(t, router, "test-dms", buildTestPollReq(t, txID, 0))
	require.Equal(t, http.StatusOK, pollResp.Code)
	assert.Equal(t, corecmp.BodyTagError, parseCMPResponseTag(t, pollResp.Body.Bytes()),
		"pollReq on a CKG transaction must be refused, not answered with a keyless certificate")
}

// TestHandleCMP_KGA_ImplicitConfirmPersistsConfirmed verifies that when the EE
// requests implicit confirmation and the DMS grants it, the CKG row is stored
// directly as CONFIRMED — so the confirmation-timeout monitor does not later
// revoke a certificate that RFC 4210 §5.2.8 already considers complete.
func TestHandleCMP_KGA_ImplicitConfirmPersistsConfirmed(t *testing.T) {
	issuedCert, _ := buildSelfSignedCert(t, "kga-device")
	router, store, recipientCert, recipientKey := newKGATestRouter(t,
		models.CMPEnrollmentSettings{AcceptImplicit: true}, issuedCert)

	txID := randomTxID(t)
	// Same KGA ir, but with id-it-implicitConfirm in the header generalInfo.
	senderNonce := randomNonce(t)
	headerDER := buildTestPKIHeaderDER(t, txID, senderNonce, nil, true)
	certRequestDER := buildCertRequestDER(t, "kga-device", buildEmptyRSASPKIDER(t))
	bodyDER := ctxDER(t, corecmp.BodyTagIR, wrapCertReqMsgs(t, certRequestDER))
	msgDER, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true,
		Bytes: concatBytes(headerDER, bodyDER),
	})
	require.NoError(t, err)

	resp := postCMP(t, router, "test-dms", signCMPMessage(t, msgDER, recipientCert, recipientKey))
	require.Equal(t, http.StatusOK, resp.Code)
	require.Equal(t, corecmp.BodyTagIP, parseCMPResponseTag(t, resp.Body.Bytes()))

	tx, ok := store.Peek(hex.EncodeToString(txID))
	require.True(t, ok, "an implicit-confirm CKG enrollment must still persist a row")
	assert.Equal(t, models.CMPTransactionStateConfirmed, tx.State,
		"implicit confirmation completes the transaction at delivery (RFC 4210 §5.2.8)")
	assert.True(t, tx.CentralKeyGeneration)
	assert.Equal(t, tx.CreatedAt, tx.ConfirmedAt,
		"ConfirmedAt must equal CreatedAt exactly, the marker handleCertConf uses for implicit confirmation")
}
