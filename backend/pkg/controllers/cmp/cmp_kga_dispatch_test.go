package cmp

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"net/http"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
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
	opts := models.EnrollmentOptionsLWCRFC9483{ServerKeyGenEnabled: true}
	svc.On("LWCGetEnrollmentOptions", mock.Anything, "test-dms").Return(&opts, nil)

	issuedCert, _ := buildSelfSignedCert(t, "kga-device")
	svc.On("LWCEnroll", mock.Anything, mock.AnythingOfType("*x509.CertificateRequest"), "test-dms", mock.Anything).Return(issuedCert, nil)

	wrapped := &mockKGAService{MockLightweightCMPService: svc, store: newInMemoryCMPStore()}
	wrapped.On("LWCIssueKGAHelperCertificate", mock.Anything, "test-dms",
		mock.AnythingOfType("*x509.CertificateRequest"), services.KGAHelperSigner).
		Return((*x509.Certificate)(nil), []*x509.Certificate{}, nil)

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

func TestHandleCMP_KGA_EmptyPublicKey_RequiresProtection(t *testing.T) {
	svc := &cmpmock.MockLightweightCMPService{}
	opts := models.EnrollmentOptionsLWCRFC9483{ServerKeyGenEnabled: true}
	svc.On("LWCGetEnrollmentOptions", mock.Anything, "test-dms").Return(&opts, nil)

	wrapped := &mockKGAService{MockLightweightCMPService: svc, store: newInMemoryCMPStore()}

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
	opts := models.EnrollmentOptionsLWCRFC9483{} // ServerKeyGenEnabled left at its zero value (false)
	svc.On("LWCGetEnrollmentOptions", mock.Anything, "test-dms").Return(&opts, nil)

	wrapped := &mockKGAService{MockLightweightCMPService: svc, store: newInMemoryCMPStore()}

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
