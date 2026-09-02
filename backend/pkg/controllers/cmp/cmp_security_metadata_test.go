package cmp

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"
	corecmp "github.com/lamassuiot/lamassuiot/core/v3/pkg/cmp"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	cmpmock "github.com/lamassuiot/lamassuiot/core/v3/pkg/services/mock"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// This file covers the security-audit metadata added to models.CMPTransaction
// (POPOMethod, ChallengeType, AuthenticatorControlPresent,
// AuthModeAtEnrollment): it verifies each enrollment path records the
// semantically correct values on the persisted row. Round-trip assertions for
// challenge_response, encrypted_certificate, p10cr and kur live alongside
// their existing dedicated tests in cmp_enrollment_variants_test.go and
// cmp_handler_test.go; this file adds the paths that had no existing test to
// extend (signature POPO, trusted-RA raVerified, the authenticator control,
// and AuthModeAtEnrollment denormalization).

// TestHandleCMP_SecurityMetadata_SignaturePOPO verifies that an ir accepted
// via a valid POPOSigningKey signature records POPOMethod="signature".
func TestHandleCMP_SecurityMetadata_SignaturePOPO(t *testing.T) {
	issuedCert, _ := buildSelfSignedCert(t, "sigpopo-device")

	router, store, svc := newEnrollRouter(t, models.CMPEnrollmentSettings{
		AcceptImplicit: true,
		AuthMode:       models.CMPAuthModeClientCertificate,
		IR:             models.CMPIRSettings{ProofOfPossession: models.CMPProofOfPossession{Required: true}},
	}, issuedCert)

	irDER, txID, _ := buildTestIR(t, testIROptions{
		CN:                  "sigpopo-device",
		WithImplicitConfirm: true,
		POPOMode:            "signature",
	})
	// AuthMode=CLIENT_CERTIFICATE requires message-level protection; the
	// enrolling device's own POPOSigningKey proof is orthogonal to (and does
	// not substitute for) that requirement.
	protCert, protKey := buildSelfSignedCert(t, "sigpopo-signer")
	irDER = signCMPMessage(t, irDER, protCert, protKey)

	resp := postCMP(t, router, "test-dms", irDER)
	require.Equal(t, http.StatusOK, resp.Code)
	assert.Equal(t, corecmp.BodyTagIP, parseCMPResponseTag(t, resp.Body.Bytes()))

	tx, ok := store.Peek(hex.EncodeToString(txID))
	require.True(t, ok)
	assert.Equal(t, string(models.CMPPOPOMethodSignature), tx.POPOMethod)
	assert.Empty(t, tx.ChallengeType)
	assert.Equal(t, string(models.CMPAuthModeClientCertificate), tx.AuthModeAtEnrollment)

	svc.AssertExpectations(t)
}

// TestHandleCMP_SecurityMetadata_AbsentPOPO_NotEnforced verifies that an ir
// accepted with NO POPO at all (tolerated because Required=false — e.g. mTLS
// already proves possession out-of-band) records an EMPTY POPOMethod rather
// than misreporting "signature": there is no POPOSigningKey to point to.
func TestHandleCMP_SecurityMetadata_AbsentPOPO_NotEnforced(t *testing.T) {
	issuedCert, _ := buildSelfSignedCert(t, "nopopo-device")

	router, store, svc := newEnrollRouter(t, models.CMPEnrollmentSettings{
		AcceptImplicit: true,
		IR:             models.CMPIRSettings{ProofOfPossession: models.CMPProofOfPossession{Required: false}},
	}, issuedCert)

	irDER, txID, _ := buildTestIR(t, testIROptions{
		CN:                  "nopopo-device",
		WithImplicitConfirm: true,
		POPOMode:            "",
	})

	resp := postCMP(t, router, "test-dms", irDER)
	require.Equal(t, http.StatusOK, resp.Code)
	assert.Equal(t, corecmp.BodyTagIP, parseCMPResponseTag(t, resp.Body.Bytes()))

	tx, ok := store.Peek(hex.EncodeToString(txID))
	require.True(t, ok)
	assert.Empty(t, tx.POPOMethod, "no POPO was asserted, so POPOMethod must not claim 'signature'")

	svc.AssertExpectations(t)
}

// mockRAValidatorService extends MockLightweightCMPService with
// GetCMPTransactionRepo (so NewCMPHttpRoutes wires the in-memory store) and
// LWCValidateRASigner (services.LightweightCMPRAValidator), letting a test
// exercise the trusted-RA raVerified acceptance branch of handleEnrollment —
// the plain MockLightweightCMPService does not implement that optional
// capability, so the type assertion in handleEnrollment always fails against
// it.
type mockRAValidatorService struct {
	*cmpmock.MockLightweightCMPService
	store storage.CMPTransactionRepo
}

func (m *mockRAValidatorService) GetCMPTransactionRepo() storage.CMPTransactionRepo { return m.store }

func (m *mockRAValidatorService) LWCValidateRASigner(ctx context.Context, dmsID string, signer *x509.Certificate) error {
	args := m.Called(ctx, dmsID, signer)
	return args.Error(0)
}

func newTrustedRARouter(t *testing.T, opts models.CMPEnrollmentSettings, issued *x509.Certificate) (*gin.Engine, *inMemoryCMPStore, *mockRAValidatorService) {
	t.Helper()
	opts = resolveTestCMPOpts(opts)
	store := newInMemoryCMPStore()
	inner := &cmpmock.MockLightweightCMPService{}
	inner.On("LWCGetEnrollmentOptions", mock.Anything, "test-dms").Return(&opts, nil)
	inner.On("LWCEnroll", mock.Anything, mock.AnythingOfType("*x509.CertificateRequest"), "test-dms", mock.Anything).Return(issued, nil)
	wrapped := &mockRAValidatorService{MockLightweightCMPService: inner, store: store}

	gin.SetMode(gin.TestMode)
	r := gin.New()
	logger := logrus.NewEntry(logrus.New())
	routes, err := NewCMPHttpRoutes(logger, wrapped)
	require.NoError(t, err)
	r.POST("/.well-known/cmp/p/:id", routes.HandleCMP)
	return r, store, wrapped
}

// TestHandleCMP_SecurityMetadata_TrustedRA verifies that an ir asserting
// raVerified, signed by a certificate the service validates as a trusted RA
// (id-kp-cmcRA + LWCValidateRASigner), records POPOMethod="trusted_ra"
// (RFC 9483 §5.2.3.2).
func TestHandleCMP_SecurityMetadata_TrustedRA(t *testing.T) {
	raCert, raKey := buildRACert(t, "trusted-ra-enroll")
	issuedCert, _ := buildSelfSignedCert(t, "raverified-device")

	router, store, svc := newTrustedRARouter(t, models.CMPEnrollmentSettings{
		AcceptImplicit: true,
		IR: models.CMPIRSettings{
			ProofOfPossession: models.CMPProofOfPossession{AllowedMethods: []models.CMPPOPOMethod{models.CMPPOPOMethodTrustedRA}},
		},
	}, issuedCert)
	svc.On("LWCValidateRASigner", mock.Anything, "test-dms", mock.Anything).Return(nil)

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	pubKeyDER, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	require.NoError(t, err)
	irBody := buildTestIRBodyDERWithPOPO(t, "raverified-device", pubKeyDER, privKey, "raVerified")

	txID := randomTxID(t)
	headerDER := buildTestPKIHeaderDER(t, txID, randomNonce(t), nil, true)
	irDER, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true,
		Bytes: concatBytes(headerDER, irBody),
	})
	require.NoError(t, err)
	signedIR := signCMPMessage(t, irDER, raCert, raKey)

	resp := postCMP(t, router, "test-dms", signedIR)
	require.Equal(t, http.StatusOK, resp.Code)
	assert.Equal(t, corecmp.BodyTagIP, parseCMPResponseTag(t, resp.Body.Bytes()),
		"a raVerified POPO from a trusted RA must be accepted")

	tx, ok := store.Peek(hex.EncodeToString(txID))
	require.True(t, ok)
	assert.Equal(t, string(models.CMPPOPOMethodTrustedRA), tx.POPOMethod)

	svc.AssertExpectations(t)
}

// TestHandleCMP_SecurityMetadata_AuthenticatorControl verifies
// AuthenticatorControlPresent is recorded true/false according to whether the
// request actually carried the CRMF id-regCtrl-authenticator control
// (RFC 4211 §6.2), independent of any configured ExpectedAuthenticator value.
func TestHandleCMP_SecurityMetadata_AuthenticatorControl(t *testing.T) {
	tests := []struct {
		name        string
		withControl bool
	}{
		{name: "Present", withControl: true},
		{name: "Absent", withControl: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cn := "authctrl-device-" + tc.name
			issuedCert, _ := buildSelfSignedCert(t, cn)
			router, store, svc := newEnrollRouter(t, models.CMPEnrollmentSettings{
				AcceptImplicit: true,
				IR:             models.CMPIRSettings{AuthenticatorControl: models.CMPControl{Mode: models.CMPControlModeOptional}},
			}, issuedCert)

			privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			require.NoError(t, err)
			pubKeyDER, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
			require.NoError(t, err)

			var certRequestDER []byte
			if tc.withControl {
				authValueDER, err := asn1.MarshalWithParams("some-answer", "utf8")
				require.NoError(t, err)
				attrDER, err := asn1.Marshal(struct {
					Type  asn1.ObjectIdentifier
					Value asn1.RawValue
				}{
					Type:  corecmp.OIDRegCtrlAuthenticator(),
					Value: asn1.RawValue{FullBytes: authValueDER},
				})
				require.NoError(t, err)
				controlsDER := seqDER(t, attrDER)
				certRequestDER = buildCertRequestDER(t, cn, pubKeyDER, controlsDER)
			} else {
				certRequestDER = buildCertRequestDER(t, cn, pubKeyDER)
			}
			bodyDER := ctxDER(t, corecmp.BodyTagIR, wrapCertReqMsgs(t, certRequestDER))

			txID := randomTxID(t)
			headerDER := buildTestPKIHeaderDER(t, txID, randomNonce(t), nil, true)
			irDER, err := asn1.Marshal(asn1.RawValue{
				Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true,
				Bytes: concatBytes(headerDER, bodyDER),
			})
			require.NoError(t, err)

			resp := postCMP(t, router, "test-dms", irDER)
			require.Equal(t, http.StatusOK, resp.Code)
			assert.Equal(t, corecmp.BodyTagIP, parseCMPResponseTag(t, resp.Body.Bytes()))

			tx, ok := store.Peek(hex.EncodeToString(txID))
			require.True(t, ok)
			assert.Equal(t, tc.withControl, tx.AuthenticatorControlPresent)

			svc.AssertExpectations(t)
		})
	}
}

// TestHandleCMP_SecurityMetadata_AuthModeAtEnrollment verifies that
// AuthModeAtEnrollment is a faithful, per-request snapshot of the DMS's
// CMPEnrollmentSettings.AuthMode at enrollment time, distinguishing two DMSs
// configured differently.
func TestHandleCMP_SecurityMetadata_AuthModeAtEnrollment(t *testing.T) {
	tests := []struct {
		name     string
		authMode models.CMPAuthMode
	}{
		{name: "NoAuth", authMode: models.CMPAuthModeNoAuth},
		{name: "ClientCertificate", authMode: models.CMPAuthModeClientCertificate},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cn := "authmode-device-" + tc.name
			issuedCert, _ := buildSelfSignedCert(t, cn)
			router, store, svc := newEnrollRouter(t, models.CMPEnrollmentSettings{
				AcceptImplicit: true,
				AuthMode:       tc.authMode,
			}, issuedCert)

			irDER, txID, _ := buildTestIR(t, testIROptions{
				CN:                  cn,
				WithImplicitConfirm: true,
			})
			if tc.authMode == models.CMPAuthModeClientCertificate {
				protCert, protKey := buildSelfSignedCert(t, cn+"-signer")
				irDER = signCMPMessage(t, irDER, protCert, protKey)
			}

			resp := postCMP(t, router, "test-dms", irDER)
			require.Equal(t, http.StatusOK, resp.Code)
			assert.Equal(t, corecmp.BodyTagIP, parseCMPResponseTag(t, resp.Body.Bytes()))

			tx, ok := store.Peek(hex.EncodeToString(txID))
			require.True(t, ok)
			assert.Equal(t, string(tc.authMode), tx.AuthModeAtEnrollment)

			svc.AssertExpectations(t)
		})
	}
}
