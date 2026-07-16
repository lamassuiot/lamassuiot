package cmp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"net/http"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// Coverage for genm/genp (RFC 9483 §4.3): one test per InfoType required by
// the project's test plan (caCerts, rootCaKeyUpdate, certReqTemplate,
// crlStatusList), plus the unknown-InfoType error path. Prior to these tests
// handleGeneralMessage/buildGenpEntry (cmp_genmsg.go) had no dedicated unit
// or e2e coverage at all despite being fully implemented.
//
// Request/response construction is hand-rolled independently of
// cmp_genmsg.go's own encoders (buildTestGenM/buildTestITAV/
// decodeTestGenRepEntries below), matching this suite's established
// philosophy of not routing test fixtures through the same code being
// tested.

// buildTestITAV encodes a single InfoTypeAndValue ::= SEQUENCE { infoType
// OBJECT IDENTIFIER, infoValue ANY OPTIONAL }. valueDER == nil omits infoValue.
func buildTestITAV(t *testing.T, oid asn1.ObjectIdentifier, valueDER []byte) []byte {
	t.Helper()
	if len(valueDER) == 0 {
		der, err := asn1.Marshal(struct {
			InfoType asn1.ObjectIdentifier
		}{oid})
		require.NoError(t, err)
		return der
	}
	der, err := asn1.Marshal(struct {
		InfoType  asn1.ObjectIdentifier
		InfoValue asn1.RawValue
	}{oid, asn1.RawValue{FullBytes: valueDER}})
	require.NoError(t, err)
	return der
}

// buildTestGenM constructs a minimal DER-encoded genm (21) PKIMessage carrying
// GenMsgContent ::= SEQUENCE OF InfoTypeAndValue.
func buildTestGenM(t *testing.T, txID []byte, itavDER ...[]byte) []byte {
	t.Helper()
	senderNonce := randomNonce(t)
	headerDER := buildTestPKIHeaderDER(t, txID, senderNonce, nil, false)
	genMsgContent := seqDER(t, itavDER...)
	bodyDER := ctxDER(t, cmpBodyTagGenMsg, genMsgContent)
	msgDER, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      concatBytes(headerDER, bodyDER),
	})
	require.NoError(t, err)
	return msgDER
}

// testITAV mirrors InfoTypeAndValue for response decoding, independent of
// cmp_genmsg.go's genITAV.
type testITAV struct {
	InfoType  asn1.ObjectIdentifier
	InfoValue asn1.RawValue `asn1:"optional"`
}

// decodeTestGenRepEntries parses a genp (22) PKIBody's raw bytes (a
// GenRepContent ::= SEQUENCE OF InfoTypeAndValue) into individual entries.
func decodeTestGenRepEntries(t *testing.T, genRepBodyBytes []byte) []testITAV {
	t.Helper()
	var seq asn1.RawValue
	_, err := asn1.Unmarshal(genRepBodyBytes, &seq)
	require.NoError(t, err)
	require.Equal(t, asn1.ClassUniversal, seq.Class)
	require.Equal(t, asn1.TagSequence, seq.Tag)

	var out []testITAV
	rest := seq.Bytes
	for len(rest) > 0 {
		var it testITAV
		rest, err = asn1.Unmarshal(rest, &it)
		require.NoError(t, err)
		out = append(out, it)
	}
	return out
}

// genRepSingleEntry posts msgDER, asserts the response is a genp carrying
// exactly one InfoTypeAndValue, and returns it.
func genRepSingleEntry(t *testing.T, router *gin.Engine, dmsID string, msgDER []byte) testITAV {
	t.Helper()
	resp := postCMP(t, router, dmsID, msgDER)
	require.Equal(t, http.StatusOK, resp.Code)

	var msg rawPKIMessage
	_, err := asn1.Unmarshal(resp.Body.Bytes(), &msg)
	require.NoError(t, err)
	require.Equal(t, cmpBodyTagGenRep, msg.Body.Tag, "genm must be answered with a genp (22) body")

	entries := decodeTestGenRepEntries(t, msg.Body.Bytes)
	require.Len(t, entries, 1)
	return entries[0]
}

func TestHandleCMP_GenM_CACerts(t *testing.T) {
	router, _, svc := newOptionsRouter(t, models.EnrollmentOptionsLWCRFC9483{})
	caCert, _ := buildSelfSignedCert(t, "test-ca")
	svc.On("LWCCACerts", mock.Anything, "test-dms").Return([]*x509.Certificate{caCert}, nil)

	msgDER := buildTestGenM(t, randomTxID(t), buildTestITAV(t, oidItCaCerts, nil))
	entry := genRepSingleEntry(t, router, "test-dms", msgDER)

	assert.True(t, entry.InfoType.Equal(oidItCaCerts), "response infoType must be id-it-caCerts")
	require.NotEmpty(t, entry.InfoValue.FullBytes, "caCerts response must carry the CA certificate chain")

	var caCertsSeq asn1.RawValue
	_, err := asn1.Unmarshal(entry.InfoValue.FullBytes, &caCertsSeq)
	require.NoError(t, err)
	parsedCA, err := x509.ParseCertificate(caCertsSeq.Bytes)
	require.NoError(t, err, "CaCertsValue must decode as a SEQUENCE OF Certificate")
	assert.Equal(t, caCert.Raw, parsedCA.Raw, "returned CA cert must be the one LWCCACerts provided")

	svc.AssertExpectations(t)
}

func TestHandleCMP_GenM_RootCACertUpdate(t *testing.T) {
	router, _, svc := newOptionsRouter(t, models.EnrollmentOptionsLWCRFC9483{})
	newRoot, _ := buildSelfSignedCert(t, "new-root")
	oldRoot, _ := buildSelfSignedCert(t, "old-root")
	svc.On("LWCGetRootCACertUpdate", mock.Anything, services.GetRootCACertUpdateInput{APS: "test-dms"}).
		Return(&services.RootCACertUpdateOutput{NewWithNew: newRoot, NewWithOld: oldRoot}, nil)

	// The request InfoType is id-it-rootCaCert (RFC 9483 §4.3.2 genm side);
	// the response must carry the DIFFERENT id-it-rootCaKeyUpdate OID.
	msgDER := buildTestGenM(t, randomTxID(t), buildTestITAV(t, oidItRootCaCert, nil))
	entry := genRepSingleEntry(t, router, "test-dms", msgDER)

	assert.True(t, entry.InfoType.Equal(oidItRootCaKeyUpdate),
		"response infoType must be id-it-rootCaKeyUpdate, not the request's id-it-rootCaCert")
	require.NotEmpty(t, entry.InfoValue.FullBytes, "rootCaKeyUpdate response must carry a RootCaKeyUpdateValue")

	svc.AssertExpectations(t)
}

func TestHandleCMP_GenM_RootCACertUpdate_NoneAvailable(t *testing.T) {
	router, _, svc := newOptionsRouter(t, models.EnrollmentOptionsLWCRFC9483{})
	svc.On("LWCGetRootCACertUpdate", mock.Anything, services.GetRootCACertUpdateInput{APS: "test-dms"}).
		Return(nil, nil)

	msgDER := buildTestGenM(t, randomTxID(t), buildTestITAV(t, oidItRootCaCert, nil))
	entry := genRepSingleEntry(t, router, "test-dms", msgDER)

	assert.True(t, entry.InfoType.Equal(oidItRootCaKeyUpdate))
	assert.Empty(t, entry.InfoValue.FullBytes, "no update available must produce an absent infoValue, not an error")

	svc.AssertExpectations(t)
}

func TestHandleCMP_GenM_CertReqTemplate(t *testing.T) {
	router, _, svc := newOptionsRouter(t, models.EnrollmentOptionsLWCRFC9483{})
	svc.On("LWCGetCertReqTemplate", mock.Anything, services.GetCertReqTemplateInput{APS: "test-dms"}).
		Return(&services.CertReqTemplateOutput{}, nil)

	msgDER := buildTestGenM(t, randomTxID(t), buildTestITAV(t, oidItCertReqTemplate, nil))
	entry := genRepSingleEntry(t, router, "test-dms", msgDER)

	assert.True(t, entry.InfoType.Equal(oidItCertReqTemplate))
	require.NotEmpty(t, entry.InfoValue.FullBytes, "certReqTemplate response must carry a CertReqTemplateValue")

	svc.AssertExpectations(t)
}

func TestHandleCMP_GenM_CRLStatusList(t *testing.T) {
	router, _, svc := newOptionsRouter(t, models.EnrollmentOptionsLWCRFC9483{})

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "crl-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	caCert, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)

	crlDER, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: time.Now(),
		NextUpdate: time.Now().Add(time.Hour),
	}, caCert, caKey)
	require.NoError(t, err)
	crl, err := x509.ParseRevocationList(crlDER)
	require.NoError(t, err)

	svc.On("LWCGetCRL", mock.Anything, services.GetCMPCRLInput{APS: "test-dms"}).Return(crl, nil)

	// The request InfoType is id-it-crlStatusList; the response must carry the
	// DIFFERENT id-it-crls OID (RFC 9483 §4.3.4).
	msgDER := buildTestGenM(t, randomTxID(t), buildTestITAV(t, oidItCrlStatusList, nil))
	entry := genRepSingleEntry(t, router, "test-dms", msgDER)

	assert.True(t, entry.InfoType.Equal(oidItCrls),
		"response infoType must be id-it-crls, not the request's id-it-crlStatusList")
	require.NotEmpty(t, entry.InfoValue.FullBytes, "crlStatusList response must carry the CRL")

	var crlsSeq asn1.RawValue
	_, err = asn1.Unmarshal(entry.InfoValue.FullBytes, &crlsSeq)
	require.NoError(t, err)
	parsedCRL, err := x509.ParseRevocationList(crlsSeq.Bytes)
	require.NoError(t, err, "CRLsValue must decode as a SEQUENCE OF CertificateList")
	assert.Equal(t, crl.Raw, parsedCRL.Raw)

	svc.AssertExpectations(t)
}

func TestHandleCMP_GenM_UnknownInfoType(t *testing.T) {
	router, _, svc := newOptionsRouter(t, models.EnrollmentOptionsLWCRFC9483{})

	unknownOID := asn1.ObjectIdentifier{1, 2, 3, 4, 5, 6, 7}
	msgDER := buildTestGenM(t, randomTxID(t), buildTestITAV(t, unknownOID, nil))

	resp := postCMP(t, router, "test-dms", msgDER)
	require.Equal(t, http.StatusOK, resp.Code)
	assert.Equal(t, cmpBodyTagError, parseCMPResponseTag(t, resp.Body.Bytes()),
		"an unknown genm InfoType must be rejected with a CMP error body")

	svc.AssertExpectations(t)
}
