package cmp

import (
	"bytes"
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
	corecmp "github.com/lamassuiot/lamassuiot/core/v3/pkg/cmp"
	chelpers "github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
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
	bodyDER := ctxDER(t, corecmp.BodyTagGenMsg, genMsgContent)
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

	var msg corecmp.RawPKIMessage
	_, err := asn1.Unmarshal(resp.Body.Bytes(), &msg)
	require.NoError(t, err)
	require.Equal(t, corecmp.BodyTagGenRep, msg.Body.Tag, "genm must be answered with a genp (22) body")

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
	router, _, svc := newOptionsRouter(t, models.EnrollmentOptionsLWCRFC9483{
		GENM: models.CMPGENMSettings{InformationTypes: models.CMPGENMInformationTypes{RootCAUpdate: true}},
	})
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
	router, _, svc := newOptionsRouter(t, models.EnrollmentOptionsLWCRFC9483{
		GENM: models.CMPGENMSettings{InformationTypes: models.CMPGENMInformationTypes{RootCAUpdate: true}},
	})
	svc.On("LWCGetRootCACertUpdate", mock.Anything, services.GetRootCACertUpdateInput{APS: "test-dms"}).
		Return(nil, nil)

	msgDER := buildTestGenM(t, randomTxID(t), buildTestITAV(t, oidItRootCaCert, nil))
	entry := genRepSingleEntry(t, router, "test-dms", msgDER)

	assert.True(t, entry.InfoType.Equal(oidItRootCaKeyUpdate))
	assert.Empty(t, entry.InfoValue.FullBytes, "no update available must produce an absent infoValue, not an error")

	svc.AssertExpectations(t)
}

func TestHandleCMP_GenM_CertReqTemplate(t *testing.T) {
	router, _, svc := newOptionsRouter(t, models.EnrollmentOptionsLWCRFC9483{
		GENM: models.CMPGENMSettings{InformationTypes: models.CMPGENMInformationTypes{CertificateRequestTemplate: true}},
	})
	svc.On("LWCGetCertReqTemplate", mock.Anything, services.GetCertReqTemplateInput{APS: "test-dms"}).
		Return(&services.CertReqTemplateOutput{}, nil)

	msgDER := buildTestGenM(t, randomTxID(t), buildTestITAV(t, oidItCertReqTemplate, nil))
	entry := genRepSingleEntry(t, router, "test-dms", msgDER)

	assert.True(t, entry.InfoType.Equal(oidItCertReqTemplate))
	require.NotEmpty(t, entry.InfoValue.FullBytes, "certReqTemplate response must carry a CertReqTemplateValue")

	svc.AssertExpectations(t)
}

// buildTestCRLStatusList encodes an id-it-crlStatusList request value the way a
// conforming client does (RFC 9480 §2.16):
//
//	SEQUENCE OF CRLStatus, CRLStatus ::= SEQUENCE { source CRLSource, thisUpdate Time OPTIONAL }
//	CRLSource ::= CHOICE { dpn [0] DistributionPointName, issuer [1] GeneralNames }
//
// The source is the issuer [1] alternative holding a directoryName [4]
// GeneralName. This builds the EXPLICIT form that OpenSSL actually emits, in
// which [1] wraps the GeneralNames SEQUENCE so the GeneralName entries sit one
// level below the context tag. The IMPLICIT alternative (GeneralName entries
// directly inside [1]) is covered separately in
// TestDecodeCRLStatusList_ImplicitGeneralNames, and the byte-exact OpenSSL
// capture is pinned in TestDecodeCRLStatusList_RealOpenSSLRequest.
func buildTestCRLStatusList(t *testing.T, issuerRawDN []byte, thisUpdate time.Time) []byte {
	t.Helper()

	directoryName, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassContextSpecific, Tag: 4, IsCompound: true, Bytes: issuerRawDN,
	})
	require.NoError(t, err)
	generalNames, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: directoryName,
	})
	require.NoError(t, err)
	issuerSource, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassContextSpecific, Tag: 1, IsCompound: true, Bytes: generalNames,
	})
	require.NoError(t, err)

	statusContent := issuerSource
	if !thisUpdate.IsZero() {
		timeDER, err := asn1.MarshalWithParams(thisUpdate.UTC(), "utc")
		require.NoError(t, err)
		statusContent = append(statusContent, timeDER...)
	}

	status, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: statusContent,
	})
	require.NoError(t, err)

	value, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: status,
	})
	require.NoError(t, err)
	return value
}

func TestHandleCMP_GenM_CRLStatusList(t *testing.T) {
	router, _, svc := newOptionsRouter(t, models.EnrollmentOptionsLWCRFC9483{
		GENM: models.CMPGENMSettings{InformationTypes: models.CMPGENMInformationTypes{CRLUpdate: true}},
	})

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

	// The request's CRLStatus must reach the service: the issuer names WHICH CRL
	// is wanted and thisUpdate says how fresh the EE's copy already is. A handler
	// that drops either turns this operation into a plain "give me the current
	// CRL" — which is what id-it-currentCRL already is.
	eeThisUpdate := crl.ThisUpdate.Add(-2 * time.Hour)
	svc.On("LWCGetCRL", mock.Anything, mock.MatchedBy(func(in services.GetCMPCRLInput) bool {
		return in.APS == "test-dms" &&
			bytes.Equal(in.IssuerRawDN, caCert.RawSubject) &&
			in.CurrentThisUpdate.Equal(eeThisUpdate.Truncate(time.Second))
	})).Return(crl, nil)

	// The request InfoType is id-it-crlStatusList; the response must carry the
	// DIFFERENT id-it-crls OID (RFC 9483 §4.3.4).
	statusValue := buildTestCRLStatusList(t, caCert.RawSubject, eeThisUpdate)
	msgDER := buildTestGenM(t, randomTxID(t), buildTestITAV(t, oidItCrlStatusList, statusValue))
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

// TestHandleCMP_GenM_CRLStatusList_MissingValue locks in that the request value
// is MANDATORY for id-it-crlStatusList (RFC 9480 §2.16 gives it no absent
// alternative), unlike every other support message whose value MUST be absent.
func TestHandleCMP_GenM_CRLStatusList_MissingValue(t *testing.T) {
	router, _, svc := newOptionsRouter(t, models.EnrollmentOptionsLWCRFC9483{
		GENM: models.CMPGENMSettings{InformationTypes: models.CMPGENMInformationTypes{CRLUpdate: true}},
	})

	msgDER := buildTestGenM(t, randomTxID(t), buildTestITAV(t, oidItCrlStatusList, nil))
	resp := postCMP(t, router, "test-dms", msgDER)
	require.Equal(t, http.StatusOK, resp.Code)
	assert.Equal(t, corecmp.BodyTagError, parseCMPResponseTag(t, resp.Body.Bytes()),
		"a crlStatusList request with no CRLStatus must be rejected")
	svc.AssertNotCalled(t, "LWCGetCRL", mock.Anything, mock.Anything)
}

// TestHandleCMP_GenM_CRLStatusList_UpToDate covers the answer that makes CRL
// update retrieval different from a plain current-CRL fetch: when the EE already
// holds a CRL at least as fresh as ours, the service reports no update and the
// genp carries id-it-crls with an ABSENT value — "you are current" — rather than
// re-sending a CRL the EE already has.
func TestHandleCMP_GenM_CRLStatusList_UpToDate(t *testing.T) {
	router, _, svc := newOptionsRouter(t, models.EnrollmentOptionsLWCRFC9483{
		GENM: models.CMPGENMSettings{InformationTypes: models.CMPGENMInformationTypes{CRLUpdate: true}},
	})

	svc.On("LWCGetCRL", mock.Anything, mock.Anything).Return(nil, nil)

	statusValue := buildTestCRLStatusList(t, testRawSubject(t, "crl-ca"), time.Now())
	msgDER := buildTestGenM(t, randomTxID(t), buildTestITAV(t, oidItCrlStatusList, statusValue))
	entry := genRepSingleEntry(t, router, "test-dms", msgDER)

	assert.True(t, entry.InfoType.Equal(oidItCrls))
	assert.Empty(t, entry.InfoValue.FullBytes,
		"no CRL newer than the EE's copy means an absent infoValue, not a resent CRL")
	svc.AssertExpectations(t)
}

// testRawSubject returns the DER RDNSequence for a CN-only subject.
func testRawSubject(t *testing.T, cn string) []byte {
	t.Helper()
	der, err := asn1.Marshal(pkix.Name{CommonName: cn}.ToRDNSequence())
	require.NoError(t, err)
	return der
}

// TestEncodeCertReqTemplateValue exercises the hand-rolled RFC 9483 §4.3.3
// CertReqTemplateValue encoder directly (the controller-level tests only assert
// non-emptiness): it must emit a CertTemplate carrying the mandated subject as
// an EXPLICIT [5] Name, plus a keySpec Controls sequence. RSA is advertised as
// id-regCtrl-rsaKeyLen (never as an id-regCtrl-algId, which RFC 9480 §2.15
// forbids for rsaEncryption), and it wins over ECDSA when the profile accepts
// both — so a single control is emitted even here.
func TestEncodeCertReqTemplateValue(t *testing.T) {
	out := &services.CertReqTemplateOutput{
		Subject:              x509.Certificate{Subject: pkix.Name{CommonName: "mandated-cn", Organization: []string{"LAMASSU"}}},
		AllowedKeyAlgorithms: []x509.PublicKeyAlgorithm{x509.RSA, x509.ECDSA},
		AllowedRSAKeySizes:   []int{3072, 4096},
		AllowedECDSAKeySizes: []int{256},
	}
	der, err := encodeCertReqTemplateValue(out)
	require.NoError(t, err)

	var outer asn1.RawValue
	_, err = asn1.Unmarshal(der, &outer)
	require.NoError(t, err)
	require.Equal(t, asn1.TagSequence, outer.Tag)

	// certTemplate (SEQUENCE) then keySpec (SEQUENCE).
	var certTemplate asn1.RawValue
	rest, err := asn1.Unmarshal(outer.Bytes, &certTemplate)
	require.NoError(t, err)
	require.Equal(t, asn1.TagSequence, certTemplate.Tag)

	var keySpec asn1.RawValue
	_, err = asn1.Unmarshal(rest, &keySpec)
	require.NoError(t, err)
	require.Equal(t, asn1.TagSequence, keySpec.Tag)

	// certTemplate.subject is [5] wrapping an RDNSequence.
	var subjectField asn1.RawValue
	_, err = asn1.Unmarshal(certTemplate.Bytes, &subjectField)
	require.NoError(t, err)
	assert.Equal(t, asn1.ClassContextSpecific, subjectField.Class)
	assert.Equal(t, 5, subjectField.Tag)

	var rdn pkix.RDNSequence
	_, err = asn1.Unmarshal(subjectField.Bytes, &rdn)
	require.NoError(t, err)
	var name pkix.Name
	name.FillFromRDNSequence(&rdn)
	assert.Equal(t, "mandated-cn", name.CommonName)

	// keySpec Controls: exactly one control, and for RSA it is the rsaKeyLen
	// INTEGER carrying the SMALLEST accepted modulus size (advertising a larger
	// one would turn keys the CA accepts into keys the EE never generates).
	var atav struct {
		Type  asn1.ObjectIdentifier
		Value asn1.RawValue
	}
	r, err := asn1.Unmarshal(keySpec.Bytes, &atav)
	require.NoError(t, err)
	assert.Empty(t, r, "keySpec must carry exactly one control")
	assert.True(t, atav.Type.Equal(oidRegCtrlRsaKeyLen), "RSA must be advertised as id-regCtrl-rsaKeyLen")

	var keyLen int
	_, err = asn1.Unmarshal(atav.Value.FullBytes, &keyLen)
	require.NoError(t, err)
	assert.Equal(t, 3072, keyLen)
}

// TestEncodeCertReqTemplateKeySpec_ECDSA covers the non-RSA branch: ECDSA is
// advertised as an id-regCtrl-algId whose AlgorithmIdentifier MUST carry the
// ECParameters namedCurve — a bare id-ecPublicKey would not tell the EE which
// curve to generate on.
func TestEncodeCertReqTemplateKeySpec_ECDSA(t *testing.T) {
	der, err := encodeCertReqTemplateKeySpec(&services.CertReqTemplateOutput{
		AllowedKeyAlgorithms: []x509.PublicKeyAlgorithm{x509.ECDSA},
		AllowedECDSAKeySizes: []int{384, 521},
	})
	require.NoError(t, err)

	var keySpec asn1.RawValue
	_, err = asn1.Unmarshal(der, &keySpec)
	require.NoError(t, err)

	var atav struct {
		Type  asn1.ObjectIdentifier
		Value asn1.RawValue
	}
	rest, err := asn1.Unmarshal(keySpec.Bytes, &atav)
	require.NoError(t, err)
	assert.Empty(t, rest, "keySpec must carry exactly one control")
	assert.True(t, atav.Type.Equal(oidRegCtrlAlgId))

	var alg pkix.AlgorithmIdentifier
	_, err = asn1.Unmarshal(atav.Value.FullBytes, &alg)
	require.NoError(t, err)
	assert.True(t, alg.Algorithm.Equal(corecmp.OIDECPublicKey()))

	var namedCurve asn1.ObjectIdentifier
	_, err = asn1.Unmarshal(alg.Parameters.FullBytes, &namedCurve)
	require.NoError(t, err, "ecPublicKey parameters must decode as an ECParameters namedCurve")
	assert.True(t, namedCurve.Equal(ecCurveOIDByBits[384]), "smallest accepted curve must be advertised")
}

// TestEncodeCertReqTemplateKeySpec_Unconstrained locks in that keySpec is OMITTED
// when the profile constrains no algorithm (crypto enforcement off). keySpec is
// OPTIONAL, so an absent one is the correct encoding — emitting an empty Controls
// SEQUENCE would violate its SIZE (1..MAX) bound.
func TestEncodeCertReqTemplateKeySpec_Unconstrained(t *testing.T) {
	der, err := encodeCertReqTemplateKeySpec(&services.CertReqTemplateOutput{})
	require.NoError(t, err)
	assert.Nil(t, der)
}

// TestEncodeCertReqTemplateValue_Validity verifies the always-present validity
// [4] field: IMPLICIT over OptionalValidity, with notBefore [0] / notAfter [1]
// EXPLICITly tagged Times (Time is a CHOICE). This is what makes a certReqTemplate
// available even for a profile that otherwise honors everything from the request.
func TestEncodeCertReqTemplateValue_Validity(t *testing.T) {
	nb := time.Date(2026, 7, 28, 10, 0, 0, 0, time.UTC)
	na := time.Date(2036, 7, 28, 10, 0, 0, 0, time.UTC)
	der, err := encodeCertReqTemplateValue(&services.CertReqTemplateOutput{NotBefore: nb, NotAfter: na})
	require.NoError(t, err)

	var outer asn1.RawValue
	_, err = asn1.Unmarshal(der, &outer)
	require.NoError(t, err)
	var certTemplate asn1.RawValue
	rest, err := asn1.Unmarshal(outer.Bytes, &certTemplate)
	require.NoError(t, err)
	assert.Empty(t, rest, "no keySpec expected")

	// validity [4] is the only certTemplate field present.
	var validityField asn1.RawValue
	_, err = asn1.Unmarshal(certTemplate.Bytes, &validityField)
	require.NoError(t, err)
	assert.Equal(t, asn1.ClassContextSpecific, validityField.Class)
	assert.Equal(t, 4, validityField.Tag)

	// notBefore [0] then notAfter [1], each EXPLICIT over a Time value.
	var nbField asn1.RawValue
	r, err := asn1.Unmarshal(validityField.Bytes, &nbField)
	require.NoError(t, err)
	assert.Equal(t, 0, nbField.Tag)
	var naField asn1.RawValue
	_, err = asn1.Unmarshal(r, &naField)
	require.NoError(t, err)
	assert.Equal(t, 1, naField.Tag)

	var gotNB, gotNA time.Time
	_, err = asn1.Unmarshal(nbField.Bytes, &gotNB)
	require.NoError(t, err)
	_, err = asn1.Unmarshal(naField.Bytes, &gotNA)
	require.NoError(t, err)
	assert.True(t, gotNB.Equal(nb), "notBefore round-trips")
	assert.True(t, gotNA.Equal(na), "notAfter round-trips")
}

// TestEncodeCertReqTemplateValue_Empty verifies that an output with no
// constraints still yields a well-formed (empty CertTemplate)-only value.
func TestEncodeCertReqTemplateValue_Empty(t *testing.T) {
	der, err := encodeCertReqTemplateValue(&services.CertReqTemplateOutput{})
	require.NoError(t, err)

	var outer asn1.RawValue
	_, err = asn1.Unmarshal(der, &outer)
	require.NoError(t, err)
	require.Equal(t, asn1.TagSequence, outer.Tag)

	var certTemplate asn1.RawValue
	rest, err := asn1.Unmarshal(outer.Bytes, &certTemplate)
	require.NoError(t, err)
	assert.Equal(t, asn1.TagSequence, certTemplate.Tag)
	assert.Empty(t, certTemplate.Bytes, "empty output must yield an empty CertTemplate")
	assert.Empty(t, rest, "no keySpec must be emitted when no algorithms are advertised")
}

// TestEncodeCertReqTemplateValue_KeyUsageExtensions verifies the certTemplate
// carries a mandated keyUsage/extKeyUsage as an IMPLICITly-tagged extensions
// [9] field (RFC 4211 §5) — decoded the exact same way the request-side
// parser (parseCertTemplateExtensions in core/pkg/cmp/crmf.go) reads it: the
// [9] tag substitutes for the SEQUENCE tag, so its content is the
// concatenation of individual Extension TLVs, not those TLVs re-wrapped in an
// extra inner SEQUENCE.
func TestEncodeCertReqTemplateValue_KeyUsageExtensions(t *testing.T) {
	out := &services.CertReqTemplateOutput{
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := encodeCertReqTemplateValue(out)
	require.NoError(t, err)

	var outer asn1.RawValue
	_, err = asn1.Unmarshal(der, &outer)
	require.NoError(t, err)
	var certTemplate asn1.RawValue
	_, err = asn1.Unmarshal(outer.Bytes, &certTemplate)
	require.NoError(t, err)

	// No subject was set, so extensions [9] is the only field present.
	var extField asn1.RawValue
	_, err = asn1.Unmarshal(certTemplate.Bytes, &extField)
	require.NoError(t, err)
	assert.Equal(t, asn1.ClassContextSpecific, extField.Class)
	assert.Equal(t, 9, extField.Tag)

	rest := extField.Bytes
	var exts []pkix.Extension
	for len(rest) > 0 {
		var ext pkix.Extension
		rest, err = asn1.Unmarshal(rest, &ext)
		require.NoError(t, err)
		exts = append(exts, ext)
	}
	require.Len(t, exts, 2, "keyUsage and extKeyUsage must each be a separate Extension TLV")
	assert.True(t, exts[0].Id.Equal(chelpers.OidExtensionKeyUsage))
	assert.True(t, exts[1].Id.Equal(chelpers.OidExtensionExtendedKeyUsage))
}

// TestPreferredSymmAlgOID verifies each configured AES variant maps to its OID,
// and that an unknown/empty value falls back to AES-256-CBC.
func TestPreferredSymmAlgOID(t *testing.T) {
	cases := map[models.CMPPreferredSymmetricAlgorithm]asn1.ObjectIdentifier{
		models.CMPPreferredSymmetricAlgorithmAES128CBC: oidAES128CBC,
		models.CMPPreferredSymmetricAlgorithmAES192CBC: oidAES192CBC,
		models.CMPPreferredSymmetricAlgorithmAES256CBC: oidAES256CBC,
		models.CMPPreferredSymmetricAlgorithmAES128GCM: oidAES128GCM,
		models.CMPPreferredSymmetricAlgorithmAES192GCM: oidAES192GCM,
		models.CMPPreferredSymmetricAlgorithmAES256GCM: oidAES256GCM,
	}
	for alg, want := range cases {
		assert.True(t, preferredSymmAlgOID(alg).Equal(want), "alg %s", alg)
	}
	assert.True(t, preferredSymmAlgOID("").Equal(oidAES256CBC), "empty must default to AES-256-CBC")
	assert.True(t, preferredSymmAlgOID("bogus").Equal(oidAES256CBC), "unknown must default to AES-256-CBC")
}

// TestHandleCMP_GenM_PreferredSymmAlg checks the id-it-preferredSymmAlg response
// carries the AES variant the DMS configured, not the hardcoded default.
func TestHandleCMP_GenM_PreferredSymmAlg(t *testing.T) {
	router, _, _ := newOptionsRouter(t, models.EnrollmentOptionsLWCRFC9483{
		GENM: models.CMPGENMSettings{
			InformationTypes:            models.CMPGENMInformationTypes{PreferredSymmetricAlgorithm: true},
			PreferredSymmetricAlgorithm: models.CMPPreferredSymmetricAlgorithmAES128GCM,
		},
	})

	msgDER := buildTestGenM(t, randomTxID(t), buildTestITAV(t, oidItPreferredSymmAlg, nil))
	entry := genRepSingleEntry(t, router, "test-dms", msgDER)

	assert.True(t, entry.InfoType.Equal(oidItPreferredSymmAlg))
	require.NotEmpty(t, entry.InfoValue.FullBytes)

	var alg pkix.AlgorithmIdentifier
	_, err := asn1.Unmarshal(entry.InfoValue.FullBytes, &alg)
	require.NoError(t, err)
	assert.True(t, alg.Algorithm.Equal(oidAES128GCM), "must advertise the configured AES-128-GCM")
}

// TestHandleCMP_GenM_PublicDiscovery_UnprotectedUnderClientCertAuth locks in
// that a public_discovery genm is answered UNPROTECTED even when the DMS's
// enrollment auth_mode is CLIENT_CERTIFICATE. genm protection is governed by
// GENM.AccessPolicy, not auth_mode — so capability discovery works regardless
// of how the DMS authenticates enrollment.
func TestHandleCMP_GenM_PublicDiscovery_UnprotectedUnderClientCertAuth(t *testing.T) {
	router, _, svc := newOptionsRouter(t, models.EnrollmentOptionsLWCRFC9483{
		AuthMode: models.CMPAuthModeClientCertificate,
		GENM: models.CMPGENMSettings{
			Enabled:          true,
			AccessPolicy:     models.CMPGENMAccessPolicyPublicDiscovery,
			InformationTypes: models.CMPGENMInformationTypes{CACertificates: true},
		},
	})
	caCert, _ := buildSelfSignedCert(t, "test-ca")
	svc.On("LWCCACerts", mock.Anything, "test-dms").Return([]*x509.Certificate{caCert}, nil)

	// Unprotected genm (no extraCerts / no protection) — the compliance path a
	// discovery client uses.
	msgDER := buildTestGenM(t, randomTxID(t), buildTestITAV(t, oidItCaCerts, nil))
	entry := genRepSingleEntry(t, router, "test-dms", msgDER)

	assert.True(t, entry.InfoType.Equal(oidItCaCerts), "public_discovery genm must be answered even under CLIENT_CERTIFICATE auth")
	svc.AssertExpectations(t)
}

// TestHandleCMP_GenM_RequireSigned_RejectsUnprotected verifies the opposite
// gate: with GENM.AccessPolicy=require_signed, an unprotected genm is rejected
// at the wire layer (before any info-type handler runs).
func TestHandleCMP_GenM_RequireSigned_RejectsUnprotected(t *testing.T) {
	router, _, _ := newOptionsRouter(t, models.EnrollmentOptionsLWCRFC9483{
		AuthMode: models.CMPAuthModeNoAuth,
		GENM: models.CMPGENMSettings{
			Enabled:          true,
			AccessPolicy:     models.CMPGENMAccessPolicyRequireSigned,
			InformationTypes: models.CMPGENMInformationTypes{CACertificates: true},
		},
	})

	msgDER := buildTestGenM(t, randomTxID(t), buildTestITAV(t, oidItCaCerts, nil))
	resp := postCMP(t, router, "test-dms", msgDER)
	require.Equal(t, http.StatusOK, resp.Code)
	assert.Equal(t, corecmp.BodyTagError, parseCMPResponseTag(t, resp.Body.Bytes()),
		"an unprotected genm under require_signed must be rejected with a CMP error body")
}

// TestHandleCMP_GenM_HardDisabledInfoTypes locks in that revPassphrase is kept
// out of service: it has no config toggle, so without an explicit case in
// genmInfoTypeEnabled it would fall through the default to being answered.
func TestHandleCMP_GenM_HardDisabledInfoTypes(t *testing.T) {
	router, _, _ := newOptionsRouter(t, models.EnrollmentOptionsLWCRFC9483{
		GENM: models.CMPGENMSettings{
			Enabled:      true,
			AccessPolicy: models.CMPGENMAccessPolicyPublicDiscovery,
		},
	})

	msgDER := buildTestGenM(t, randomTxID(t), buildTestITAV(t, oidItRevPassphrase, nil))
	resp := postCMP(t, router, "test-dms", msgDER)
	require.Equal(t, http.StatusOK, resp.Code)
	assert.Equal(t, corecmp.BodyTagError, parseCMPResponseTag(t, resp.Body.Bytes()),
		"id-it-revPassphrase must be rejected while hard-disabled")
}

// TestHandleCMP_GenM_CAProtEncCert covers the caProtEncCert answer: Lamassu never
// provisions a dedicated protocol-encryption certificate, so the genp carries the
// id-it-caProtEncCert infoType with an ABSENT infoValue. That is a real answer
// ("not available") rather than a rejection — rejecting the whole genm would turn
// a legitimate capability query into a CMP error.
func TestHandleCMP_GenM_CAProtEncCert(t *testing.T) {
	router, _, _ := newOptionsRouter(t, models.EnrollmentOptionsLWCRFC9483{
		GENM: models.CMPGENMSettings{
			Enabled:          true,
			AccessPolicy:     models.CMPGENMAccessPolicyPublicDiscovery,
			InformationTypes: models.CMPGENMInformationTypes{ProtocolEncryptionCertificate: true},
		},
	})

	msgDER := buildTestGenM(t, randomTxID(t), buildTestITAV(t, oidItCaProtEncCert, nil))
	entry := genRepSingleEntry(t, router, "test-dms", msgDER)
	assert.True(t, entry.InfoType.Equal(oidItCaProtEncCert))
	assert.Empty(t, entry.InfoValue.FullBytes, "no protocol-encryption cert is provisioned, so the value must be absent")
}

// TestHandleCMP_GenM_CAProtEncCertDisabled proves the answer above is still gated
// on the operator's toggle rather than being unconditional.
func TestHandleCMP_GenM_CAProtEncCertDisabled(t *testing.T) {
	router, _, _ := newOptionsRouter(t, models.EnrollmentOptionsLWCRFC9483{
		GENM: models.CMPGENMSettings{
			Enabled:          true,
			AccessPolicy:     models.CMPGENMAccessPolicyPublicDiscovery,
			InformationTypes: models.CMPGENMInformationTypes{ProtocolEncryptionCertificate: false},
		},
	})

	msgDER := buildTestGenM(t, randomTxID(t), buildTestITAV(t, oidItCaProtEncCert, nil))
	resp := postCMP(t, router, "test-dms", msgDER)
	require.Equal(t, http.StatusOK, resp.Code)
	assert.Equal(t, corecmp.BodyTagError, parseCMPResponseTag(t, resp.Body.Bytes()),
		"caProtEncCert must be rejected when the DMS has the info type disabled")
}

func TestHandleCMP_GenM_UnknownInfoType(t *testing.T) {
	router, _, svc := newOptionsRouter(t, models.EnrollmentOptionsLWCRFC9483{})

	unknownOID := asn1.ObjectIdentifier{1, 2, 3, 4, 5, 6, 7}
	msgDER := buildTestGenM(t, randomTxID(t), buildTestITAV(t, unknownOID, nil))

	resp := postCMP(t, router, "test-dms", msgDER)
	require.Equal(t, http.StatusOK, resp.Code)
	assert.Equal(t, corecmp.BodyTagError, parseCMPResponseTag(t, resp.Body.Bytes()),
		"an unknown genm InfoType must be rejected with a CMP error body")

	svc.AssertExpectations(t)
}

// TestHandleCMP_EEError covers an error (23) body sent BY the EE to abandon a
// transaction (RFC 4210 §5.3.21). It is a legitimate message, so the server
// acknowledges with pkiConf — before this it fell through the dispatch default
// and was answered with "unsupported body tag 23", i.e. an error about an error.
func TestHandleCMP_EEError(t *testing.T) {
	router, _, _ := newOptionsRouter(t, models.EnrollmentOptionsLWCRFC9483{})

	statusInfo := seqDER(t, mustMarshal(t, 2), mustMarshal(t, asn1.BitString{Bytes: []byte{0x04}, BitLength: 6}))
	errBody := ctxDER(t, corecmp.BodyTagError, seqDER(t, statusInfo))
	headerDER := buildTestPKIHeaderDER(t, randomTxID(t), randomNonce(t), nil, false)
	msgDER, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true,
		Bytes: concatBytes(headerDER, errBody),
	})
	require.NoError(t, err)

	resp := postCMP(t, router, "test-dms", msgDER)
	require.Equal(t, http.StatusOK, resp.Code)
	assert.Equal(t, corecmp.BodyTagPKIConf, parseCMPResponseTag(t, resp.Body.Bytes()),
		"an EE-sent error message must be acknowledged with pkiConf, not rejected")
}

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	der, err := asn1.Marshal(v)
	require.NoError(t, err)
	return der
}
