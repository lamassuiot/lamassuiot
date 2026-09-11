package cmp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"net/http"
	"testing"
	"time"

	corecmp "github.com/lamassuiot/lamassuiot/core/v3/pkg/cmp"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Cross-certification (ccr / ccp) — RFC 4210bis §5.3.11
// ---------------------------------------------------------------------------

// buildCCRCATestCert mints a self-signed CA certificate with a SubjectKeyId, as
// required for a ccr requester: CCR.RequireCACertificate demands signer.IsCA,
// and signature-based protection demands senderKID == SKI.
func buildCCRCATestCert(t *testing.T, cn string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	pubKeyDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)
	skiHash := sha256.Sum256(pubKeyDER)

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(4210),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          skiHash[:20],
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert, key
}

// buildCCRCertTemplateDER encodes a CertTemplate carrying every field
// validateCrossCertTemplate requires (RFC 4210bis App. D.6): version [0],
// signingAlg [2], issuer [3], validity [4], subject [5] and publicKey [6].
func buildCCRCertTemplateDER(t *testing.T, cn string, pubKeyDER []byte) []byte {
	t.Helper()

	// version [0] — v3 (encoded as 2).
	versionField := func() []byte {
		v, err := asn1.Marshal(2)
		require.NoError(t, err)
		var raw asn1.RawValue
		_, err = asn1.Unmarshal(v, &raw)
		require.NoError(t, err)
		der, err := asn1.Marshal(asn1.RawValue{
			Class: asn1.ClassContextSpecific,
			Tag:   0,
			Bytes: raw.Bytes,
		})
		require.NoError(t, err)
		return der
	}()

	// signingAlg [2] — ecdsaWithSHA256, IMPLICIT over AlgorithmIdentifier.
	signingAlgField := func() []byte {
		oid, err := asn1.Marshal(asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2})
		require.NoError(t, err)
		return ctxDER(t, 2, oid)
	}()

	issuerField := ctxDER(t, 3, buildSubjectCN(t, "issuing-ca"))

	// validity [4] OptionalValidity ::= SEQUENCE {
	//   notBefore [0] Time OPTIONAL, notAfter [1] Time OPTIONAL }
	validityField := func() []byte {
		mkTime := func(tag int, ts time.Time) []byte {
			gt, err := asn1.Marshal(ts.UTC())
			require.NoError(t, err)
			der, err := asn1.Marshal(asn1.RawValue{
				Class:      asn1.ClassContextSpecific,
				Tag:        tag,
				IsCompound: true,
				Bytes:      gt,
			})
			require.NoError(t, err)
			return der
		}
		return ctxDER(t, 4,
			mkTime(0, time.Now().Add(-time.Hour)),
			mkTime(1, time.Now().Add(24*time.Hour)),
		)
	}()

	subjectField := ctxDER(t, 5, buildSubjectCN(t, cn))

	// [6] carries the CONTENT of the SubjectPublicKeyInfo SEQUENCE (no outer tag).
	var spkiRaw asn1.RawValue
	_, err := asn1.Unmarshal(pubKeyDER, &spkiRaw)
	require.NoError(t, err)
	pubKeyField := ctxDER(t, 6, spkiRaw.Bytes)

	return seqDER(t, versionField, signingAlgField, issuerField, validityField, subjectField, pubKeyField)
}

// buildTestCCR builds a complete signature-protected ccr PKIMessage. popoMode
// follows buildTestIRBodyDERWithPOPO's vocabulary ("signature", "badsig", "").
func buildTestCCR(t *testing.T, cn string, popoMode string, signerCert *x509.Certificate, signerKey *ecdsa.PrivateKey) []byte {
	t.Helper()

	subjectKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	pubKeyDER, err := x509.MarshalPKIXPublicKey(&subjectKey.PublicKey)
	require.NoError(t, err)

	certReqIDDER, err := asn1.Marshal(0)
	require.NoError(t, err)
	certRequestDER := seqDER(t, certReqIDDER, buildCCRCertTemplateDER(t, cn, pubKeyDER))

	var popo [][]byte
	switch popoMode {
	case "signature":
		popo = append(popo, buildPOPOSigningKey(t, certRequestDER, subjectKey, false))
	case "badsig":
		popo = append(popo, buildPOPOSigningKey(t, certRequestDER, subjectKey, true))
	case "":
		// no POPO
	default:
		t.Fatalf("unknown popoMode %q", popoMode)
	}

	bodyDER := ctxDER(t, corecmp.BodyTagCCR, wrapCertReqMsgs(t, certRequestDER, popo...))
	headerDER := buildTestPKIHeaderDER(t, randomTxID(t), randomNonce(t), nil, false)

	msgDER, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      concatBytes(headerDER, bodyDER),
	})
	require.NoError(t, err)

	return signCMPMessage(t, msgDER, signerCert, signerKey)
}

// ccrTestOptions enables ccr with POPO required. CCR defaults OFF (RFC011
// treats cross-certification as privileged), so it must be turned on explicitly.
func ccrTestOptions() models.CMPEnrollmentSettings {
	opts := models.CMPEnrollmentSettings{}
	opts.CCR.Enabled = true
	opts.CCR.RequireCACertificate = true
	opts.CCR.RequireProofOfPossession = true
	return opts
}

// TestHandleCMP_CCR_InvalidPOPOSignatureRejected is the regression test for a
// ccr whose POPOSigningKey carries a structurally valid but cryptographically
// wrong signature.
//
// handleCrossCertification used to check only that the POPO container was
// tagged [1] (signature) and never verified the signature bytes against the
// CertTemplate's declared public key — unlike the ir/cr and p10cr paths, which
// both verify for real. Nothing downstream caught it either, because
// BuildSyntheticCSR fills the synthesized CSR's signature with a dummy value.
// A requesting CA could therefore cross-certify a public key it does not
// actually control the private key for, which is precisely the property
// proof-of-possession exists to establish.
func TestHandleCMP_CCR_InvalidPOPOSignatureRejected(t *testing.T) {
	caCert, caKey := buildCCRCATestCert(t, "requesting-ca")
	router, _, _ := newOptionsRouter(t, ccrTestOptions())

	ccrDER := buildTestCCR(t, "cross-subject", "badsig", caCert, caKey)
	resp := postCMP(t, router, "test-dms", ccrDER)

	require.Equal(t, http.StatusOK, resp.Code)
	bs := parseFailInfoBitString(t, resp.Body.Bytes())
	assert.True(t, bitSet(bs, corecmp.PKIFailureInfoBadPOP),
		"a ccr with an invalid POPOSigningKey signature must be rejected with badPOP (9)")
}

// TestHandleCMP_CCR_ValidPOPOSignatureAccepted is the negative control for the
// test above: it proves the badPOP rejection is caused by the bad signature
// specifically, not by some unrelated part of the ccr fixture.
//
// With a valid POPO the request clears the proof-of-possession gate and reaches
// the LightweightCMPCrossCertifier type assertion, which the base test mock
// does not implement — so the expected outcome is systemFailure ("cross-
// certification not supported"), NOT badPOP.
func TestHandleCMP_CCR_ValidPOPOSignatureAccepted(t *testing.T) {
	caCert, caKey := buildCCRCATestCert(t, "requesting-ca")
	router, _, _ := newOptionsRouter(t, ccrTestOptions())

	ccrDER := buildTestCCR(t, "cross-subject", "signature", caCert, caKey)
	resp := postCMP(t, router, "test-dms", ccrDER)

	require.Equal(t, http.StatusOK, resp.Code)
	bs := parseFailInfoBitString(t, resp.Body.Bytes())
	assert.False(t, bitSet(bs, corecmp.PKIFailureInfoBadPOP),
		"a ccr with a valid POPOSigningKey signature must clear the POPO gate")
	assert.True(t, bitSet(bs, corecmp.PKIFailureInfoSystemFailure),
		"the base test mock implements no cross-certifier, so the request should fall through to systemFailure")
}

// TestHandleCMP_CCR_AbsentPOPORejected pins the pre-existing presence check that
// the signature verification above sits alongside.
func TestHandleCMP_CCR_AbsentPOPORejected(t *testing.T) {
	caCert, caKey := buildCCRCATestCert(t, "requesting-ca")
	router, _, _ := newOptionsRouter(t, ccrTestOptions())

	ccrDER := buildTestCCR(t, "cross-subject", "", caCert, caKey)
	resp := postCMP(t, router, "test-dms", ccrDER)

	require.Equal(t, http.StatusOK, resp.Code)
	bs := parseFailInfoBitString(t, resp.Body.Bytes())
	assert.True(t, bitSet(bs, corecmp.PKIFailureInfoBadPOP),
		"a ccr with no POPO must be rejected with badPOP when CCR.RequireProofOfPossession is set")
}
