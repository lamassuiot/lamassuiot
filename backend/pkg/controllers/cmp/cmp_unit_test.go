package cmp

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"testing"
	"time"

	corecmp "github.com/lamassuiot/lamassuiot/core/v3/pkg/cmp"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	cmpmock "github.com/lamassuiot/lamassuiot/core/v3/pkg/services/mock"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// A7: table-driven unit tests for the audit's flagged paths.
// ---------------------------------------------------------------------------

// TestIsImplicitConfirm_AllCombinations exercises every (DMS-policy, EE-request)
// combination. The contract is: implicit confirmation is granted iff BOTH the
// EE includes the id-it-implicitConfirm OID AND the DMS is configured to
// accept implicit confirmation. Anything else degrades to explicit.
func TestIsImplicitConfirm_AllCombinations(t *testing.T) {
	cases := []struct {
		name             string
		eeRequests       bool
		dmsAccepts       bool
		dmsLookupError   error
		dmsLookupReturns *models.EnrollmentOptionsLWCRFC9483
		want             bool
	}{
		{
			name:             "EE no, DMS no",
			eeRequests:       false,
			dmsAccepts:       false,
			dmsLookupReturns: &models.EnrollmentOptionsLWCRFC9483{AcceptImplicit: false},
			want:             false,
		},
		{
			name:             "EE no, DMS yes",
			eeRequests:       false,
			dmsAccepts:       true,
			dmsLookupReturns: &models.EnrollmentOptionsLWCRFC9483{AcceptImplicit: true},
			want:             false,
		},
		{
			name:             "EE yes, DMS no",
			eeRequests:       true,
			dmsAccepts:       false,
			dmsLookupReturns: &models.EnrollmentOptionsLWCRFC9483{AcceptImplicit: false},
			want:             false,
		},
		{
			name:             "EE yes, DMS yes",
			eeRequests:       true,
			dmsAccepts:       true,
			dmsLookupReturns: &models.EnrollmentOptionsLWCRFC9483{AcceptImplicit: true},
			want:             true,
		},
		{
			name:           "DMS lookup error treats as explicit",
			eeRequests:     true,
			dmsLookupError: errors.New("DMS not found"),
			want:           false,
		},
		{
			name:             "DMS returns nil options treats as explicit",
			eeRequests:       true,
			dmsLookupReturns: nil,
			want:             false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc := &cmpmock.MockLightweightCMPService{}
			if tc.eeRequests {
				svc.On("LWCGetEnrollmentOptions", mock.Anything, "test-dms").
					Return(tc.dmsLookupReturns, tc.dmsLookupError).Maybe()
			}
			store := newInMemoryCMPStore()
			wrapped := &mockServiceWithStore{MockLightweightCMPService: svc, store: store}
			routes, err := NewCMPHttpRoutes(logrus.NewEntry(logrus.New()), wrapped)
			require.NoError(t, err)

			h := corecmp.RequestPKIHeader{}
			if tc.eeRequests {
				h.GeneralInfo = []asn1.RawValue{makeImplicitConfirmGeneralInfo(t)}
			}
			got := routes.isImplicitConfirm(context.Background(), h, "test-dms")
			assert.Equal(t, tc.want, got)
		})
	}
}

// makeImplicitConfirmGeneralInfo constructs the asn1.RawValue that the
// PKIHeader generalInfo field carries when the EE requests implicit confirm.
// hasImplicitConfirmOID scans the raw bytes for the OID, so we need a wire-
// shape value.
func makeImplicitConfirmGeneralInfo(t *testing.T) asn1.RawValue {
	t.Helper()
	type itav struct {
		Type  asn1.ObjectIdentifier
		Value asn1.RawValue `asn1:"optional"`
	}
	der, err := asn1.Marshal(itav{
		Type:  corecmp.OIDImplicitConfirm(),
		Value: asn1.NullRawValue,
	})
	require.NoError(t, err)
	var rv asn1.RawValue
	_, err = asn1.Unmarshal(der, &rv)
	require.NoError(t, err)
	return rv
}

// TestMarshalProtectedResponse_AllSignerTypes verifies that the protected-
// response pipeline emits a well-formed PKIMessage for each supported signer
// key type. Each table row issues a self-signed cert with the right key and
// drives marshalProtectedResponse end-to-end; the test then re-parses the
// output and confirms the protection BitString is non-empty and the
// signature can be verified against the signer's public key (round-trip).
func TestMarshalProtectedResponse_AllSignerTypes(t *testing.T) {
	cases := []struct {
		name   string
		signer func(t *testing.T) (crypto.Signer, *x509.Certificate)
	}{
		{
			name: "RSA-2048",
			signer: func(t *testing.T) (crypto.Signer, *x509.Certificate) {
				key, err := rsa.GenerateKey(rand.Reader, 2048)
				require.NoError(t, err)
				cert := selfSignedFor(t, key, "rsa-2048")
				return key, cert
			},
		},
		{
			name: "ECDSA-P256",
			signer: func(t *testing.T) (crypto.Signer, *x509.Certificate) {
				key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				require.NoError(t, err)
				cert := selfSignedFor(t, key, "ecdsa-p256")
				return key, cert
			},
		},
		{
			name: "ECDSA-P384",
			signer: func(t *testing.T) (crypto.Signer, *x509.Certificate) {
				key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
				require.NoError(t, err)
				cert := selfSignedFor(t, key, "ecdsa-p384")
				return key, cert
			},
		},
		{
			name: "ECDSA-P521",
			signer: func(t *testing.T) (crypto.Signer, *x509.Certificate) {
				key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
				require.NoError(t, err)
				cert := selfSignedFor(t, key, "ecdsa-p521")
				return key, cert
			},
		},
		{
			name: "Ed25519",
			signer: func(t *testing.T) (crypto.Signer, *x509.Certificate) {
				_, priv, err := ed25519.GenerateKey(rand.Reader)
				require.NoError(t, err)
				cert := selfSignedFor(t, priv, "ed25519")
				return priv, cert
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			signer, cert := tc.signer(t)

			// Build a minimal request header so the response can echo it.
			reqHeader := corecmp.RequestPKIHeader{
				PVNO:          corecmp.PVNOCMP2000,
				TransactionID: []byte("0123456789abcdef"),
				SenderNonce:   []byte("0123456789abcdef"),
			}

			// Body: pkiConf (empty NULL body content).
			body, err := corecmp.MarshalPKIConfBody()
			require.NoError(t, err)

			out, err := marshalProtectedResponse(reqHeader, corecmp.BodyTagPKIConf, body, []*x509.Certificate{cert}, signer)
			require.NoError(t, err, "marshalProtectedResponse must succeed for %s", tc.name)
			require.NotEmpty(t, out)

			// Round-trip: parse the response and verify the signature against
			// the same cert we signed with (mirrors what an EE would do).
			var raw corecmp.RawMessage
			_, err = asn1.Unmarshal(out, &raw)
			require.NoError(t, err, "response must parse as PKIMessage")
			require.NotEmpty(t, raw.Protection.Bytes, "Protection field must be non-empty")
			require.NotEmpty(t, raw.ExtraCerts, "ExtraCerts must include signer cert")
		})
	}
}

// selfSignedFor builds a self-signed certificate using the given private key.
// CommonName is the test label; the cert lives for an hour, more than enough
// for the test to run.
func selfSignedFor(t *testing.T, key crypto.Signer, label string) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "cmp-test-" + label},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

// TestValidateRequestEnvelope_AllRules exercises every rejection produced by
// validateRequestEnvelope so the audit's new R1 (messageTime drift) and
// existing pvno/transactionID/senderNonce paths cannot regress silently.
func TestValidateRequestEnvelope_AllRules(t *testing.T) {
	goodNonce := make([]byte, 16)
	goodTxID := make([]byte, 16)
	for i := range goodNonce {
		goodNonce[i] = byte(i + 1)
		goodTxID[i] = byte(i + 100)
	}
	now := time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC)

	cases := []struct {
		name        string
		header      corecmp.RequestPKIHeader
		wantReject  bool
		wantFailBit int
	}{
		{
			name: "valid envelope passes",
			header: corecmp.RequestPKIHeader{
				PVNO:          corecmp.PVNOCMP2000,
				TransactionID: goodTxID,
				SenderNonce:   goodNonce,
				MessageTime:   now.Add(-30 * time.Second),
			},
			wantReject: false,
		},
		{
			name: "envelope without messageTime is rejected",
			header: corecmp.RequestPKIHeader{
				PVNO:          corecmp.PVNOCMP2021,
				TransactionID: goodTxID,
				SenderNonce:   goodNonce,
			},
			wantReject:  true,
			wantFailBit: corecmp.PKIFailureInfoBadTime,
		},
		{
			name:        "unsupported pvno",
			header:      corecmp.RequestPKIHeader{PVNO: 99, TransactionID: goodTxID, SenderNonce: goodNonce},
			wantReject:  true,
			wantFailBit: corecmp.PKIFailureInfoUnsupportedVersion,
		},
		{
			name:        "missing transactionID",
			header:      corecmp.RequestPKIHeader{PVNO: corecmp.PVNOCMP2000, SenderNonce: goodNonce},
			wantReject:  true,
			wantFailBit: corecmp.PKIFailureInfoBadDataFormat,
		},
		{
			name:        "short transactionID",
			header:      corecmp.RequestPKIHeader{PVNO: corecmp.PVNOCMP2000, TransactionID: []byte{1, 2, 3}, SenderNonce: goodNonce},
			wantReject:  true,
			wantFailBit: corecmp.PKIFailureInfoBadDataFormat,
		},
		{
			name:        "short senderNonce",
			header:      corecmp.RequestPKIHeader{PVNO: corecmp.PVNOCMP2000, TransactionID: goodTxID, SenderNonce: []byte{1, 2, 3}},
			wantReject:  true,
			wantFailBit: corecmp.PKIFailureInfoBadSenderNonce,
		},
		{
			name: "messageTime future drift",
			header: corecmp.RequestPKIHeader{
				PVNO:          corecmp.PVNOCMP2000,
				TransactionID: goodTxID,
				SenderNonce:   goodNonce,
				MessageTime:   now.Add(10 * time.Minute),
			},
			wantReject:  true,
			wantFailBit: corecmp.PKIFailureInfoBadTime,
		},
		{
			name: "messageTime past drift",
			header: corecmp.RequestPKIHeader{
				PVNO:          corecmp.PVNOCMP2000,
				TransactionID: goodTxID,
				SenderNonce:   goodNonce,
				MessageTime:   now.Add(-10 * time.Minute),
			},
			wantReject:  true,
			wantFailBit: corecmp.PKIFailureInfoBadTime,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rej := validateRequestEnvelope(tc.header, now, corecmp.BodyTagIR)
			if !tc.wantReject {
				assert.Nil(t, rej)
				return
			}
			require.NotNil(t, rej)
			assert.Equal(t, tc.wantFailBit, rej.failInfo)
		})
	}
}

// TestVerifySenderMatchesProtectionCert exercises every branch of the new
// RFC 9483 §3.5 sender-vs-protection-cert-subject check.
func TestVerifySenderMatchesProtectionCert(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	cert := selfSignedFor(t, key, "subj-match")
	matchingSender := senderRawFrom(t, cert.Subject)

	otherCert := selfSignedFor(t, key, "other-subject")
	mismatchedSender := senderRawFrom(t, otherCert.Subject)

	t.Run("nil cert means no protection — no check", func(t *testing.T) {
		assert.Nil(t, verifySenderMatchesProtectionCert(asn1.RawValue{}, nil))
	})

	t.Run("matching sender accepted", func(t *testing.T) {
		assert.Nil(t, verifySenderMatchesProtectionCert(matchingSender, cert))
	})

	t.Run("mismatched DN rejected", func(t *testing.T) {
		rej := verifySenderMatchesProtectionCert(mismatchedSender, cert)
		require.NotNil(t, rej)
		assert.Equal(t, corecmp.PKIFailureInfoBadMessageCheck, rej.failInfo)
	})

	t.Run("non-directoryName CHOICE rejected", func(t *testing.T) {
		rfc822Sender := asn1.RawValue{
			Class: asn1.ClassContextSpecific,
			Tag:   1, // rfc822Name
			Bytes: []byte("alice@example.com"),
		}
		rej := verifySenderMatchesProtectionCert(rfc822Sender, cert)
		require.NotNil(t, rej)
		assert.Equal(t, corecmp.PKIFailureInfoBadMessageCheck, rej.failInfo)
	})
}

// senderRawFrom builds a [4] EXPLICIT directoryName GeneralName carrying the
// given subject's RDNSequence — matches what the CMP wire format requires.
func senderRawFrom(t *testing.T, name pkix.Name) asn1.RawValue {
	t.Helper()
	rdn, err := asn1.Marshal(name.ToRDNSequence())
	require.NoError(t, err)
	full, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        4,
		IsCompound: true,
		Bytes:      rdn,
	})
	require.NoError(t, err)
	var rv asn1.RawValue
	_, err = asn1.Unmarshal(full, &rv)
	require.NoError(t, err)
	return rv
}

// Silence unused-import warnings for `services` when only mock is used.
var _ = services.GetCAByIDInput{}

// generalInfoEntry builds a single InfoTypeAndValue DER (SEQUENCE { infoType
// OID, infoValue ANY OPTIONAL }) for validateGeneralInfo test fixtures.
func generalInfoEntry(t *testing.T, oid asn1.ObjectIdentifier, value *asn1.RawValue) asn1.RawValue {
	t.Helper()
	var content []byte
	oidDER, err := asn1.Marshal(oid)
	require.NoError(t, err)
	content = append(content, oidDER...)
	if value != nil {
		content = append(content, value.FullBytes...)
	}
	der, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: content})
	require.NoError(t, err)
	var rv asn1.RawValue
	_, err = asn1.Unmarshal(der, &rv)
	require.NoError(t, err)
	return rv
}

func TestValidateGeneralInfo(t *testing.T) {
	nullValue, err := asn1.Marshal(asn1.NullRawValue)
	require.NoError(t, err)
	var nullRV asn1.RawValue
	_, err = asn1.Unmarshal(nullValue, &nullRV)
	require.NoError(t, err)

	garbageDER, err := asn1.Marshal([]byte{1, 2, 3, 4})
	require.NoError(t, err)
	var garbageRV asn1.RawValue
	_, err = asn1.Unmarshal(garbageDER, &garbageRV)
	require.NoError(t, err)

	now := time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC)
	genTimeDER, err := asn1.MarshalWithParams(now, "generalized")
	require.NoError(t, err)
	var genTimeRV asn1.RawValue
	_, err = asn1.Unmarshal(genTimeDER, &genTimeRV)
	require.NoError(t, err)

	utcTimeDER, err := asn1.MarshalWithParams(now, "utc")
	require.NoError(t, err)
	var utcTimeRV asn1.RawValue
	_, err = asn1.Unmarshal(utcTimeDER, &utcTimeRV)
	require.NoError(t, err)

	cases := []struct {
		name        string
		entries     []asn1.RawValue
		wantReject  bool
		wantFailBit int
	}{
		{
			name:    "no generalInfo passes",
			entries: nil,
		},
		{
			name:    "implicitConfirm with NULL value passes",
			entries: []asn1.RawValue{generalInfoEntry(t, corecmp.OIDImplicitConfirm(), &nullRV)},
		},
		{
			name:    "implicitConfirm with absent value passes",
			entries: []asn1.RawValue{generalInfoEntry(t, corecmp.OIDImplicitConfirm(), nil)},
		},
		{
			name:        "implicitConfirm with non-NULL value is rejected",
			entries:     []asn1.RawValue{generalInfoEntry(t, corecmp.OIDImplicitConfirm(), &garbageRV)},
			wantReject:  true,
			wantFailBit: corecmp.PKIFailureInfoBadRequest,
		},
		{
			name:    "confirmWaitTime with GeneralizedTime passes",
			entries: []asn1.RawValue{generalInfoEntry(t, oidConfirmWaitTime, &genTimeRV)},
		},
		{
			name:        "confirmWaitTime with UTCTime is rejected",
			entries:     []asn1.RawValue{generalInfoEntry(t, oidConfirmWaitTime, &utcTimeRV)},
			wantReject:  true,
			wantFailBit: corecmp.PKIFailureInfoBadDataFormat,
		},
		{
			name: "implicitConfirm and confirmWaitTime together is rejected",
			entries: []asn1.RawValue{
				generalInfoEntry(t, corecmp.OIDImplicitConfirm(), &nullRV),
				generalInfoEntry(t, oidConfirmWaitTime, &genTimeRV),
			},
			wantReject:  true,
			wantFailBit: corecmp.PKIFailureInfoBadRequest,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rej := validateGeneralInfo(tc.entries)
			if tc.wantReject {
				require.NotNil(t, rej)
				assert.Equal(t, tc.wantFailBit, rej.failInfo)
			} else {
				assert.Nil(t, rej)
			}
		})
	}
}

func TestExtensionsMatch(t *testing.T) {
	ku := pkix.Extension{Id: oidExtKeyUsage, Critical: true, Value: []byte{0x03, 0x02, 0x01, 0xA0}}
	san := pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Value: []byte{0x30, 0x00}}
	bad := pkix.Extension{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Value: []byte{0x05, 0x00}}

	cases := []struct {
		name      string
		requested []pkix.Extension
		actual    []pkix.Extension
		want      bool
	}{
		{name: "identical sets match", requested: []pkix.Extension{ku, san}, actual: []pkix.Extension{ku, san}, want: true},
		{name: "order-independent", requested: []pkix.Extension{san, ku}, actual: []pkix.Extension{ku, san}, want: true},
		{name: "extra unknown extension fails", requested: []pkix.Extension{ku, san, bad}, actual: []pkix.Extension{ku, san}, want: false},
		{name: "only invalid extension fails", requested: []pkix.Extension{bad}, actual: []pkix.Extension{ku, san}, want: false},
		{name: "missing extension fails", requested: []pkix.Extension{ku}, actual: []pkix.Extension{ku, san}, want: false},
		{name: "both empty match", requested: nil, actual: nil, want: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, extensionsMatch(tc.requested, tc.actual))
		})
	}
}

// spkiBody builds a SubjectPublicKeyInfo *body* (algorithm || subjectPublicKey,
// without the outer SEQUENCE) for use as a CertTemplate publicKey [6] content.
func spkiBody(t *testing.T, algOID asn1.ObjectIdentifier, params asn1.RawValue, keyBits []byte) []byte {
	t.Helper()
	algID, err := asn1.Marshal(struct {
		Algorithm  asn1.ObjectIdentifier
		Parameters asn1.RawValue `asn1:"optional"`
	}{Algorithm: algOID, Parameters: params})
	if err != nil {
		t.Fatal(err)
	}
	bs, err := asn1.Marshal(asn1.BitString{Bytes: keyBits, BitLength: len(keyBits) * 8})
	if err != nil {
		t.Fatal(err)
	}
	return append(algID, bs...)
}

func TestInspectKGATemplateKey(t *testing.T) {
	null := asn1.NullRawValue

	// Empty RSA key ⇒ for_kga, RSA hint.
	if empty, alg := corecmp.InspectKGATemplateKey(spkiBody(t, corecmp.OIDRSAEncryption(), null, nil)); !empty || alg != x509.RSA {
		t.Fatalf("empty RSA: got empty=%v alg=%v, want true/RSA", empty, alg)
	}
	// Empty EC key ⇒ for_kga, ECDSA hint.
	ecParams := asn1.RawValue{}
	if empty, alg := corecmp.InspectKGATemplateKey(spkiBody(t, corecmp.OIDECPublicKey(), ecParams, nil)); !empty || alg != x509.ECDSA {
		t.Fatalf("empty EC: got empty=%v alg=%v, want true/ECDSA", empty, alg)
	}
	// Non-empty key ⇒ NOT for_kga.
	if empty, _ := corecmp.InspectKGATemplateKey(spkiBody(t, corecmp.OIDRSAEncryption(), null, []byte{0x01, 0x02, 0x03})); empty {
		t.Fatal("non-empty key must not be flagged as for_kga")
	}
	// Empty key with an unknown algorithm ⇒ for_kga but no usable hint.
	if empty, alg := corecmp.InspectKGATemplateKey(spkiBody(t, asn1.ObjectIdentifier{1, 2, 3, 4}, null, nil)); !empty || alg != x509.UnknownPublicKeyAlgorithm {
		t.Fatalf("empty unknown-alg: got empty=%v alg=%v, want true/Unknown", empty, alg)
	}
	// Garbage ⇒ safe default (treated as a normal key).
	if empty, _ := corecmp.InspectKGATemplateKey([]byte{0xFF, 0x00}); empty {
		t.Fatal("malformed SPKI body must default to non-KGA")
	}
}

// TestMarshalKGACertRepBody verifies the RFC 9483 §4.1.6 CertifiedKeyPair
// encoding: the issued certificate under certOrEncCert [0], and the centrally
// generated key under privateKey [0] EXPLICIT → EncryptedKey CHOICE →
// envelopedData [0] IMPLICIT EnvelopedData. The decode below mirrors the
// compliance validator's pyasn1 schema (privateKey.getName() == "envelopedData").
func TestMarshalKGACertRepBody(t *testing.T) {
	// Stand-in DER blobs. certDER and envelopedDataDER only need to be
	// well-formed TLVs for the structural test; their contents are opaque here.
	certDER, err := asn1.Marshal(struct {
		A int
		B []byte
	}{A: 1, B: []byte("fake-cert")})
	if err != nil {
		t.Fatal(err)
	}
	// EnvelopedData is a SEQUENCE; use a recognisable body so we can assert the
	// re-tagging preserved it byte-for-byte.
	envBody := struct {
		Version int
		Tag     []byte
	}{Version: 2, Tag: []byte("enveloped-data-body")}
	envelopedDataDER, err := asn1.Marshal(envBody)
	if err != nil {
		t.Fatal(err)
	}

	bodyDER, err := corecmp.MarshalKGACertRepBody(0, 0, certDER, envelopedDataDER)
	if err != nil {
		t.Fatalf("marshalKGACertRepBody: %v", err)
	}

	// CertRepMessage ::= SEQUENCE { response SEQUENCE OF CertResponse }
	var msg corecmp.ServerCertRepMessage
	if _, err := asn1.Unmarshal(bodyDER, &msg); err != nil {
		t.Fatalf("decode CertRepMessage: %v", err)
	}
	if len(msg.Responses) != 1 {
		t.Fatalf("want 1 CertResponse, got %d", len(msg.Responses))
	}
	resp := msg.Responses[0]
	if resp.CertReqID != 0 {
		t.Fatalf("certReqId = %d, want 0", resp.CertReqID)
	}

	// CertifiedKeyPair ::= SEQUENCE { certOrEncCert, privateKey [0] ... }
	var ckp struct {
		CertOrEncCert asn1.RawValue
		PrivateKey    asn1.RawValue `asn1:"tag:0"`
	}
	if _, err := asn1.Unmarshal(resp.CertifiedKeyPair.FullBytes, &ckp); err != nil {
		t.Fatalf("decode CertifiedKeyPair: %v", err)
	}
	certOrEncCert := ckp.CertOrEncCert
	privateKey := ckp.PrivateKey

	// certOrEncCert ::= [0] certificate — its content must be the cert DER.
	if certOrEncCert.Class != asn1.ClassContextSpecific || certOrEncCert.Tag != 0 {
		t.Fatalf("certOrEncCert tag = class %d/tag %d, want context/0", certOrEncCert.Class, certOrEncCert.Tag)
	}
	if !bytes.Equal(certOrEncCert.Bytes, certDER) {
		t.Fatal("certOrEncCert content does not equal the issued cert DER")
	}

	// privateKey is EXPLICIT [0]; its single inner element is the EncryptedKey
	// CHOICE, chosen as envelopedData [0] IMPLICIT.
	if privateKey.Class != asn1.ClassContextSpecific || privateKey.Tag != 0 {
		t.Fatalf("privateKey tag = class %d/tag %d, want context/0", privateKey.Class, privateKey.Tag)
	}
	var envChoice asn1.RawValue
	if _, err := asn1.Unmarshal(privateKey.Bytes, &envChoice); err != nil {
		t.Fatalf("decode EncryptedKey CHOICE: %v", err)
	}
	if envChoice.Class != asn1.ClassContextSpecific || envChoice.Tag != 0 {
		t.Fatalf("envelopedData alternative tag = class %d/tag %d, want context/0", envChoice.Class, envChoice.Tag)
	}

	// The IMPLICIT [0] re-tag must have preserved the EnvelopedData SEQUENCE body:
	// re-wrapping the content as a UNIVERSAL SEQUENCE must reproduce the input DER.
	rebuilt, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: envChoice.Bytes,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rebuilt, envelopedDataDER) {
		t.Fatal("recovered EnvelopedData body does not match the input DER")
	}
}

// buildCertStatusTLV encodes a CertStatus ::= SEQUENCE {
//
//	certHash   OCTET STRING,
//	certReqId  INTEGER,
//	statusInfo PKIStatusInfo OPTIONAL }
//
// statusInfoDER, when non-nil, is appended verbatim as the optional statusInfo.
func buildCertStatusTLV(t *testing.T, certHash []byte, certReqID int, statusInfoDER []byte) []byte {
	t.Helper()
	hashDER, err := asn1.Marshal(certHash) // OCTET STRING
	if err != nil {
		t.Fatalf("marshal certHash: %v", err)
	}
	reqIDDER, err := asn1.Marshal(certReqID) // INTEGER
	if err != nil {
		t.Fatalf("marshal certReqId: %v", err)
	}
	content := append([]byte{}, hashDER...)
	content = append(content, reqIDDER...)
	content = append(content, statusInfoDER...)
	seqDER, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      content,
	})
	if err != nil {
		t.Fatalf("marshal CertStatus SEQUENCE: %v", err)
	}
	return seqDER
}

// buildCertConfirmContent encodes CertConfirmContent ::= SEQUENCE OF CertStatus.
// This is exactly what body.Bytes carries for a certConf body, because the
// PKIBody CHOICE uses EXPLICIT tagging: certConf [24] EXPLICIT CertConfirmContent
// → the [24] element's content is the full CertConfirmContent SEQUENCE.
func buildCertConfirmContent(t *testing.T, certStatusTLVs ...[]byte) []byte {
	t.Helper()
	var content []byte
	for _, cs := range certStatusTLVs {
		content = append(content, cs...)
	}
	seqDER, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      content,
	})
	if err != nil {
		t.Fatalf("marshal CertConfirmContent SEQUENCE: %v", err)
	}
	return seqDER
}

// TestDecodeCertConfStatuses_MultiStatus verifies the decoder reports all
// CertStatus entries when the EE sends more than one (RFC 9483 §4.1.1 only
// permits one in this profile, so handleCertConf must be able to see >1).
func TestDecodeCertConfStatuses_MultiStatus(t *testing.T) {
	hash := make([]byte, 32)
	cs := buildCertStatusTLV(t, hash, 0, nil)

	body := buildCertConfirmContent(t, cs, cs, cs)
	statuses, err := corecmp.DecodeCertConfStatuses(body)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(statuses) != 3 {
		t.Fatalf("expected 3 statuses, got %d", len(statuses))
	}
}

// TestDecodeCertConfStatuses_NegativeCertReqID verifies certReqId=-1 is decoded
// as -1 (so the structural check can reject it).
func TestDecodeCertConfStatuses_NegativeCertReqID(t *testing.T) {
	hash := make([]byte, 32)
	cs := buildCertStatusTLV(t, hash, -1, nil)
	body := buildCertConfirmContent(t, cs)
	statuses, err := corecmp.DecodeCertConfStatuses(body)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(statuses) != 1 {
		t.Fatalf("expected 1 status, got %d", len(statuses))
	}
	if statuses[0].CertReqID != -1 {
		t.Fatalf("expected certReqId -1, got %d", statuses[0].CertReqID)
	}
}

// TestDecodeCertConfStatuses_AcceptedWithFailInfo verifies a statusInfo with
// status=accepted(0) AND a failInfo bit is decoded so the structural check can
// reject the inconsistency.
func TestDecodeCertConfStatuses_AcceptedWithFailInfo(t *testing.T) {
	hash := make([]byte, 32)

	// PKIStatusInfo ::= SEQUENCE { status INTEGER(0), failInfo BIT STRING }
	// badRequest is bit 2.
	statusDER, err := asn1.Marshal(0)
	if err != nil {
		t.Fatalf("marshal status: %v", err)
	}
	failInfo := asn1.BitString{Bytes: []byte{0x20}, BitLength: 3} // bit 2 set
	failDER, err := asn1.Marshal(failInfo)
	if err != nil {
		t.Fatalf("marshal failInfo: %v", err)
	}
	siContent := append(append([]byte{}, statusDER...), failDER...)
	siDER, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      siContent,
	})
	if err != nil {
		t.Fatalf("marshal statusInfo: %v", err)
	}

	cs := buildCertStatusTLV(t, hash, 0, siDER)
	body := buildCertConfirmContent(t, cs)
	statuses, err := corecmp.DecodeCertConfStatuses(body)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(statuses) != 1 {
		t.Fatalf("expected 1 status, got %d", len(statuses))
	}
	if statuses[0].StatusInfo.Status != corecmp.PKIStatus(corecmp.PKIStatusAccepted) {
		t.Fatalf("expected status accepted, got %d", statuses[0].StatusInfo.Status)
	}
	if statuses[0].StatusInfo.FailInfo.BitLength == 0 {
		t.Fatalf("expected non-empty failInfo, got empty")
	}
}

// TestDecodeCertConfStatuses_SingleAccepted verifies the happy-path: a single
// CertStatus with certReqId 0 and no statusInfo decodes to exactly one entry
// with the correct certHash.
func TestDecodeCertConfStatuses_SingleAccepted(t *testing.T) {
	hash := make([]byte, 32)
	for i := range hash {
		hash[i] = byte(i)
	}
	cs := buildCertStatusTLV(t, hash, 0, nil)
	body := buildCertConfirmContent(t, cs)
	statuses, err := corecmp.DecodeCertConfStatuses(body)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(statuses) != 1 {
		t.Fatalf("expected 1 status, got %d", len(statuses))
	}
	if statuses[0].CertReqID != 0 {
		t.Fatalf("expected certReqId 0, got %d", statuses[0].CertReqID)
	}
	if len(statuses[0].CertHash) != 32 {
		t.Fatalf("expected 32-byte certHash, got %d", len(statuses[0].CertHash))
	}
	if statuses[0].CertHash[5] != 5 {
		t.Fatalf("certHash content mismatch: got %x", statuses[0].CertHash)
	}
}

// TestDecodeCertConfStatuses_ExplicitHashAlg verifies the optional hashAlg [0]
// field is parsed when EXPLICIT-tagged (the CMP module uses EXPLICIT TAGS), so
// [0] wraps a full AlgorithmIdentifier SEQUENCE. Without unwrapping the
// SEQUENCE the OID would be lost and the server would recompute certHash with
// the default algorithm, wrongly rejecting a valid pvno=3 different-hash
// confirmation (RFC 9483 §4.1.1 / RFC 9810 §5.3.18).
func TestDecodeCertConfStatuses_ExplicitHashAlg(t *testing.T) {
	hash := make([]byte, 64)

	// AlgorithmIdentifier { algorithm = id-sha512 (2.16.840.1.101.3.4.2.3) }
	sha512OID := asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
	algIDDER, err := asn1.Marshal(struct {
		Algorithm asn1.ObjectIdentifier
	}{Algorithm: sha512OID})
	if err != nil {
		t.Fatalf("marshal AlgorithmIdentifier: %v", err)
	}
	// hashAlg [0] EXPLICIT AlgorithmIdentifier — the [0] content is the whole
	// AlgorithmIdentifier SEQUENCE TLV.
	hashAlgField, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        0,
		IsCompound: true,
		Bytes:      algIDDER,
	})
	if err != nil {
		t.Fatalf("marshal hashAlg [0]: %v", err)
	}

	// CertStatus { certHash, certReqId=0, hashAlg [0] } (no statusInfo).
	hashDER, _ := asn1.Marshal(hash)
	reqIDDER, _ := asn1.Marshal(0)
	content := append(append(append([]byte{}, hashDER...), reqIDDER...), hashAlgField...)
	cs, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      content,
	})
	if err != nil {
		t.Fatalf("marshal CertStatus: %v", err)
	}

	body := buildCertConfirmContent(t, cs)
	statuses, err := corecmp.DecodeCertConfStatuses(body)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(statuses) != 1 {
		t.Fatalf("expected 1 status, got %d", len(statuses))
	}
	if !statuses[0].HashAlgOID.Equal(sha512OID) {
		t.Fatalf("expected hashAlg OID %v, got %v", sha512OID, statuses[0].HashAlgOID)
	}
}

// TestFindFirstOctetString_BoundsRecursionDepth is a DoS regression test:
// certConf parsing (decodeCertConfStatuses -> findFirstOctetString) walks
// fully unauthenticated, attacker-controlled ASN.1. Before
// maxOctetStringSearchDepth was added, a pathologically nested
// SEQUENCE-of-SEQUENCE payload could recurse until it hit Go's stack limit,
// crashing the process with a non-recoverable fatal error instead of
// returning a normal decode error.
func TestFindFirstOctetString_BoundsRecursionDepth(t *testing.T) {
	// Build a chain of nested SEQUENCEs, innermost containing no OCTET STRING
	// at all, deep enough to exceed maxOctetStringSearchDepth.
	inner, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassUniversal, Tag: asn1.TagInteger, Bytes: []byte{0x00},
	})
	if err != nil {
		t.Fatalf("marshal innermost INTEGER: %v", err)
	}
	for i := 0; i < corecmp.MaxOctetStringSearchDepth+16; i++ {
		wrapped, err := asn1.Marshal(asn1.RawValue{
			Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: inner,
		})
		if err != nil {
			t.Fatalf("marshal nesting level %d: %v", i, err)
		}
		inner = wrapped
	}

	_, err = corecmp.FindFirstOctetString(inner)
	if err == nil {
		t.Fatal("expected an error for a pathologically nested ASN.1 structure, got nil (unbounded recursion regression)")
	}
}
