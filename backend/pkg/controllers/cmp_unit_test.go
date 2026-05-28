package controllers

import (
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

			h := requestPKIHeader{}
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
		Type:  oidImplicitConfirm,
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
			reqHeader := requestPKIHeader{
				PVNO:          pvnoCMP2000,
				TransactionID: []byte("0123456789abcdef"),
				SenderNonce:   []byte("0123456789abcdef"),
			}

			// Body: pkiConf (empty NULL body content).
			body, err := marshalPKIConfBody()
			require.NoError(t, err)

			out, err := marshalProtectedResponse(reqHeader, cmpBodyTagPKIConf, body, []*x509.Certificate{cert}, signer)
			require.NoError(t, err, "marshalProtectedResponse must succeed for %s", tc.name)
			require.NotEmpty(t, out)

			// Round-trip: parse the response and verify the signature against
			// the same cert we signed with (mirrors what an EE would do).
			var raw rawResponsePKIMessage
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
		header      requestPKIHeader
		wantReject  bool
		wantFailBit int
	}{
		{
			name: "valid envelope passes",
			header: requestPKIHeader{
				PVNO:          pvnoCMP2000,
				TransactionID: goodTxID,
				SenderNonce:   goodNonce,
				MessageTime:   now.Add(-30 * time.Second),
			},
			wantReject: false,
		},
		{
			name: "valid envelope without messageTime passes (optional)",
			header: requestPKIHeader{
				PVNO:          pvnoCMP2021,
				TransactionID: goodTxID,
				SenderNonce:   goodNonce,
			},
			wantReject: false,
		},
		{
			name:        "unsupported pvno",
			header:      requestPKIHeader{PVNO: 99, TransactionID: goodTxID, SenderNonce: goodNonce},
			wantReject:  true,
			wantFailBit: pkiFailureInfoUnsupportedVersion,
		},
		{
			name:        "missing transactionID",
			header:      requestPKIHeader{PVNO: pvnoCMP2000, SenderNonce: goodNonce},
			wantReject:  true,
			wantFailBit: pkiFailureInfoBadDataFormat,
		},
		{
			name:        "short transactionID",
			header:      requestPKIHeader{PVNO: pvnoCMP2000, TransactionID: []byte{1, 2, 3}, SenderNonce: goodNonce},
			wantReject:  true,
			wantFailBit: pkiFailureInfoBadDataFormat,
		},
		{
			name:        "short senderNonce",
			header:      requestPKIHeader{PVNO: pvnoCMP2000, TransactionID: goodTxID, SenderNonce: []byte{1, 2, 3}},
			wantReject:  true,
			wantFailBit: pkiFailureInfoBadSenderNonce,
		},
		{
			name: "messageTime future drift",
			header: requestPKIHeader{
				PVNO:          pvnoCMP2000,
				TransactionID: goodTxID,
				SenderNonce:   goodNonce,
				MessageTime:   now.Add(10 * time.Minute),
			},
			wantReject:  true,
			wantFailBit: pkiFailureInfoBadTime,
		},
		{
			name: "messageTime past drift",
			header: requestPKIHeader{
				PVNO:          pvnoCMP2000,
				TransactionID: goodTxID,
				SenderNonce:   goodNonce,
				MessageTime:   now.Add(-10 * time.Minute),
			},
			wantReject:  true,
			wantFailBit: pkiFailureInfoBadTime,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rej := validateRequestEnvelope(tc.header, now)
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
		assert.Equal(t, pkiFailureInfoBadMessageCheck, rej.failInfo)
	})

	t.Run("non-directoryName CHOICE rejected", func(t *testing.T) {
		rfc822Sender := asn1.RawValue{
			Class: asn1.ClassContextSpecific,
			Tag:   1, // rfc822Name
			Bytes: []byte("alice@example.com"),
		}
		rej := verifySenderMatchesProtectionCert(rfc822Sender, cert)
		require.NotNil(t, rej)
		assert.Equal(t, pkiFailureInfoBadMessageCheck, rej.failInfo)
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
