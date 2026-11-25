package revocation

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"
)

type testKeyPair struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

// testSerial numbers the test certificates. Tests in this package do not run in parallel.
var testSerial int64

// issueTestCert signs tmpl with parent, or self-signs it when parent is nil.
func issueTestCert(t *testing.T, tmpl *x509.Certificate, parent *testKeyPair) *testKeyPair {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("could not generate key: %s", err)
	}
	testSerial++
	tmpl.SerialNumber = big.NewInt(testSerial)
	signerCert, signerKey := tmpl, key
	if parent != nil {
		signerCert, signerKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signerCert, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatalf("could not create certificate: %s", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("could not parse certificate: %s", err)
	}
	return &testKeyPair{cert: cert, key: key}
}

func newTestCA(t *testing.T, cn string) *testKeyPair {
	t.Helper()
	return issueTestCert(t, &x509.Certificate{
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-48 * time.Hour),
		NotAfter:              time.Now().Add(48 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}, nil)
}

func newTestResponder(t *testing.T, issuer *testKeyPair, ekus []x509.ExtKeyUsage, notBefore, notAfter time.Time) *testKeyPair {
	t.Helper()
	return issueTestCert(t, &x509.Certificate{
		Subject:     pkix.Name{CommonName: "ocsp-responder"},
		NotBefore:   notBefore,
		NotAfter:    notAfter,
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: ekus,
	}, issuer)
}

// signedResponse returns a good response about a certificate of issuer, signed by signer and embedding embedded when
// not nil, as ocsp.ParseResponse returns it.
func signedResponse(t *testing.T, issuer, signer *testKeyPair, embedded *x509.Certificate) *ocsp.Response {
	t.Helper()
	der, err := ocsp.CreateResponse(issuer.cert, signer.cert, ocsp.Response{
		Status:       ocsp.Good,
		SerialNumber: big.NewInt(1000),
		ThisUpdate:   time.Now().Add(-time.Hour),
		NextUpdate:   time.Now().Add(time.Hour),
		Certificate:  embedded,
	}, signer.key)
	if err != nil {
		t.Fatalf("could not create OCSP response: %s", err)
	}
	resp, err := ocsp.ParseResponse(der, nil)
	if err != nil {
		t.Fatalf("could not parse OCSP response: %s", err)
	}
	return resp
}

func TestCheckDelegatedResponder(t *testing.T) {
	now := time.Now()
	ca := newTestCA(t, "ca")
	otherCA := newTestCA(t, "other-ca")
	validFrom, validTo := now.Add(-time.Hour), now.Add(time.Hour)

	delegated := func(t *testing.T, issuer *testKeyPair, ekus ...x509.ExtKeyUsage) *ocsp.Response {
		responder := newTestResponder(t, issuer, ekus, validFrom, validTo)
		return signedResponse(t, ca, responder, responder.cert)
	}

	tests := []struct {
		name    string
		resp    func(t *testing.T) *ocsp.Response
		issuer  *x509.Certificate
		now     time.Time
		wantErr string
	}{
		{
			name:   "OK/DelegatedOCSPSigning",
			resp:   func(t *testing.T) *ocsp.Response { return delegated(t, ca, x509.ExtKeyUsageOCSPSigning) },
			issuer: ca.cert,
			now:    now,
		},
		{
			// RFC 6960 4.2.2.2 authorizes the issuer's own key without any EKU.
			name:   "OK/SignedByIssuerKeyWithCertificate",
			resp:   func(t *testing.T) *ocsp.Response { return signedResponse(t, ca, ca, ca.cert) },
			issuer: ca.cert,
			now:    now,
		},
		{
			// anyExtendedKeyUsage, no EKU or the clientAuth EKU of a device certificate do not designate a responder.
			name:    "Err/AnyEKU",
			resp:    func(t *testing.T) *ocsp.Response { return delegated(t, ca, x509.ExtKeyUsageAny) },
			issuer:  ca.cert,
			now:     now,
			wantErr: "not authorized for OCSP signing",
		},
		{
			name:    "Err/NoEKU",
			resp:    func(t *testing.T) *ocsp.Response { return delegated(t, ca) },
			issuer:  ca.cert,
			now:     now,
			wantErr: "not authorized for OCSP signing",
		},
		{
			name:    "Err/ClientAuth",
			resp:    func(t *testing.T) *ocsp.Response { return delegated(t, ca, x509.ExtKeyUsageClientAuth) },
			issuer:  ca.cert,
			now:     now,
			wantErr: "not authorized for OCSP signing",
		},
		{
			// A responder whose key leaked after it expired must not be able to vouch for revoked certificates.
			name: "Err/Expired",
			resp: func(t *testing.T) *ocsp.Response {
				responder := newTestResponder(t, ca, []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning}, now.Add(-24*time.Hour), now.Add(-time.Hour))
				return signedResponse(t, ca, responder, responder.cert)
			},
			issuer:  ca.cert,
			now:     now,
			wantErr: "not valid at this time",
		},
		{
			name: "Err/NotYetValid",
			resp: func(t *testing.T) *ocsp.Response {
				responder := newTestResponder(t, ca, []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning}, now.Add(time.Hour), now.Add(24*time.Hour))
				return signedResponse(t, ca, responder, responder.cert)
			},
			issuer:  ca.cert,
			now:     now,
			wantErr: "not valid at this time",
		},
		{
			name:    "Err/ZeroNow",
			resp:    func(t *testing.T) *ocsp.Response { return delegated(t, ca, x509.ExtKeyUsageOCSPSigning) },
			issuer:  ca.cert,
			now:     time.Time{},
			wantErr: "not valid at this time",
		},
		{
			name:    "Err/IssuedByAnotherCA",
			resp:    func(t *testing.T) *ocsp.Response { return delegated(t, otherCA, x509.ExtKeyUsageOCSPSigning) },
			issuer:  ca.cert,
			now:     now,
			wantErr: "was not issued by the issuer",
		},
		{
			name:    "Err/NoEmbeddedCertificate",
			resp:    func(t *testing.T) *ocsp.Response { return signedResponse(t, ca, ca, nil) },
			issuer:  ca.cert,
			now:     now,
			wantErr: "embeds no responder certificate",
		},
		{
			// ocsp.ParseResponse checks the signature against the embedded certificate, but a caller could hand over a
			// response it built or altered itself.
			name: "Err/AlteredAfterParsing",
			resp: func(t *testing.T) *ocsp.Response {
				resp := delegated(t, ca, x509.ExtKeyUsageOCSPSigning)
				resp.TBSResponseData = slices.Clone(resp.TBSResponseData)
				resp.TBSResponseData[len(resp.TBSResponseData)-1] ^= 0xff
				return resp
			},
			issuer:  ca.cert,
			now:     now,
			wantErr: "bad OCSP signature",
		},
		{
			name:    "Err/NilResponse",
			resp:    func(t *testing.T) *ocsp.Response { return nil },
			issuer:  ca.cert,
			now:     now,
			wantErr: "missing OCSP response or issuer",
		},
		{
			name:    "Err/NilIssuer",
			resp:    func(t *testing.T) *ocsp.Response { return delegated(t, ca, x509.ExtKeyUsageOCSPSigning) },
			issuer:  nil,
			now:     now,
			wantErr: "missing OCSP response or issuer",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckDelegatedResponder(tc.resp(t), tc.issuer, tc.now)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("expected no error. Got %s", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("expected error containing %q. Got %v", tc.wantErr, err)
			}
		})
	}
}
