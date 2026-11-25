package external_clients

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"
)

type testKeyPair struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func issueTestCert(t *testing.T, tmpl *x509.Certificate, parent *testKeyPair) *testKeyPair {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signerCert, signerKey := tmpl, key
	if parent != nil {
		signerCert, signerKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signerCert, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatalf("could not create certificate: %s", err)
	}
	cert, _ := x509.ParseCertificate(der)
	return &testKeyPair{cert: cert, key: key}
}

// delegatedOCSPServer answers every request with a "good" response signed by responder, embedding its certificate.
func delegatedOCSPServer(t *testing.T, issuer, responder *testKeyPair) *httptest.Server {
	t.Helper()
	return signedOCSPServer(t, issuer, responder.cert, responder.key)
}

// signedOCSPServer answers every request with a "good" response signed by key, embedding the certificate embedded
// unless it is nil. The two do not need to match.
func signedOCSPServer(t *testing.T, issuer *testKeyPair, embedded *x509.Certificate, key *ecdsa.PrivateKey) *httptest.Server {
	t.Helper()
	responderCert := embedded
	if responderCert == nil {
		responderCert = issuer.cert
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		req, err := ocsp.ParseRequest(body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		resp, err := ocsp.CreateResponse(issuer.cert, responderCert, ocsp.Response{
			Status:       ocsp.Good,
			SerialNumber: req.SerialNumber,
			ThisUpdate:   time.Now().Add(-time.Minute),
			NextUpdate:   time.Now().Add(time.Hour),
			Certificate:  embedded,
		}, key)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Write(resp)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestDelegatedOCSPResponderValidity(t *testing.T) {
	ca := issueTestCert(t, &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ca"},
		NotBefore:             time.Now().Add(-48 * time.Hour),
		NotAfter:              time.Now().Add(48 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}, nil)
	leaf := issueTestCert(t, &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "device"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}, ca)

	tests := []struct {
		name        string
		notBefore   time.Time
		notAfter    time.Time
		expectedErr string
	}{
		{"OK/Valid", time.Now().Add(-time.Hour), time.Now().Add(time.Hour), ""},
		// A responder whose key leaked after it expired must not be able to vouch for revoked certificates.
		{"Err/Expired", time.Now().Add(-24 * time.Hour), time.Now().Add(-time.Hour), "not valid at this time"},
		{"Err/NotYetValid", time.Now().Add(time.Hour), time.Now().Add(24 * time.Hour), "not valid at this time"},
	}

	for idx, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			responder := issueTestCert(t, &x509.Certificate{
				SerialNumber: big.NewInt(int64(100 + idx)),
				Subject:      pkix.Name{CommonName: "ocsp-responder"},
				NotBefore:    tc.notBefore,
				NotAfter:     tc.notAfter,
				KeyUsage:     x509.KeyUsageDigitalSignature,
				ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning},
			}, ca)
			srv := delegatedOCSPServer(t, ca, responder)

			resp, err := GetOCSPResponsePost(srv.URL, leaf.cert, ca.cert, nil, true)
			if tc.expectedErr == "" {
				if err != nil {
					t.Fatalf("expected no error. Got %s", err)
				}
				if resp.Status != ocsp.Good {
					t.Fatalf("expected good status. Got %d", resp.Status)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.expectedErr) {
				t.Fatalf("expected error containing '%s'. Got %v", tc.expectedErr, err)
			}
		})
	}
}

// TestOCSPResponseSignedByIssuer covers responses signed with the key of the issuer itself, which RFC 6960 4.2.2.2
// authorizes without any EKU, whether or not they embed the issuer's certificate.
func TestOCSPResponseSignedByIssuer(t *testing.T) {
	caTemplate := func(serial int64, cn string) *x509.Certificate {
		return &x509.Certificate{
			SerialNumber:          big.NewInt(serial),
			Subject:               pkix.Name{CommonName: cn},
			NotBefore:             time.Now().Add(-48 * time.Hour),
			NotAfter:              time.Now().Add(48 * time.Hour),
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
			BasicConstraintsValid: true,
			IsCA:                  true,
		}
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "device"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}

	root := issueTestCert(t, caTemplate(1, "root"), nil)
	intermediate := issueTestCert(t, caTemplate(2, "intermediate"), root)
	other := issueTestCert(t, caTemplate(4, "other"), nil)

	tests := []struct {
		name        string
		issuer      *testKeyPair
		embedded    func(issuer *testKeyPair) *x509.Certificate
		signer      func(issuer *testKeyPair) *ecdsa.PrivateKey
		expectedErr string
	}{
		{
			name:     "OK/NoEmbeddedCertificate",
			issuer:   intermediate,
			embedded: func(*testKeyPair) *x509.Certificate { return nil },
			signer:   func(issuer *testKeyPair) *ecdsa.PrivateKey { return issuer.key },
		},
		{
			name:     "OK/RootEmbedsItsOwnCertificate",
			issuer:   root,
			embedded: func(issuer *testKeyPair) *x509.Certificate { return issuer.cert },
			signer:   func(issuer *testKeyPair) *ecdsa.PrivateKey { return issuer.key },
		},
		{
			// The intermediate's certificate is signed by the root, not by the intermediate's own key.
			name:     "OK/IntermediateEmbedsItsOwnCertificate",
			issuer:   intermediate,
			embedded: func(issuer *testKeyPair) *x509.Certificate { return issuer.cert },
			signer:   func(issuer *testKeyPair) *ecdsa.PrivateKey { return issuer.key },
		},
		{
			name:        "Err/NoEmbeddedCertificateSignedByAnotherKey",
			issuer:      intermediate,
			embedded:    func(*testKeyPair) *x509.Certificate { return nil },
			signer:      func(*testKeyPair) *ecdsa.PrivateKey { return other.key },
			expectedErr: "signature",
		},
		{
			name:        "Err/EmbeddedIssuerCertificateSignedByAnotherKey",
			issuer:      intermediate,
			embedded:    func(issuer *testKeyPair) *x509.Certificate { return issuer.cert },
			signer:      func(*testKeyPair) *ecdsa.PrivateKey { return other.key },
			expectedErr: "signature",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			leaf := issueTestCert(t, leafTemplate, tc.issuer)
			srv := signedOCSPServer(t, tc.issuer, tc.embedded(tc.issuer), tc.signer(tc.issuer))

			resp, err := GetOCSPResponsePost(srv.URL, leaf.cert, tc.issuer.cert, nil, true)
			if tc.expectedErr == "" {
				if err != nil {
					t.Fatalf("expected no error. Got %s", err)
				}
				if resp.Status != ocsp.Good {
					t.Fatalf("expected good status. Got %d", resp.Status)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.expectedErr) {
				t.Fatalf("expected error containing '%s'. Got %v", tc.expectedErr, err)
			}
		})
	}
}
