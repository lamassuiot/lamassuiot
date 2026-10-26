package external_clients

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// hangingServer accepts requests but never answers until the test ends.
func hangingServer(t *testing.T) *httptest.Server {
	t.Helper()
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(func() {
		close(release)
		srv.Close()
	})
	return srv
}

func selfSignedCert(t *testing.T) *x509.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("could not create certificate: %s", err)
	}
	cert, _ := x509.ParseCertificate(der)
	return cert
}

func TestRevocationRequestsTimeOut(t *testing.T) {
	previous := revocationRequestTimeout
	revocationRequestTimeout = 200 * time.Millisecond
	t.Cleanup(func() { revocationRequestTimeout = previous })

	cert := selfSignedCert(t)

	tests := []struct {
		name string
		call func(url string) error
	}{
		{"OCSPPost", func(url string) error {
			_, err := GetOCSPResponsePost(url, cert, cert, nil, true)
			return err
		}},
		{"OCSPGet", func(url string) error {
			_, err := GetOCSPResponseGet(url, cert, cert, nil, true)
			return err
		}},
		{"CRL", func(url string) error {
			_, err := GetCRLResponse(url, cert, nil, true)
			return err
		}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := hangingServer(t)

			done := make(chan error, 1)
			go func() { done <- tc.call(srv.URL) }()

			select {
			case err := <-done:
				if err == nil {
					t.Fatalf("expected timeout error. Got none")
				}
			case <-time.After(5 * time.Second):
				t.Fatalf("request to a hanging server did not time out")
			}
		})
	}
}
