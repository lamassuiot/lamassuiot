package webhookclient

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/config"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

func TestWebhookAlwaysValidatesServerCertificate(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("webhook reached an untrusted server")
	}))
	defer server.Close()
	for _, raw := range []string{`{}`, `{"validate_server_cert":false}`, `{"validate_server_cert":true}`} {
		t.Run(raw, func(t *testing.T) {
			var options models.WebhookCallHttpClient
			require.NoError(t, json.Unmarshal([]byte(raw), &options))
			_, err := InvokeWebhook(logrus.NewEntry(logrus.New()), models.WebhookCall{Url: server.URL, Config: options}, []byte(`{}`))
			var unknownAuthority x509.UnknownAuthorityError
			require.ErrorAs(t, err, &unknownAuthority)
		})
	}
}

func TestWebhookMTLSAcceptsOnlyInlinePEM(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	certificate := server.TLS.Certificates[0]
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Certificate[0]})
	keyDER, err := x509.MarshalPKCS8PrivateKey(certificate.PrivateKey)
	require.NoError(t, err)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	certPath := filepath.Join(t.TempDir(), "client.crt")
	keyPath := filepath.Join(t.TempDir(), "client.key")
	require.NoError(t, os.WriteFile(certPath, certPEM, 0600))
	require.NoError(t, os.WriteFile(keyPath, keyPEM, 0600))
	// These are valid, readable credentials: rejecting them must not depend on
	// a filesystem error or on the remote server's certificate being untrusted.
	_, err = tls.LoadX509KeyPair(certPath, keyPath)
	require.NoError(t, err)
	for _, tc := range []struct{ name, cert, key string }{
		{"local files", certPath, keyPath},
		{"inline certificate and local key", string(certPEM), keyPath},
		{"local certificate and inline key", certPath, string(keyPEM)},
		{"invalid PEM", "invalid certificate", "invalid key"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conf := models.WebhookCall{Url: server.URL, Config: models.WebhookCallHttpClient{
				AuthMode:  config.MTLS,
				MutualTLS: models.WebhookCallHttpClientMutualTLS{Cert: tc.cert, Key: tc.key},
			}}
			_, err := InvokeWebhook(logrus.NewEntry(logrus.New()), conf, []byte(`{}`))
			require.ErrorContains(t, err, "webhook mTLS requires a PEM-encoded certificate and private key")
		})
	}
	require.Zero(t, calls.Load())
	// Inline PEM must pass client credential validation and reach the TLS check.
	conf := models.WebhookCall{Url: server.URL, Config: models.WebhookCallHttpClient{
		AuthMode:  config.MTLS,
		MutualTLS: models.WebhookCallHttpClientMutualTLS{Cert: string(certPEM), Key: string(keyPEM)},
	}}
	_, err = InvokeWebhook(logrus.NewEntry(logrus.New()), conf, []byte(`{}`))
	var unknownAuthority x509.UnknownAuthorityError
	require.ErrorAs(t, err, &unknownAuthority)
}
