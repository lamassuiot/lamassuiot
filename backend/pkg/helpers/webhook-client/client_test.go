package webhookclient

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/config"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

func apiKeyWebhook(url, header string) models.WebhookCall {
	return models.WebhookCall{Name: "test", Url: url, Config: models.WebhookCallHttpClient{HTTPClient: config.HTTPClient{
		AuthMode:          config.ApiKey,
		AuthApiKeyOptions: config.AuthApiKeyOptions{Header: header, Key: "admin-mode"},
	}}}
}

func TestInvokeWebhookRejectsReservedApiKeyHeaders(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("webhook with reserved header reached the server: X-Principal-ID=%q", r.Header.Get("X-Principal-ID"))
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	for _, header := range []string{
		"X-Principal-ID", "x-principal-id", " X-Principal-Id ", "X-Lms-Source", "X-Request-Id",
		"X-Forwarded-Cert", "X-Forwarded-Client-Cert", "X-Forwarded-Tls-Client-Cert", "X-Forwarded-For",
		"Ssl-Client-Cert", "X-Amzn-Mtls-Clientcert", "X-Envoy-Original-Path", "X-Original-Uri", "Host",
	} {
		t.Run(header, func(t *testing.T) {
			err := InvokeWebhook(context.Background(), logrus.NewEntry(logrus.New()), apiKeyWebhook(server.URL, header), []byte("{}"))
			require.ErrorContains(t, err, "is reserved")
		})
	}
}

func TestInvokeWebhookSendsCustomApiKeyHeader(t *testing.T) {
	received := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received <- r.Header.Get("Authorization")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	err := InvokeWebhook(context.Background(), logrus.NewEntry(logrus.New()), apiKeyWebhook(server.URL, "Authorization"), []byte("{}"))
	require.NoError(t, err)
	require.Equal(t, "admin-mode", <-received)
}

// The transport adds the credential to every request, including redirected
// ones, so following a redirect would hand it to wherever the receiver points.
func TestInvokeWebhookDoesNotFollowRedirects(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("redirect was followed: X-Api-Key=%q", r.Header.Get("X-Api-Key"))
	}))
	defer target.Close()
	for _, code := range []int{http.StatusFound, http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, target.URL, code)
			}))
			defer server.Close()
			err := InvokeWebhook(context.Background(), logrus.NewEntry(logrus.New()), apiKeyWebhook(server.URL, "X-Api-Key"), []byte("{}"))
			require.ErrorContains(t, err, fmt.Sprintf("unexpected status code: %d", code))
		})
	}
}

func TestInvokeWebhookHonoursContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("canceled webhook reached the server")
	}))
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	conf := models.WebhookCall{Name: "test", Url: server.URL, Config: models.WebhookCallHttpClient{HTTPClient: config.HTTPClient{AuthMode: config.NoAuth}}}
	err := InvokeWebhook(ctx, logrus.NewEntry(logrus.New()), conf, []byte("{}"))
	require.ErrorIs(t, err, context.Canceled)
}

func TestInvokeWebhookJWTDiscoveryHonoursContextDeadline(t *testing.T) {
	release := make(chan struct{})
	oidc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
	}))
	defer oidc.Close()
	defer close(release)
	webhook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("webhook reached the server without a token")
	}))
	defer webhook.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	conf := models.WebhookCall{Name: "test", Url: webhook.URL, Config: models.WebhookCallHttpClient{HTTPClient: config.HTTPClient{
		AuthMode:       config.JWT,
		AuthJWTOptions: config.AuthJWTOptions{ClientID: "id", ClientSecret: "secret", OIDCWellKnownURL: oidc.URL},
	}}}
	start := time.Now()
	err := InvokeWebhook(ctx, logrus.NewEntry(logrus.New()), conf, []byte("{}"))
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Less(t, time.Since(start), 2*time.Second)
}

func selfSignedPEM(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "webhook-client"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}

func mtlsWebhook(url string, mtls config.AuthMTLSOptions) models.WebhookCall {
	return models.WebhookCall{Name: "test", Url: url, Config: models.WebhookCallHttpClient{HTTPClient: config.HTTPClient{
		AuthMode:        config.MTLS,
		AuthMTLSOptions: mtls,
		// httptest servers use a self-signed certificate.
		HTTPConnection: config.HTTPConnection{BasicConnection: config.BasicConnection{TLSConfig: config.TLSConfig{InsecureSkipVerify: true}}},
	}}}
}

func TestInvokeWebhookRejectsServerFiles(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("webhook referencing server files reached the server")
	}))
	defer server.Close()

	certPEM, keyPEM := selfSignedPEM(t)
	dir := t.TempDir()
	certPath := filepath.Join(dir, "client.crt")
	keyPath := filepath.Join(dir, "client.key")
	require.NoError(t, os.WriteFile(certPath, certPEM, 0o600))
	require.NoError(t, os.WriteFile(keyPath, keyPEM, 0o600))

	withCAFile := mtlsWebhook(server.URL, config.AuthMTLSOptions{CertContent: string(certPEM), KeyContent: string(keyPEM)})
	withCAFile.Config.CACertificateFile = certPath

	for name, tc := range map[string]struct {
		conf models.WebhookCall
		err  string
	}{
		"cert and key files": {mtlsWebhook(server.URL, config.AuthMTLSOptions{CertFile: certPath, KeyFile: keyPath}), "must not reference files"},
		"key file":           {mtlsWebhook(server.URL, config.AuthMTLSOptions{CertContent: string(certPEM), KeyFile: keyPath}), "must not reference files"},
		"ca cert file":       {withCAFile, "must not reference files"},
		"missing content":    {mtlsWebhook(server.URL, config.AuthMTLSOptions{CertContent: string(certPEM)}), "requires mtls_options.cert_content"},
		"mismatched key":     {mtlsWebhook(server.URL, config.AuthMTLSOptions{CertContent: string(certPEM), KeyContent: string(func() []byte { _, k := selfSignedPEM(t); return k }())}), "private key does not match"},
		"invalid base64":     {mtlsWebhook(server.URL, config.AuthMTLSOptions{CertContent: "not base64!", KeyContent: string(keyPEM)}), "mtls_options.cert_content must be base64-encoded PEM"},
	} {
		t.Run(name, func(t *testing.T) {
			err := InvokeWebhook(context.Background(), logrus.NewEntry(logrus.New()), tc.conf, []byte("{}"))
			require.ErrorContains(t, err, tc.err)
		})
	}
}

func TestValidateWebhook(t *testing.T) {
	webhook := func(url, method string, cfg config.HTTPClient) models.WebhookCall {
		return models.WebhookCall{Name: "test", Url: url, Method: method, Config: models.WebhookCallHttpClient{HTTPClient: cfg}}
	}
	noAuth := config.HTTPClient{AuthMode: config.NoAuth}
	jwt := func(opts config.AuthJWTOptions) config.HTTPClient {
		return config.HTTPClient{AuthMode: config.JWT, AuthJWTOptions: opts}
	}
	apiKey := func(opts config.AuthApiKeyOptions) config.HTTPClient {
		return config.HTTPClient{AuthMode: config.ApiKey, AuthApiKeyOptions: opts}
	}
	const hook, wellKnown = "https://hooks.example.com/x", "https://idp.example.com/.well-known/openid-configuration"

	for name, conf := range map[string]models.WebhookCall{
		"default method": webhook(hook, "", noAuth),
		"put over http":  webhook("http://hooks.example.com/x", http.MethodPut, noAuth),
		"api key":        webhook(hook, http.MethodPost, apiKey(config.AuthApiKeyOptions{Header: "X-Api-Key", Key: "secret"})),
		"jwt":            webhook(hook, http.MethodPost, jwt(config.AuthJWTOptions{ClientID: "id", ClientSecret: "secret", OIDCWellKnownURL: wellKnown})),
	} {
		t.Run(name, func(t *testing.T) {
			require.NoError(t, ValidateWebhook(conf))
		})
	}

	for name, tc := range map[string]struct {
		conf models.WebhookCall
		err  string
	}{
		"empty url":                 {webhook("", "", noAuth), "url must be an absolute http or https URL"},
		"url without scheme":        {webhook("hooks.example.com/x", "", noAuth), "url must be an absolute http or https URL"},
		"unsupported scheme":        {webhook("ftp://hooks.example.com/x", "", noAuth), "url must be an absolute http or https URL"},
		"unsupported method":        {webhook(hook, http.MethodGet, noAuth), `method "GET" is not supported`},
		"lowercase method":          {webhook(hook, "post", noAuth), `method "post" is not supported`},
		"api key without key":       {webhook(hook, "", apiKey(config.AuthApiKeyOptions{Header: "X-Api-Key"})), "requires apikey_options.header and apikey_options.key"},
		"api key without header":    {webhook(hook, "", apiKey(config.AuthApiKeyOptions{Key: "secret"})), "requires apikey_options.header and apikey_options.key"},
		"jwt without client id":     {webhook(hook, "", jwt(config.AuthJWTOptions{ClientSecret: "secret", OIDCWellKnownURL: wellKnown})), "requires jwt_options.oidc_client_id and jwt_options.oidc_client_secret"},
		"jwt without client secret": {webhook(hook, "", jwt(config.AuthJWTOptions{ClientID: "id", OIDCWellKnownURL: wellKnown})), "requires jwt_options.oidc_client_id and jwt_options.oidc_client_secret"},
		"jwt without well-known":    {webhook(hook, "", jwt(config.AuthJWTOptions{ClientID: "id", ClientSecret: "secret"})), "oidc_well_known must be an absolute http or https URL"},
	} {
		t.Run(name, func(t *testing.T) {
			require.ErrorContains(t, ValidateWebhook(tc.conf), tc.err)
		})
	}
}

func TestInvokeWebhookPresentsMTLSCertificateContent(t *testing.T) {
	certPEM, keyPEM := selfSignedPEM(t)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Len(t, r.TLS.PeerCertificates, 1)
		require.Equal(t, "webhook-client", r.TLS.PeerCertificates[0].Subject.CommonName)
		w.WriteHeader(http.StatusOK)
	}))
	server.TLS = &tls.Config{ClientAuth: tls.RequireAnyClientCert}
	server.StartTLS()
	defer server.Close()

	for name, opts := range map[string]config.AuthMTLSOptions{
		"base64 PEM": {CertContent: base64.StdEncoding.EncodeToString(certPEM), KeyContent: base64.StdEncoding.EncodeToString(keyPEM)},
		"plain PEM":  {CertContent: string(certPEM), KeyContent: string(keyPEM)},
	} {
		t.Run(name, func(t *testing.T) {
			err := InvokeWebhook(context.Background(), logrus.NewEntry(logrus.New()), mtlsWebhook(server.URL, opts), []byte("{}"))
			require.NoError(t, err)
		})
	}
}

func TestInvokeWebhookAppliesCallTimeout(t *testing.T) {
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
	}))
	defer server.Close()
	defer close(release)

	conf := models.WebhookCall{Name: "test", Url: server.URL, Config: models.WebhookCallHttpClient{
		HTTPClient:  config.HTTPClient{AuthMode: config.NoAuth},
		CallTimeout: models.TimeDuration(50 * time.Millisecond),
	}}
	start := time.Now()
	err := InvokeWebhook(context.Background(), logrus.NewEntry(logrus.New()), conf, []byte("{}"))
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Less(t, time.Since(start), 2*time.Second)
}

// Responses are ignored, so their size must not fail the delivery.
func TestInvokeWebhookIgnoresOversizedResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(make([]byte, 2*MaxResponseBodySize))
	}))
	defer server.Close()

	conf := models.WebhookCall{Name: "test", Url: server.URL, Config: models.WebhookCallHttpClient{HTTPClient: config.HTTPClient{AuthMode: config.NoAuth}}}
	err := InvokeWebhook(context.Background(), logrus.NewEntry(logrus.New()), conf, []byte("{}"))
	require.NoError(t, err)
}

func TestInvokeJSONWebhookRejectsOversizedResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(make([]byte, MaxResponseBodySize+1))
	}))
	defer server.Close()

	conf := models.WebhookCall{Name: "test", Url: server.URL, Config: models.WebhookCallHttpClient{HTTPClient: config.HTTPClient{AuthMode: config.NoAuth}}}
	_, err := InvokeJSONWebhook[map[string]any](context.Background(), logrus.NewEntry(logrus.New()), conf, map[string]any{})
	require.ErrorContains(t, err, "webhook response exceeds")
}

func TestInvokeJSONWebhookDecodesResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"authorized":true}`))
	}))
	defer server.Close()

	type response struct {
		Authorized bool `json:"authorized"`
	}
	conf := models.WebhookCall{Name: "test", Url: server.URL, Config: models.WebhookCallHttpClient{HTTPClient: config.HTTPClient{AuthMode: config.NoAuth}}}
	res, err := InvokeJSONWebhook[response](context.Background(), logrus.NewEntry(logrus.New()), conf, map[string]any{})
	require.NoError(t, err)
	require.True(t, res.Authorized)
}
