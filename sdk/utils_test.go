package sdk

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
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lamassuiot/lamassuiot/v4/core"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/config"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

func selfSignedClientPEM(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "sdk-client"},
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

func TestBuildHTTPClientMTLSCertificateSources(t *testing.T) {
	certPEM, keyPEM := selfSignedClientPEM(t)
	dir := t.TempDir()
	certPath := filepath.Join(dir, "client.crt")
	keyPath := filepath.Join(dir, "client.key")
	require.NoError(t, os.WriteFile(certPath, certPEM, 0o600))
	require.NoError(t, os.WriteFile(keyPath, keyPEM, 0o600))

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(r.TLS.PeerCertificates) != 1 || r.TLS.PeerCertificates[0].Subject.CommonName != "sdk-client" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	server.TLS = &tls.Config{ClientAuth: tls.RequireAnyClientCert}
	server.StartTLS()
	defer server.Close()

	for name, opts := range map[string]config.AuthMTLSOptions{
		"base64 content":     {CertContent: base64.StdEncoding.EncodeToString(certPEM), KeyContent: base64.StdEncoding.EncodeToString(keyPEM)},
		"plain PEM content":  {CertContent: string(certPEM), KeyContent: string(keyPEM)},
		"legacy PEM in file": {CertFile: string(certPEM), KeyFile: string(keyPEM)},
		"file paths":         {CertFile: certPath, KeyFile: keyPath},
	} {
		t.Run(name, func(t *testing.T) {
			cli, err := BuildHTTPClient(config.HTTPClient{
				AuthMode:        config.MTLS,
				AuthMTLSOptions: opts,
				HTTPConnection: config.HTTPConnection{BasicConnection: config.BasicConnection{
					TLSConfig: config.TLSConfig{InsecureSkipVerify: true},
				}},
			}, logrus.NewEntry(logrus.New()))
			require.NoError(t, err)

			res, err := cli.Get(server.URL)
			require.NoError(t, err)
			res.Body.Close()
			require.Equal(t, http.StatusOK, res.StatusCode)
		})
	}
}

// Every auth mode must trust a server signed by the CA in ca_cert_file.
func TestBuildHTTPClientTrustsCACertificateFile(t *testing.T) {
	certPEM, keyPEM := selfSignedClientPEM(t)

	var srv *httptest.Server
	srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"token_endpoint":"` + srv.URL + `/token"}`))
		case "/token":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"token","token_type":"Bearer","expires_in":3600}`))
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	srv.TLS = &tls.Config{ClientAuth: tls.RequestClientCert}
	srv.StartTLS()
	defer srv.Close()

	caFile := filepath.Join(t.TempDir(), "ca.crt")
	require.NoError(t, os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600))

	for name, cfg := range map[string]config.HTTPClient{
		"no auth": {AuthMode: config.NoAuth},
		"api key": {AuthMode: config.ApiKey, AuthApiKeyOptions: config.AuthApiKeyOptions{Header: "x-api-key", Key: "key"}},
		"mtls":    {AuthMode: config.MTLS, AuthMTLSOptions: config.AuthMTLSOptions{CertContent: string(certPEM), KeyContent: string(keyPEM)}},
		"jwt": {AuthMode: config.JWT, AuthJWTOptions: config.AuthJWTOptions{
			ClientID:         "client",
			ClientSecret:     "secret",
			OIDCWellKnownURL: srv.URL + "/.well-known/openid-configuration",
		}},
	} {
		t.Run(name, func(t *testing.T) {
			cfg.HTTPConnection = config.HTTPConnection{BasicConnection: config.BasicConnection{
				TLSConfig: config.TLSConfig{CACertificateFile: caFile},
			}}
			cli, err := BuildHTTPClient(cfg, logrus.NewEntry(logrus.New()))
			require.NoError(t, err)

			res, err := cli.Get(srv.URL)
			require.NoError(t, err)
			res.Body.Close()
			require.Equal(t, http.StatusOK, res.StatusCode)
		})
	}
}

func TestBuildHTTPClientJWTDiscoverySizeCap(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ok":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"token_endpoint":"` + srv.URL + `/token"}`))
		case "/huge":
			_, _ = w.Write(make([]byte, maxOIDCDiscoverySize+1))
		}
	}))
	defer srv.Close()

	build := func(wellKnown string) error {
		_, err := BuildHTTPClient(config.HTTPClient{
			AuthMode: config.JWT,
			AuthJWTOptions: config.AuthJWTOptions{
				ClientID:         "client",
				ClientSecret:     "secret",
				OIDCWellKnownURL: wellKnown,
			},
		}, logrus.NewEntry(logrus.New()))
		return err
	}

	require.NoError(t, build(srv.URL+"/ok"))

	err := build(srv.URL + "/huge")
	require.Error(t, err)
	require.Contains(t, err.Error(), "OIDC discovery response exceeds")
}

func TestHTTPHelpersPropagateTenantIDHeader(t *testing.T) {
	seen := map[string]string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen[r.Method] = r.Header.Get(tenantIDHeader)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	ctx := context.WithValue(context.Background(), core.LamassuContextKeyTenantID, "tenant-sdk")
	cli := srv.Client()

	_, err := Get[map[string]any](ctx, cli, srv.URL, nil, nil)
	require.NoError(t, err)
	_, err = Post[map[string]any](ctx, cli, srv.URL, map[string]any{"a": 1}, nil)
	require.NoError(t, err)
	_, err = Put[map[string]any](ctx, cli, srv.URL, map[string]any{"a": 2}, nil)
	require.NoError(t, err)
	require.NoError(t, Delete(ctx, cli, srv.URL, nil))

	for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete} {
		require.Equal(t, "tenant-sdk", seen[method], method)
	}
}
