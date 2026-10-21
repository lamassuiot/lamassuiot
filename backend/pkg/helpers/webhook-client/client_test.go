package webhookclient

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/config"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

func apiKeyWebhook(url, header string) models.WebhookCall {
	return models.WebhookCall{Name: "test", Url: url, Config: models.WebhookCallHttpClient{
		AuthMode: config.ApiKey,
		ApiKey:   models.WebhookCallHttpClientApiKey{Header: header, Key: "admin-mode"},
	}}
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
			_, err := InvokeWebhook(context.Background(), logrus.NewEntry(logrus.New()), apiKeyWebhook(server.URL, header), []byte("{}"))
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
	_, err := InvokeWebhook(context.Background(), logrus.NewEntry(logrus.New()), apiKeyWebhook(server.URL, "Authorization"), []byte("{}"))
	require.NoError(t, err)
	require.Equal(t, "admin-mode", <-received)
}

func TestInvokeWebhookHonoursContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("canceled webhook reached the server")
	}))
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	conf := models.WebhookCall{Name: "test", Url: server.URL, Config: models.WebhookCallHttpClient{AuthMode: config.NoAuth}}
	_, err := InvokeWebhook(ctx, logrus.NewEntry(logrus.New()), conf, []byte("{}"))
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
	conf := models.WebhookCall{Name: "test", Url: webhook.URL, Config: models.WebhookCallHttpClient{
		AuthMode: config.JWT,
		OIDC:     models.WebhookCallHttpClientOidcOptions{ClientID: "id", ClientSecret: "secret", OIDCWellKnownURL: oidc.URL},
	}}
	start := time.Now()
	_, err := InvokeWebhook(ctx, logrus.NewEntry(logrus.New()), conf, []byte("{}"))
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Less(t, time.Since(start), 2*time.Second)
}
