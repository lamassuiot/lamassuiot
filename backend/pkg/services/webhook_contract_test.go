package services

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lamassuiot/lamassuiot/v4/core"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/config"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/errs"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestEnrollmentWebhookEveryOpenAPIOperation(t *testing.T) {
	spec, err := os.ReadFile("../specs/enroll-reenroll-webhook-openapi.yaml")
	require.NoError(t, err)
	var doc struct {
		Paths map[string]map[string]yaml.Node `yaml:"paths"`
	}
	require.NoError(t, yaml.Unmarshal(spec, &doc))
	csrPEM, err := os.ReadFile("../helpers/testdata/samplecsr.pem")
	require.NoError(t, err)
	block, _ := pem.Decode(csrPEM)
	require.NotNil(t, block)
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	require.NoError(t, err)
	logger := logrus.NewEntry(logrus.New())
	original := httptest.NewRequest(http.MethodPost, "http://est.example/.well-known/est/profile/simpleenroll", nil)
	original.Header.Set("X-Device", "device-123")
	ctx := context.WithValue(context.Background(), core.LamassuContextKeyHTTPRequest, original)
	operations := 0
	for path, item := range doc.Paths {
		for method := range item {
			if method == "parameters" || strings.HasPrefix(method, "x-") {
				continue
			}
			require.Contains(t, []string{"post", "put"}, method, "new webhook method needs client support and a test")
			operations++
			for _, scenario := range []struct {
				name, body string
				status     int
				allow      bool
				slow       bool
			}{
				{name: "allow", body: `{"authorized":true}`, status: 200, allow: true},
				{name: "deny", body: `{"authorized":false}`, status: 200},
				{name: "missing decision", body: `{}`, status: 200},
				{name: "invalid JSON", body: `not json`, status: 200},
				{name: "wrong decision type", body: `{"authorized":"true"}`, status: 200},
				{name: "empty response", status: 204},
				{name: "non-success status", body: `{"authorized":true}`, status: 403},
				{name: "timeout", body: `{"authorized":true}`, status: 200, slow: true},
			} {
				t.Run(method+" "+path+"/"+scenario.name, func(t *testing.T) {
					// This is an outbound API: use the real HTTP client against a local callback.
					received := make(chan map[string]any, 1)
					methods := make(chan string, 1)
					server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						methods <- r.Method
						contentType := r.Header.Get("Content-Type")
						var payload map[string]any
						data, readErr := io.ReadAll(r.Body)
						if readErr == nil {
							_ = json.Unmarshal(data, &payload)
						}
						received <- payload
						if contentType != "application/json" {
							w.WriteHeader(http.StatusUnsupportedMediaType)
							return
						}
						if scenario.slow {
							time.Sleep(50 * time.Millisecond)
						}
						w.WriteHeader(scenario.status)
						_, _ = w.Write([]byte(scenario.body))
					}))
					defer server.Close()
					conf := models.WebhookCall{Name: "test", Url: server.URL + path, Method: strings.ToUpper(method), Config: models.WebhookCallHttpClient{HTTPClient: config.HTTPClient{AuthMode: config.NoAuth}}}
					if scenario.slow {
						conf.Config.CallTimeout = models.TimeDuration(10 * time.Millisecond)
					}
					_, err := invokeWebhook(ctx, logger, conf, csr, "profile", "enrollment")
					if scenario.allow {
						require.NoError(t, err)
					} else {
						require.Error(t, err)
					}
					if scenario.slow {
						assert.ErrorContains(t, err, "timed out or was canceled")
					}
					select {
					case actual := <-methods:
						assert.Equal(t, strings.ToUpper(method), actual)
					case <-time.After(time.Second):
						t.Fatal("webhook client did not call documented operation")
					}
					payload := <-received
					require.NotNil(t, payload)
					assert.Equal(t, "profile", payload["aps"])
					assert.Equal(t, csr.Subject.CommonName, payload["device_cn"])
					encoded, ok := payload["csr"].(string)
					require.True(t, ok)
					decoded, err := base64.StdEncoding.DecodeString(encoded)
					require.NoError(t, err)
					actualCSR, _ := pem.Decode(decoded)
					require.NotNil(t, actualCSR)
					assert.Equal(t, csr.Raw, actualCSR.Bytes)
					request, ok := payload["http_request"].(map[string]any)
					require.True(t, ok)
					assert.Equal(t, original.URL.String(), request["url"])
					assert.Equal(t, "device-123", request["headers"].(map[string]any)["X-Device"])
				})
			}
		}
	}
	require.Equal(t, 2, operations)
}

func TestEnrollmentWebhookRejectsReservedApiKeyHeader(t *testing.T) {
	csrPEM, err := os.ReadFile("../helpers/testdata/samplecsr.pem")
	require.NoError(t, err)
	block, _ := pem.Decode(csrPEM)
	require.NotNil(t, block)
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	require.NoError(t, err)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("webhook with reserved header reached the server: X-Principal-ID=%q", r.Header.Get("X-Principal-ID"))
		_, _ = w.Write([]byte(`{"authorized":true}`))
	}))
	defer server.Close()
	conf := models.WebhookCall{Name: "test", Url: server.URL, Method: http.MethodPost, Config: models.WebhookCallHttpClient{HTTPClient: config.HTTPClient{
		AuthMode:          config.ApiKey,
		AuthApiKeyOptions: config.AuthApiKeyOptions{Header: "X-Principal-ID", Key: "admin-mode"},
	}}}
	_, err = invokeWebhook(context.Background(), logrus.NewEntry(logrus.New()), conf, csr, "profile", "enrollment")
	require.ErrorContains(t, err, "is reserved")
}

func TestValidateDMSWebhooks(t *testing.T) {
	webhookSettings := func(cfg config.HTTPClient) models.EnrollmentOptionsESTRFC7030 {
		return models.EnrollmentOptionsESTRFC7030{
			AuthMode:                   models.ESTAuthModeExternalWebhook,
			AuthOptionsExternalWebhook: models.WebhookCall{Name: "hook", Url: "https://example.com", Config: models.WebhookCallHttpClient{HTTPClient: cfg}},
		}
	}
	fileMTLS := config.HTTPClient{AuthMode: config.MTLS, AuthMTLSOptions: config.AuthMTLSOptions{CertFile: "/certs/client.crt", KeyFile: "/certs/client.key"}}

	t.Run("valid", func(t *testing.T) {
		var settings models.DMSSettings
		settings.EnrollmentSettings.EnrollmentOptionsESTRFC7030 = webhookSettings(config.HTTPClient{AuthMode: config.NoAuth})
		require.NoError(t, validateDMSWebhooks(settings))
	})

	t.Run("rejects reenrollment file references", func(t *testing.T) {
		var settings models.DMSSettings
		settings.ReEnrollmentSettings.ReEnrollmentOptionsESTRFC7030 = webhookSettings(fileMTLS)
		err := validateDMSWebhooks(settings)
		require.ErrorIs(t, err, errs.ErrValidateBadRequest)
		require.ErrorContains(t, err, "reenrollment external webhook")
		require.ErrorContains(t, err, "must not reference files")
	})

	t.Run("rejects calls that fail on every enroll", func(t *testing.T) {
		for name, tc := range map[string]struct {
			edit func(*models.WebhookCall)
			err  string
		}{
			"unsupported method":  {func(w *models.WebhookCall) { w.Method = http.MethodGet }, `method "GET" is not supported`},
			"missing url":         {func(w *models.WebhookCall) { w.Url = "" }, "url must be an absolute http or https URL"},
			"jwt without options": {func(w *models.WebhookCall) { w.Config.AuthMode = config.JWT }, "requires jwt_options"},
		} {
			t.Run(name, func(t *testing.T) {
				var settings models.DMSSettings
				settings.EnrollmentSettings.EnrollmentOptionsESTRFC7030 = webhookSettings(config.HTTPClient{AuthMode: config.NoAuth})
				tc.edit(&settings.EnrollmentSettings.EnrollmentOptionsESTRFC7030.AuthOptionsExternalWebhook)
				err := validateDMSWebhooks(settings)
				require.ErrorIs(t, err, errs.ErrValidateBadRequest)
				require.ErrorContains(t, err, tc.err)
			})
		}
	})

	t.Run("validates client certificate and webhook mode", func(t *testing.T) {
		var settings models.DMSSettings
		settings.EnrollmentSettings.EnrollmentOptionsESTRFC7030 = webhookSettings(fileMTLS)
		settings.EnrollmentSettings.EnrollmentOptionsESTRFC7030.AuthMode = models.ESTAuthModeClientCertificateAndWebhook
		require.ErrorIs(t, validateDMSWebhooks(settings), errs.ErrValidateBadRequest)
	})

	t.Run("ignores webhook config when auth mode is not external webhook", func(t *testing.T) {
		var settings models.DMSSettings
		settings.EnrollmentSettings.EnrollmentOptionsESTRFC7030 = webhookSettings(fileMTLS)
		settings.EnrollmentSettings.EnrollmentOptionsESTRFC7030.AuthMode = models.ESTAuthModeClientCertificate
		require.NoError(t, validateDMSWebhooks(settings))
	})
}
