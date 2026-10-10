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

	"github.com/lamassuiot/lamassuiot/core/v3"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
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
					conf := models.WebhookCall{Name: "test", Url: server.URL + path, Method: strings.ToUpper(method), Config: models.WebhookCallHttpClient{AuthMode: config.NoAuth, LogLevel: "error"}}
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
