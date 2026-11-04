package api

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/lamassuiot/v4/core"
	cconfig "github.com/lamassuiot/lamassuiot/v4/core/pkg/config"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

func TestNewGinEngineExtractsBearerCredentials(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := newGinEngine(logrus.NewEntry(logrus.New()))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"dashboard-user"}`))
	token := strings.Join([]string{"header", payload, "signature"}, ".")

	router.GET("/protected", func(c *gin.Context) {
		authType, authTypeOK := c.Get(core.LamassuContextKeyAuthType)
		credential, credentialOK := c.Get(core.LamassuContextKeyAuthCredentialString)
		require.True(t, authTypeOK)
		require.True(t, credentialOK)
		require.Equal(t, "JWT", authType)
		require.Equal(t, token, credential)
		c.Status(http.StatusNoContent)
	})

	request := httptest.NewRequest(http.MethodGet, "/protected", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	require.Equal(t, http.StatusNoContent, response.Code)
}

func TestNewGinEnginePropagatesSourceHeader(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := newGinEngine(logrus.NewEntry(logrus.New()))
	router.GET("/source", func(c *gin.Context) {
		require.Equal(t, "service/ca", c.Request.Context().Value(core.LamassuContextKeySource))
		c.Status(http.StatusNoContent)
	})

	request := httptest.NewRequest(http.MethodGet, "/source", nil)
	request.Header.Set("x-lms-source", "service/ca")
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	require.Equal(t, http.StatusNoContent, response.Code)
}

func TestServerTLSConfigPreservesMutualTLSModes(t *testing.T) {
	logger := logrus.NewEntry(logrus.New())

	tests := []struct {
		name string
		mode string
		auth tls.ClientAuthType
	}{
		{name: "strict", mode: "strict", auth: tls.RequireAndVerifyClientCert},
		{name: "any", mode: "any", auth: tls.RequireAnyClientCert},
		{name: "request", mode: "request", auth: tls.RequestClientCert},
		{name: "empty defaults to strict", mode: "", auth: tls.RequireAndVerifyClientCert},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := cconfig.HttpServerAuthentication{}
			cfg.MutualTLS.Enabled = true
			cfg.MutualTLS.ValidationMode = cconfig.MutualTLSMode(tt.mode)

			tlsConfig := serverTLSConfig(logger, cfg)

			require.NotNil(t, tlsConfig)
			require.Equal(t, tt.auth, tlsConfig.ClientAuth)
			require.NotNil(t, tlsConfig.ClientCAs)
			require.Equal(t, uint16(tls.VersionTLS12), tlsConfig.MaxVersion)
		})
	}

	require.Nil(t, serverTLSConfig(logger, cconfig.HttpServerAuthentication{}))

	cfg := cconfig.HttpServerAuthentication{}
	cfg.MutualTLS.Enabled = true
	cfg.MutualTLS.ValidationMode = "unsupported"
	cfg.MutualTLS.CACertificateFile = t.TempDir() + "/missing-ca.pem"
	require.Equal(t, tls.RequireAndVerifyClientCert, serverTLSConfig(logger, cfg).ClientAuth)
}

func TestNewHTTPServerUsesBoundedTimeouts(t *testing.T) {
	server := newHTTPServer(logrus.NewEntry(logrus.New()), ":0", http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), cconfig.HttpServerAuthentication{})

	require.Equal(t, 10*time.Second, server.ReadTimeout)
	require.Equal(t, 10*time.Second, server.ReadHeaderTimeout)
	require.Equal(t, 10*time.Second, server.WriteTimeout)
}

func TestHealthHandlerPreservesBuildDetails(t *testing.T) {
	response := httptest.NewRecorder()
	info := models.APIServiceInfo{
		Version:   "v4.2.1",
		BuildSHA:  "abc123",
		BuildTime: "2026-11-04T10:00:00Z",
	}

	healthHandler(info)(response, httptest.NewRequest(http.MethodGet, "/health", nil))

	var body struct {
		Health    bool   `json:"health"`
		Version   string `json:"version"`
		Build     string `json:"build"`
		BuildTime string `json:"build_time"`
	}
	require.NoError(t, json.NewDecoder(response.Body).Decode(&body))
	require.Equal(t, http.StatusOK, response.Code)
	require.Equal(t, "application/json", response.Header().Get("Content-Type"))
	require.True(t, body.Health)
	require.Equal(t, info.Version, body.Version)
	require.Equal(t, info.BuildSHA, body.Build)
	require.Equal(t, info.BuildTime, body.BuildTime)
}

func TestHealthGinHandlerUsesAuthzHTTPMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := newGinEngine(logrus.NewEntry(logrus.New()))
	router.GET("/health", healthGinHandler(models.APIServiceInfo{Version: "v4.2.1"}))

	request := httptest.NewRequest(http.MethodGet, "/health", nil)
	request.Header.Set("Origin", "https://dashboard.example")
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	require.Equal(t, http.StatusOK, response.Code)
	require.Equal(t, "*", response.Header().Get("Access-Control-Allow-Origin"))
	require.Contains(t, response.Body.String(), `"health":true`)
}

func TestInjectVersionIntoOpenAPI(t *testing.T) {
	openAPI := []byte("openapi: 3.0.0\ninfo:\n  title: Authz\n  version: template\n")

	require.Contains(t, string(injectVersionIntoOpenAPI(openAPI, "v4.2.1")), "version: v4.2.1")
	require.Contains(t, string(injectVersionIntoOpenAPI(openAPI, "")), "version: template")
	require.Equal(t, "not yaml: [", string(injectVersionIntoOpenAPI([]byte("not yaml: ["), "v1")))
	require.Equal(t, "title: Authz\n", string(injectVersionIntoOpenAPI([]byte("title: Authz\n"), "v1")))
}

func TestOpenAPIGinHandlerServesDocument(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/openapi", openAPIGinHandler([]byte("openapi: 3.0.0\n")))
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/openapi", nil))
	require.Equal(t, http.StatusOK, response.Code)
	require.Equal(t, "application/yaml", response.Header().Get("Content-Type"))
	require.Contains(t, response.Body.String(), "openapi")
}

func TestRunHTTPRouterServesHealthAndOpenAPI(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg := cconfig.HttpServer{ListenAddress: "127.0.0.1", Port: 0, HealthCheckLogging: false}
	info := models.APIServiceInfo{Version: "v4.2.1"}
	port, err := runHTTPRouter(logrus.NewEntry(logrus.New()), http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), cfg, info, []byte("openapi: 3.0.0\ninfo:\n  version: template\n"))
	require.NoError(t, err)
	require.Positive(t, port)

	client := &http.Client{Timeout: time.Second}
	health, err := client.Get("http://127.0.0.1:" + strconv.Itoa(port) + "/health")
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, health.StatusCode)
	require.NoError(t, health.Body.Close())
	openAPI, err := client.Get("http://127.0.0.1:" + strconv.Itoa(port) + "/openapi")
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, openAPI.StatusCode)
	require.Contains(t, openAPI.Header.Get("Content-Type"), "application/yaml")
	require.NoError(t, openAPI.Body.Close())
}

func TestRunHTTPRouterRejectsInvalidHTTPSCredentials(t *testing.T) {
	cfg := cconfig.HttpServer{
		ListenAddress: "127.0.0.1",
		Port:          0,
		Protocol:      cconfig.HTTPS,
		CertFile:      t.TempDir() + "/missing-cert.pem",
		KeyFile:       t.TempDir() + "/missing-key.pem",
	}

	port, err := runHTTPRouter(logrus.NewEntry(logrus.New()), http.NewServeMux(), cfg, models.APIServiceInfo{}, nil)

	require.Error(t, err)
	require.Equal(t, -1, port)
	require.ErrorContains(t, err, "load HTTPS server certificate and key")
}
