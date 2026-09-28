package routes

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	cconfig "github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/sirupsen/logrus"
)

func TestRunHttpRouterRejectsStrictMutualTLSWithoutHTTPS(t *testing.T) {
	_, err := RunHttpRouter(logrus.NewEntry(logrus.New()), nil, cconfig.HttpServer{
		Protocol: cconfig.HTTP,
		Authentication: cconfig.HttpServerAuthentication{
			MutualTLS: cconfig.HttpServerMutualTLSAuthentication{
				Enabled:        true,
				ValidationMode: cconfig.Strict,
			},
		},
	}, models.APIServiceInfo{})
	if err == nil {
		t.Fatal("expected strict mutual TLS over plain HTTP to be rejected before listening")
	}
}

func TestNewGinEngineDoesNotAllowUnconfiguredCrossOriginRequests(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := NewGinEngine(logrus.NewEntry(logrus.New()))
	router.GET("/", func(ctx *gin.Context) { ctx.Status(http.StatusNoContent) })
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("Origin", "https://untrusted.example")
	record := httptest.NewRecorder()
	router.ServeHTTP(record, request)

	if record.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("unexpected CORS permission for unconfigured origin: %q", record.Header().Get("Access-Control-Allow-Origin"))
	}
}

func TestNewGinEngineWithCORSAllowsOnlyConfiguredOrigins(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := NewGinEngineWithCORS(logrus.NewEntry(logrus.New()), []string{"https://dashboard.example"})
	router.GET("/", func(ctx *gin.Context) { ctx.Status(http.StatusNoContent) })
	for _, testCase := range []struct {
		origin string
		want   string
	}{
		{origin: "https://dashboard.example", want: "https://dashboard.example"},
		{origin: "https://untrusted.example", want: ""},
	} {
		request := httptest.NewRequest(http.MethodGet, "/", nil)
		request.Header.Set("Origin", testCase.origin)
		record := httptest.NewRecorder()
		router.ServeHTTP(record, request)
		if actual := record.Header().Get("Access-Control-Allow-Origin"); actual != testCase.want {
			t.Errorf("origin %q: expected allow-origin %q, got %q", testCase.origin, testCase.want, actual)
		}
	}
}

func TestHTTPServerRejectsWildcardCORSOrigin(t *testing.T) {
	for _, origin := range []string{"*", "https://*.example.com"} {
		t.Run(origin, func(t *testing.T) {
			err := validateHTTPServerSecurity(cconfig.HttpServer{CORSAllowedOrigins: []string{origin}})
			if err == nil {
				t.Fatalf("expected wildcard CORS origin %q to be rejected", origin)
			}
		})
	}
}
