package routes

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	middleware "github.com/lamassuiot/authz/sdk/gin-middleware"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/config"
	cconfig "github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ocsp"
)

func TestVAOpenAPIContractCoversEveryEndpoint(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	client := config.AuthzClient{HTTPClient: cconfig.HTTPClient{HTTPConnection: cconfig.HTTPConnection{Protocol: "http", BasePath: "/api/authz", BasicConnection: cconfig.BasicConnection{Hostname: "localhost", Port: 8080}}}}
	logger := logrus.NewEntry(logrus.New())
	contract := registerVARoutes(logger, router.Group("/api/va"), nil, nil, newRemoteAuthzEngine(client, models.VASource, logger))
	require.NotEmpty(t, contract.Declarations())
	require.NoError(t, contract.ValidateRoutes(router.Routes()))
	assert.Equal(t, len(router.Routes()), len(contract.Declarations()))
	public, protected := 0, 0
	for _, route := range contract.Declarations() {
		if route.Authz.Check == "public" {
			public++
		} else {
			protected++
		}
	}
	assert.Equal(t, 3, public)
	assert.Equal(t, 2, protected)
	spec, err := os.Open("../specs/va-openapi.yaml")
	require.NoError(t, err)
	defer spec.Close()
	require.NoError(t, contract.ValidateOpenAPI(spec))
	t.Logf("VA coverage: %d/%d routes and OpenAPI operations (%d public, %d protected)", len(contract.Declarations()), len(router.Routes()), public, protected)
}

func TestVAProtectedEndpointsRunTheirDeclaredGuard(t *testing.T) {
	for _, authenticated := range []bool{true, false} {
		t.Run(fmt.Sprintf("authenticated=%v", authenticated), func(t *testing.T) {
			gin.SetMode(gin.TestMode)
			router := gin.New()
			if authenticated {
				router.Use(func(c *gin.Context) {
					c.Set("lamassu.io/ctx/auth-type", "jwt")
					c.Set("lamassu.io/ctx/auth-credential-string", "test-credential")
					c.Next()
				})
			}
			engine := &contractTestEngine{}
			contract := registerVARoutes(logrus.NewEntry(logrus.New()), router.Group("/api/va"), nil, nil, engine)
			for _, route := range contract.Declarations() {
				if route.Authz.Check == "public" {
					continue
				}
				t.Run(route.Method+" "+route.Path, func(t *testing.T) {
					engine.calls = 0
					requestPath := strings.ReplaceAll(route.Path, ":ca-ski", "ca-123")
					response := httptest.NewRecorder()
					router.ServeHTTP(response, httptest.NewRequest(route.Method, requestPath, nil))
					if !authenticated {
						assert.Equal(t, http.StatusUnauthorized, response.Code)
						assert.Zero(t, engine.calls)
						return
					}
					assert.Equal(t, http.StatusForbidden, response.Code)
					assert.Equal(t, 1, engine.calls)
					assert.Equal(t, route.Authz, engine.declaration)
					assert.Equal(t, map[string]string{"ca_ski": "ca-123"}, engine.key)
				})
			}
		})
	}
}

// Public tests reach the actual controllers with small service fakes.
type publicOCSPService struct {
	calls  int
	serial *big.Int
}

func (s *publicOCSPService) Verify(_ context.Context, request *ocsp.Request) ([]byte, error) {
	s.calls++
	s.serial = request.SerialNumber
	return []byte("test-ocsp-response"), nil
}

type publicCRLService struct {
	services.CRLService
	calls int
	input services.GetCRLInput
}

func (s *publicCRLService) GetCRL(_ context.Context, input services.GetCRLInput) (*x509.RevocationList, error) {
	s.calls++
	s.input = input
	return &x509.RevocationList{Raw: []byte("test-crl-response")}, nil
}

func TestVAPublicEndpointsWorkWithoutAuthenticationOrAuthz(t *testing.T) {
	// OCSP requests need issuer metadata, but no certificate signing or private key.
	publicKey, err := x509.MarshalPKIXPublicKey(ed25519.PublicKey(make([]byte, ed25519.PublicKeySize)))
	require.NoError(t, err)
	issuer := &x509.Certificate{RawSubject: []byte{0x30, 0}, RawSubjectPublicKeyInfo: publicKey}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(42)}
	requestDER, err := ocsp.CreateRequest(leaf, issuer, nil)
	require.NoError(t, err)
	gin.SetMode(gin.TestMode)
	router := gin.New() // No authentication context or JWT.
	engine := &contractTestEngine{}
	ocspService := &publicOCSPService{}
	crlService := &publicCRLService{}
	contract := registerVARoutes(logrus.NewEntry(logrus.New()), router.Group("/api/va"), ocspService, crlService, engine)
	require.NoError(t, contract.ValidateRoutes(router.Routes()))
	for _, route := range contract.Declarations() {
		if route.Authz.Check != "public" {
			continue
		}
		t.Run(route.Method+" "+route.Path, func(t *testing.T) {
			ocspService.calls, crlService.calls = 0, 0
			requestPath := strings.NewReplacer(":ocsp_request", base64.URLEncoding.EncodeToString(requestDER), ":ca-ski", "ca-123").Replace(route.Path)
			request := httptest.NewRequest(route.Method, requestPath, bytes.NewReader(requestDER))
			request.Header.Set("Content-Type", "application/ocsp-request")
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			assert.Equal(t, http.StatusOK, response.Code)
			assert.Zero(t, engine.calls, "public endpoints must never call authz")
			if strings.Contains(route.Path, "/ocsp") {
				assert.Equal(t, 1, ocspService.calls)
				assert.Zero(t, crlService.calls)
				assert.Equal(t, big.NewInt(42), ocspService.serial)
				assert.Equal(t, "application/ocsp-response", response.Header().Get("Content-Type"))
				assert.Equal(t, "test-ocsp-response", response.Body.String())
			} else {
				assert.Equal(t, 1, crlService.calls)
				assert.Zero(t, ocspService.calls)
				assert.Equal(t, "ca-123", crlService.input.CASubjectKeyID)
				assert.Equal(t, "application/pkix-crl", response.Header().Get("Content-Type"))
				assert.Equal(t, "test-crl-response", response.Body.String())
			}
		})
	}
}

func TestVAContractDetectsPublicSecurityDriftAndUntrackedRoutes(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	contract := registerVARoutes(logrus.NewEntry(logrus.New()), router.Group("/api/va"), nil, nil, &contractTestEngine{})
	spec, err := os.ReadFile("../specs/va-openapi.yaml")
	require.NoError(t, err)
	for _, test := range []struct{ name, old, replacement, message string }{
		{"wrong base", "url: /api/va", "url: /api/va/v1", "does not match OpenAPI server"},
		{"public requires authentication", "security: []", "security: [{BearerAuth: []}]", "must explicitly declare security: []"},
		{"missing public declaration", "check: public", "check: filter", "authz contract mismatch"},
		{"role uses wrong action", "action: read", "action: update", "authz contract mismatch"},
	} {
		t.Run(test.name, func(t *testing.T) {
			require.Contains(t, string(spec), test.old)
			wrong := strings.Replace(string(spec), test.old, test.replacement, 1)
			err := contract.ValidateOpenAPI(strings.NewReader(wrong))
			require.Error(t, err)
			assert.Contains(t, err.Error(), test.message)
		})
	}
	router.GET("/api/va/untracked", func(*gin.Context) {})
	err = contract.ValidateRoutes(router.Routes())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "GET /api/va/untracked")
	assert.Equal(t, middleware.Declaration{Check: "public"}, contract.Declarations()[0].Authz)
}
