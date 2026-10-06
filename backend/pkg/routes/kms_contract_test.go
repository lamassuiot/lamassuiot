package routes

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
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
)

func TestKMSOpenAPIContractCoversEveryEndpoint(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	// Construct the production router without contacting an authz service.
	client := config.AuthzClient{HTTPClient: cconfig.HTTPClient{HTTPConnection: cconfig.HTTPConnection{Protocol: "http", BasePath: "/api/authz", BasicConnection: cconfig.BasicConnection{Hostname: "localhost", Port: 8080}}}}
	contract := newKMSHTTPLayer(router.Group("/api/kms"), nil, client, logrus.NewEntry(logrus.New()))
	require.NotEmpty(t, contract.Declarations())
	require.NoError(t, contract.ValidateRoutes(router.Routes()))
	assert.Equal(t, len(router.Routes()), len(contract.Declarations()))
	spec, err := os.Open("../specs/kms-openapi.yaml")
	require.NoError(t, err)
	defer spec.Close()
	require.NoError(t, contract.ValidateOpenAPI(spec))
	t.Logf("KMS coverage: %d/%d routes and OpenAPI operations", len(contract.Declarations()), len(router.Routes()))
}

// Only alias lookup is implemented: reaching a business handler fails the test.
type kmsAliasService struct {
	services.KMSService
	key     *models.Key
	err     error
	lookups []string
}

func (s *kmsAliasService) GetKey(_ context.Context, input services.GetKeyInput) (*models.Key, error) {
	s.lookups = append(s.lookups, input.Identifier)
	return s.key, s.err
}

func kmsGuardRouter(authenticated bool, svc services.KMSService) (*gin.Engine, *middleware.ContractRouter, *contractTestEngine) {
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
	contract := registerKMSRoutes(router.Group("/api/kms"), svc, engine, logrus.NewEntry(logrus.New()))
	return router, contract, engine
}

func TestKMSEveryEndpointRunsItsDeclaredGuard(t *testing.T) {
	for _, test := range []struct {
		name, identifier, engineID string
		authenticated, alias       bool
	}{
		{name: "unauthenticated", identifier: "my-key"},
		{name: "uri/engine-1", identifier: "pkcs11:token-id=engine-1;id=shared-key", engineID: "engine-1", authenticated: true},
		{name: "uri/engine-2", identifier: "pkcs11:token-id=engine-2;id=shared-key", engineID: "engine-2", authenticated: true},
		{name: "alias", identifier: "my-key", engineID: "engine-1", authenticated: true, alias: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			svc := &kmsAliasService{key: &models.Key{KeyID: "shared-key", EngineID: test.engineID}}
			router, contract, engine := kmsGuardRouter(test.authenticated, svc)
			require.NoError(t, contract.ValidateRoutes(router.Routes()))
			for _, route := range contract.Declarations() {
				t.Run(route.Method+" "+route.Path, func(t *testing.T) {
					engine.calls = 0
					engine.key = nil
					engine.declaration = middleware.Declaration{}
					svc.lookups = nil
					requestPath := strings.ReplaceAll(route.Path, ":id", url.PathEscape(test.identifier))
					response := httptest.NewRecorder()
					router.ServeHTTP(response, httptest.NewRequest(route.Method, requestPath, nil))
					if !test.authenticated {
						assert.Equal(t, http.StatusUnauthorized, response.Code)
						assert.Zero(t, engine.calls)
						assert.Empty(t, svc.lookups, "authentication precedes alias resolution")
						return
					}
					expectedStatus := http.StatusForbidden
					if route.Authz.Check == "filter" {
						expectedStatus = http.StatusInternalServerError
					}
					assert.Equal(t, expectedStatus, response.Code)
					assert.Equal(t, 1, engine.calls)
					assert.Equal(t, route.Authz, engine.declaration)
					resource := strings.Contains(route.Path, ":id")
					var expectedKey map[string]string
					if resource {
						expectedKey = map[string]string{"key_id": "shared-key", "engine_id": test.engineID}
					}
					assert.Equal(t, expectedKey, engine.key, "identical key IDs in different engines must remain distinct")
					if resource && test.alias {
						assert.Equal(t, []string{test.identifier}, svc.lookups)
					} else {
						assert.Empty(t, svc.lookups)
					}
				})
			}
		})
	}
}

func TestKMSResourceResolutionFailuresStopBeforeAuthorization(t *testing.T) {
	for _, test := range []struct {
		name, identifier string
		lookupError      error
		key              *models.Key
		status           int
		alias            bool
	}{
		{name: "malformed URI", identifier: "pkcs11:broken", status: http.StatusBadRequest},
		{name: "missing key ID", identifier: "pkcs11:token-id=engine-1", status: http.StatusBadRequest},
		{name: "missing engine ID", identifier: "pkcs11:id=shared-key", status: http.StatusBadRequest},
		{name: "empty key ID", identifier: "pkcs11:token-id=engine-1;id=", status: http.StatusBadRequest},
		{name: "empty engine ID", identifier: "pkcs11:token-id=;id=shared-key", status: http.StatusBadRequest},
		{name: "unknown alias", identifier: "my-key", lookupError: errors.New("key not found"), status: http.StatusForbidden, alias: true},
		{name: "ambiguous alias", identifier: "my-key", lookupError: errors.New("key exists in multiple engines"), status: http.StatusForbidden, alias: true},
		{name: "incomplete resolved key", identifier: "my-key", key: &models.Key{KeyID: "shared-key"}, status: http.StatusBadRequest, alias: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			svc := &kmsAliasService{key: test.key, err: test.lookupError}
			router, contract, engine := kmsGuardRouter(true, svc)
			for _, route := range contract.Declarations() {
				if !strings.Contains(route.Path, ":id") {
					continue
				}
				t.Run(route.Method+" "+route.Path, func(t *testing.T) {
					svc.lookups = nil
					response := httptest.NewRecorder()
					requestPath := strings.ReplaceAll(route.Path, ":id", url.PathEscape(test.identifier))
					router.ServeHTTP(response, httptest.NewRequest(route.Method, requestPath, nil))
					assert.Equal(t, test.status, response.Code)
					assert.Zero(t, engine.calls, "a failed resolver must never authorize a partial key")
					if test.alias {
						assert.Equal(t, []string{test.identifier}, svc.lookups)
					} else {
						assert.Empty(t, svc.lookups)
					}
					if test.lookupError != nil {
						assert.JSONEq(t, `{"err":"Access denied"}`, response.Body.String(), "lookup failures must not reveal key existence")
					}
				})
			}
		})
	}
}

func TestKMSContractDetectsDriftAndUntrackedRoutes(t *testing.T) {
	router, contract, _ := kmsGuardRouter(false, nil)
	spec, err := os.ReadFile("../specs/kms-openapi.yaml")
	require.NoError(t, err)
	require.Contains(t, string(spec), "action: sign")
	// Delete is valid in the domain, but differs from the signing endpoint's guard.
	wrong := strings.Replace(string(spec), "action: sign", "action: delete", 1)
	err = contract.ValidateOpenAPI(strings.NewReader(wrong))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "authz contract mismatch for POST /api/kms/v1/keys/:id/sign")
	router.GET("/api/kms/v1/untracked", func(*gin.Context) {})
	err = contract.ValidateRoutes(router.Routes())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "GET /api/kms/v1/untracked")
}
