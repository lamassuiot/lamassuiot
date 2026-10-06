package routes

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	authzcore "github.com/lamassuiot/authz/pkg/core"
	middleware "github.com/lamassuiot/authz/sdk/gin-middleware"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/config"
	cconfig "github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCAOpenAPIContractCoversEveryEndpoint(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	// Client construction is local; this test never sends requests to authz or a CA.
	client := config.AuthzClient{HTTPClient: cconfig.HTTPClient{HTTPConnection: cconfig.HTTPConnection{Protocol: "http", BasePath: "/api/authz", BasicConnection: cconfig.BasicConnection{Hostname: "localhost", Port: 8080}}}}
	contract := newCAHTTPLayer(router.Group("/api/ca"), nil, client, logrus.NewEntry(logrus.New()))
	require.NotEmpty(t, contract.Declarations())
	// Catch direct Gin registrations that bypass permission recording.
	require.NoError(t, contract.ValidateRoutes(router.Routes()))
	assert.Equal(t, len(router.Routes()), len(contract.Declarations()))
	t.Logf("CA coverage: %d/%d routes and OpenAPI operations", len(contract.Declarations()), len(router.Routes()))
	assert.Equal(t, middleware.RouteDeclaration{Method: http.MethodPost, Path: "/api/ca/v1/certificates", Authz: middleware.Declaration{Namespace: "pki", SchemaName: "ca", EntityType: "certificate", Action: "create"}}, certificateCreateDeclaration(t, contract))
	registered := false
	for _, route := range router.Routes() {
		if route.Method == http.MethodPost && route.Path == "/api/ca/v1/certificates" {
			registered = true
		}
	}
	assert.True(t, registered, "recorded contract must belong to the actual CA router")
	file, err := os.Open("../specs/ca-openapi.yaml")
	require.NoError(t, err)
	defer file.Close()
	require.NoError(t, contract.ValidateOpenAPI(file))
}

func TestCreateCertificateContractDetectsAnOtherwiseValidWrongAction(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	client := config.AuthzClient{HTTPClient: cconfig.HTTPClient{HTTPConnection: cconfig.HTTPConnection{Protocol: "http", BasePath: "/api/authz", BasicConnection: cconfig.BasicConnection{Hostname: "localhost", Port: 8080}}}}
	contract := newCAHTTPLayer(router.Group("/api/ca"), nil, client, logrus.NewEntry(logrus.New()))
	spec, err := os.ReadFile("../specs/ca-openapi.yaml")
	require.NoError(t, err)
	marker := "entity_type: certificate\n        action: create"
	require.Contains(t, string(spec), marker)
	wrong := strings.Replace(string(spec), marker, "entity_type: certificate\n        action: import", 1)
	err = contract.ValidateOpenAPI(strings.NewReader(wrong))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "authz contract mismatch for POST /api/ca/v1/certificates")
}

func certificateCreateDeclaration(t *testing.T, contract *middleware.ContractRouter) middleware.RouteDeclaration {
	t.Helper()
	for _, declaration := range contract.Declarations() {
		if declaration.Method == http.MethodPost && declaration.Path == "/api/ca/v1/certificates" {
			return declaration
		}
	}
	t.Fatal("certificate-create contract missing")
	return middleware.RouteDeclaration{}
}

// Embedding the interface makes unexpected calls to the unused methods fail loudly.
// This fake tests guard wiring, not policies or live service behavior.
type contractTestEngine struct {
	authzcore.AuthzEngine
	calls       int
	declaration middleware.Declaration
	key         map[string]string
}

func (e *contractTestEngine) MatchAndAuthorize(_ context.Context, authType, credential, namespace, schema, action, entity string, key map[string]string) (bool, []string, error) {
	e.calls++
	e.declaration = middleware.Declaration{Namespace: namespace, SchemaName: schema, EntityType: entity, Action: action}
	e.key = key
	return false, nil, nil
}

func (e *contractTestEngine) MatchAndGetFilter(_ context.Context, authType, credential, namespace, schema, entity string) (string, []string, error) {
	e.calls++
	e.declaration = middleware.Declaration{Namespace: namespace, SchemaName: schema, EntityType: entity, Check: "filter"}
	e.key = nil
	return "", nil, fmt.Errorf("test authorization service unavailable")
}

func TestCAEveryEndpointRunsItsDeclaredGuard(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, authenticated := range []bool{true, false} {
		t.Run(fmt.Sprintf("authenticated=%v", authenticated), func(t *testing.T) {
			router := gin.New()
			if authenticated {
				router.Use(func(c *gin.Context) {
					c.Set("lamassu.io/ctx/auth-type", "jwt")
					c.Set("lamassu.io/ctx/auth-credential-string", "test-credential")
					c.Next()
				})
			}
			engine := &contractTestEngine{}
			contract := registerCARoutes(router.Group("/api/ca"), nil, engine, logrus.NewEntry(logrus.New()))
			require.NoError(t, contract.ValidateRoutes(router.Routes()))
			for _, route := range contract.Declarations() {
				t.Run(route.Method+" "+route.Path, func(t *testing.T) {
					engine.calls = 0
					engine.key = nil
					engine.declaration = middleware.Declaration{}
					requestPath := strings.NewReplacer(":id", "ca-123", ":sn", "cert-456", ":status", "ACTIVE", ":cn", "example").Replace(route.Path)
					response := httptest.NewRecorder()
					router.ServeHTTP(response, httptest.NewRequest(route.Method, requestPath, nil))
					if !authenticated {
						assert.Equal(t, http.StatusUnauthorized, response.Code)
						assert.Zero(t, engine.calls)
						return
					}
					// Permission checks deny with 403; failed filter computation stops with 500.
					// Controllers receive no request, so no CA service or fixtures are needed.
					expectedStatus := http.StatusForbidden
					if route.Authz.Check == "filter" {
						expectedStatus = http.StatusInternalServerError
					}
					assert.Equal(t, expectedStatus, response.Code)
					assert.Equal(t, 1, engine.calls)
					assert.Equal(t, route.Authz, engine.declaration)
					var expectedKey map[string]string
					if route.Authz.Action != "create" && route.Authz.Action != "import" && route.Authz.Check != "filter" {
						expectedKey = map[string]string{"id": "ca-123"}
						if route.Authz.EntityType == "certificate" {
							expectedKey = map[string]string{"serial_number": "cert-456"}
						}
					}
					assert.Equal(t, expectedKey, engine.key)
				})
			}
		})
	}
}

func TestCAContractDetectsRouteOutsideContract(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	contract := registerCARoutes(router.Group("/api/ca"), nil, &contractTestEngine{}, logrus.NewEntry(logrus.New()))
	router.GET("/api/ca/v1/untracked", func(c *gin.Context) { c.Status(http.StatusOK) })
	err := contract.ValidateRoutes(router.Routes())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "GET /api/ca/v1/untracked")
}
