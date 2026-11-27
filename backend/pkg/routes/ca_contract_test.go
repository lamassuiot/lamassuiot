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
	"github.com/lamassuiot/lamassuiot/v4/backend/pkg/config"
	tenantcontext "github.com/lamassuiot/lamassuiot/v4/backend/pkg/routes/middlewares/tenant-context"
	authzcore "github.com/lamassuiot/lamassuiot/v4/connectors/authz/pkg/core"
	middleware "github.com/lamassuiot/lamassuiot/v4/connectors/authz/sdk/gin-middleware"
	"github.com/lamassuiot/lamassuiot/v4/core"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCAOpenAPIContractCoversEveryEndpoint(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	// Client construction is local; this test never sends requests to authz or a CA.
	client := config.AuthzClient{Protocol: "http", BasePath: "/api/authz", Hostname: "localhost", Port: 8080}
	contracts := registerCARoutes(router.Group("/api/ca"), nil, newRemoteAuthzEngine(client, models.CASource, logrus.NewEntry(logrus.New())), logrus.NewEntry(logrus.New()))
	require.NotEmpty(t, contracts.v1.Declarations())
	require.NotEmpty(t, contracts.v2.Declarations())
	// Catch direct Gin registrations that bypass permission recording.
	require.NoError(t, contracts.v1.ValidateRoutes(router.Routes()))
	require.NoError(t, contracts.v2.ValidateRoutes(router.Routes()))
	assert.Equal(t, len(router.Routes()), len(contracts.v1.Declarations())+len(contracts.v2.Declarations()))
	assert.Equal(t, len(contracts.v1.Declarations()), len(contracts.v2.Declarations()))
	t.Logf("CA coverage: v1=%d, v2=%d (%d total routes)", len(contracts.v1.Declarations()), len(contracts.v2.Declarations()), len(router.Routes()))
	assert.Equal(t, middleware.RouteDeclaration{Method: http.MethodPost, Path: "/api/ca/v1/certificates", Authz: middleware.Declaration{Namespace: "pki", SchemaName: "ca", EntityType: "certificate", Action: "create"}}, certificateCreateDeclaration(t, contracts.v1))
	registered := false
	for _, route := range router.Routes() {
		if route.Method == http.MethodPost && route.Path == "/api/ca/v1/certificates" {
			registered = true
		}
	}
	assert.True(t, registered, "recorded contract must belong to the actual CA router")
	file, err := os.Open("../../../docs/specs/ca-openapi.yaml")
	require.NoError(t, err)
	defer file.Close()
	require.NoError(t, contracts.v1.ValidateOpenAPI(file))
}

// The CA key only signs through certificate issuance; the CA API exposes no arbitrary signing or verification with it.
func TestCARoutesDoNotExposeSignatureEndpoints(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	client := config.AuthzClient{Protocol: "http", BasePath: "/api/authz", Hostname: "localhost", Port: 8080}
	registerCARoutes(router.Group("/api/ca"), nil, newRemoteAuthzEngine(client, models.CASource, logrus.NewEntry(logrus.New())), logrus.NewEntry(logrus.New()))
	for _, route := range router.Routes() {
		assert.NotContains(t, route.Path, "/signature/", "%s %s must not be registered", route.Method, route.Path)
	}
}

func TestCreateCertificateContractDetectsAnOtherwiseValidWrongAction(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	client := config.AuthzClient{Protocol: "http", BasePath: "/api/authz", Hostname: "localhost", Port: 8080}
	contracts := registerCARoutes(router.Group("/api/ca"), nil, newRemoteAuthzEngine(client, models.CASource, logrus.NewEntry(logrus.New())), logrus.NewEntry(logrus.New()))
	spec, err := os.ReadFile("../../../docs/specs/ca-openapi.yaml")
	require.NoError(t, err)
	marker := "entity_type: certificate\n        action: create"
	require.Contains(t, string(spec), marker)
	wrong := strings.Replace(string(spec), marker, "entity_type: certificate\n        action: import", 1)
	err = contracts.v1.ValidateOpenAPI(strings.NewReader(wrong))
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
	tenantID    string
}

func (e *contractTestEngine) MatchAndAuthorize(ctx context.Context, authType, credential, namespace, schema, action, entity string, key map[string]string) (bool, []string, error) {
	e.calls++
	e.declaration = middleware.Declaration{Namespace: namespace, SchemaName: schema, EntityType: entity, Action: action}
	e.key = key
	e.tenantID, _ = ctx.Value(core.LamassuContextKeyTenantID).(string)
	return false, nil, nil
}

func (e *contractTestEngine) MatchAndGetFilter(ctx context.Context, authType, credential, namespace, schema, entity string) (string, []string, error) {
	e.calls++
	e.declaration = middleware.Declaration{Namespace: namespace, SchemaName: schema, EntityType: entity, Check: "filter"}
	e.key = nil
	e.tenantID, _ = ctx.Value(core.LamassuContextKeyTenantID).(string)
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
			contracts := registerCARoutes(router.Group("/api/ca"), nil, engine, logrus.NewEntry(logrus.New()))
			require.NoError(t, contracts.v1.ValidateRoutes(router.Routes()))
			require.NoError(t, contracts.v2.ValidateRoutes(router.Routes()))

			allRoutes := append(contracts.v1.Declarations(), contracts.v2.Declarations()...)
			for _, route := range allRoutes {
				t.Run(route.Method+" "+route.Path, func(t *testing.T) {
					engine.calls = 0
					engine.key = nil
					engine.tenantID = ""
					engine.declaration = middleware.Declaration{}
					isV2 := strings.Contains(route.Path, "/v2/tenants/:tenant_id/")
					expectedTenant := "tenant-a"
					if isV2 {
						expectedTenant = "tenant-v2"
					}
					requestPath := strings.NewReplacer(":tenant_id", expectedTenant, ":id", "ca-123", ":sn", "cert-456", ":status", "ACTIVE", ":cn", "example").Replace(route.Path)
					req := httptest.NewRequest(route.Method, requestPath, nil)
					if !isV2 {
						req.Header.Set(tenantcontext.HeaderTenantID, expectedTenant)
					}
					response := httptest.NewRecorder()
					router.ServeHTTP(response, req)
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
					assert.Equal(t, expectedTenant, engine.tenantID)
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
	contracts := registerCARoutes(router.Group("/api/ca"), nil, &contractTestEngine{}, logrus.NewEntry(logrus.New()))
	router.GET("/api/ca/v1/untracked", func(c *gin.Context) { c.Status(http.StatusOK) })
	err := contracts.v1.ValidateRoutes(router.Routes())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "GET /api/ca/v1/untracked")
}

func TestCARoutesEnforceTenantIDFromPathOrHeader(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("rejects v1 request without X-Tenant-ID before authz", func(t *testing.T) {
		router := gin.New()
		router.Use(func(c *gin.Context) {
			c.Set(core.LamassuContextKeyAuthType, "jwt")
			c.Set(core.LamassuContextKeyAuthCredentialString, "test-credential")
			c.Next()
		})
		engine := &contractTestEngine{}
		registerCARoutes(router.Group("/api/ca"), nil, engine, logrus.NewEntry(logrus.New()))

		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/ca/v1/cas/ca-123", nil))
		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Zero(t, engine.calls)
	})

	t.Run("accepts v2 tenant_id from path and rejects conflicting header", func(t *testing.T) {
		router := gin.New()
		router.Use(func(c *gin.Context) {
			c.Set(core.LamassuContextKeyAuthType, "jwt")
			c.Set(core.LamassuContextKeyAuthCredentialString, "test-credential")
			c.Next()
		})
		engine := &contractTestEngine{}
		registerCARoutes(router.Group("/api/ca"), nil, engine, logrus.NewEntry(logrus.New()))

		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/ca/v2/tenants/tenant-path/cas/ca-123", nil))
		assert.Equal(t, http.StatusForbidden, w.Code)
		assert.Equal(t, 1, engine.calls)
		assert.Equal(t, "tenant-path", engine.tenantID)

		engine.calls = 0
		engine.tenantID = ""
		conflictReq := httptest.NewRequest(http.MethodGet, "/api/ca/v2/tenants/tenant-path/cas/ca-123", nil)
		conflictReq.Header.Set(tenantcontext.HeaderTenantID, "tenant-other")
		wConflict := httptest.NewRecorder()
		router.ServeHTTP(wConflict, conflictReq)
		assert.Equal(t, http.StatusBadRequest, wConflict.Code)
		assert.Zero(t, engine.calls)
	})
}
