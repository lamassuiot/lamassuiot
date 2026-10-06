package api

import (
	"context"
	"fmt"
	"github.com/gin-gonic/gin"
	authzcore "github.com/lamassuiot/authz/pkg/core"
	authzengine "github.com/lamassuiot/authz/pkg/engine"
	"github.com/lamassuiot/authz/pkg/models"
	"github.com/lamassuiot/authz/pkg/service"
	middleware "github.com/lamassuiot/authz/sdk/gin-middleware"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

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

func TestAuthzOpenAPIAndEveryRegisteredGuard(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, authenticated := range []bool{false, true} {
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
			eng, err := authzengine.NewEngine(nil, nil)
			require.NoError(t, err)
			contract := registerAuthzRoutes(router.Group("/api/authz"), engine, nil, eng, nil, nil, logrus.NewEntry(logrus.New()))
			require.Len(t, contract.Declarations(), 44)
			require.NoError(t, contract.ValidateRoutes(router.Routes()))
			spec, err := os.ReadFile("../specs/authz-openapi.yaml")
			require.NoError(t, err)
			require.NoError(t, contract.ValidateOpenAPI(strings.NewReader(string(spec))))
			for _, route := range contract.Declarations() {
				t.Run(route.Method+" "+route.Path, func(t *testing.T) {
					engine.calls = 0
					path := strings.NewReplacer(":id", "principal-123", ":policyId", "policy-456", "*original_url", "devices/device-001").Replace(route.Path)
					response := httptest.NewRecorder()
					router.ServeHTTP(response, httptest.NewRequest(route.Method, path, nil))
					if route.Authz.Check == "envoy" {
						assert.Equal(t, 403, response.Code)
						assert.Zero(t, engine.calls)
						return
					}
					if route.Authz.Check == "evaluation" {
						assert.Equal(t, 400, response.Code)
						assert.Zero(t, engine.calls)
						return
					}
					if route.Authz.Check == "public" {
						assert.Equal(t, 200, response.Code)
						assert.Zero(t, engine.calls)
						return
					}
					if !authenticated {
						assert.Equal(t, 401, response.Code)
						assert.Zero(t, engine.calls)
						return
					}
					status := 403
					if route.Authz.Check == "filter" {
						status = 500
					}
					assert.Equal(t, status, response.Code)
					require.Equal(t, 1, engine.calls)
					assert.Equal(t, route.Authz, engine.declaration)
					var key map[string]string
					if route.Authz.EntityType != "principal_policy" && route.Authz.Action != "create" && route.Authz.Check != "filter" {
						key = map[string]string{"id": "principal-123"}
					}
					assert.Equal(t, key, engine.key)
				})
			}
			router.GET("/api/authz/v1/untracked", func(c *gin.Context) {})
			assert.Error(t, contract.ValidateRoutes(router.Routes()))
		})
	}
}

func TestEveryEnvoyContractRouteEvaluatesHTTPPolicies(t *testing.T) {
	gin.SetMode(gin.TestMode)
	eng, err := authzengine.NewEngine(nil, nil, authzengine.WithHTTPSchemas([]string{writeExtAuthzHTTPSchema(t)}))
	require.NoError(t, err)
	policy := &models.Policy{ID: "policy-1", Name: "Policy 1", HTTPRules: []*models.HTTPRule{{SchemaName: "test-http", Actions: []string{"resource-read"}}}}
	resolver := service.NewIdentityResolver(testPrincipalMatcher{}, testGrantStore{}, testPolicyLoader{policy: policy})
	router := gin.New()
	contract := registerAuthzRoutes(router.Group("/api/authz"), &contractTestEngine{}, nil, eng, nil, resolver, logrus.NewEntry(logrus.New()))
	for _, route := range contract.Declarations() {
		if route.Authz.Check != "envoy" {
			continue
		}
		for _, credential := range []string{"Bearer good", "Bearer unmatched"} {
			t.Run(route.Method+" "+route.Path+"/"+credential, func(t *testing.T) {
				request := httptest.NewRequest(route.Method, strings.ReplaceAll(route.Path, "*original_url", "api/v1/resource"), nil)
				request.Header.Set("Authorization", credential)
				request.Header.Set("x-envoy-original-path", "/api/v1/resource")
				response := httptest.NewRecorder()
				router.ServeHTTP(response, request)
				status := http.StatusForbidden
				if credential == "Bearer good" && route.Method == http.MethodGet {
					status = http.StatusOK
				}
				assert.Equal(t, status, response.Code)
			})
		}
	}
}
