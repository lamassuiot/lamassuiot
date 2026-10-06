package routes

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	middleware "github.com/lamassuiot/authz/sdk/gin-middleware"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/controllers"
	cconfig "github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDeviceManagerOpenAPIContractCoversEveryEndpoint(t *testing.T) {
	for _, withSSE := range []bool{false, true} {
		t.Run(fmt.Sprintf("SSE=%v", withSSE), func(t *testing.T) {
			gin.SetMode(gin.TestMode)
			router := gin.New()
			logger := logrus.NewEntry(logrus.New())
			var hub *controllers.DeviceEventSSEHub
			if withSSE {
				hub = controllers.NewDeviceEventSSEHub(logger)
			}
			// Client and hub construction are local; no servers or devices are needed.
			client := config.AuthzClient{HTTPClient: cconfig.HTTPClient{HTTPConnection: cconfig.HTTPConnection{Protocol: "http", BasePath: "/api/authz", BasicConnection: cconfig.BasicConnection{Hostname: "localhost", Port: 8080}}}}
			contract := newDeviceManagerHTTPLayerWithSSE(router.Group("/api/devmanager"), nil, hub, client, logger)
			require.NotEmpty(t, contract.Declarations())
			require.NoError(t, contract.ValidateRoutes(router.Routes()))
			assert.Equal(t, len(router.Routes()), len(contract.Declarations()))
			file, err := os.Open("../specs/device-manager-openapi.yaml")
			require.NoError(t, err)
			defer file.Close()
			require.NoError(t, contract.ValidateOpenAPI(file))
			t.Logf("Device Manager coverage: %d/%d routes and OpenAPI operations", len(contract.Declarations()), len(router.Routes()))
		})
	}
}

func deviceManagerGuardRouter(authenticated, withSSE bool) (*gin.Engine, *middleware.ContractRouter, *contractTestEngine) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	if authenticated {
		router.Use(func(c *gin.Context) {
			c.Set("lamassu.io/ctx/auth-type", "jwt")
			c.Set("lamassu.io/ctx/auth-credential-string", "test-credential")
			c.Next()
		})
	}
	logger := logrus.NewEntry(logrus.New())
	var hub *controllers.DeviceEventSSEHub
	if withSSE {
		hub = controllers.NewDeviceEventSSEHub(logger)
	}
	engine := &contractTestEngine{}
	contract := registerDeviceManagerRoutes(router.Group("/api/devmanager"), nil, hub, engine, logger)
	return router, contract, engine
}

func TestDeviceManagerEveryEndpointRunsItsDeclaredGuard(t *testing.T) {
	for _, authenticated := range []bool{true, false} {
		t.Run(fmt.Sprintf("authenticated=%v", authenticated), func(t *testing.T) {
			router, contract, engine := deviceManagerGuardRouter(authenticated, false)
			require.NoError(t, contract.ValidateRoutes(router.Routes()))
			for _, route := range contract.Declarations() {
				t.Run(route.Method+" "+route.Path, func(t *testing.T) {
					engine.calls = 0
					engine.key = nil
					engine.declaration = middleware.Declaration{}
					id := "device-123"
					expectedEntity := "device"
					if strings.Contains(route.Path, "/device-groups") {
						id = "group-456"
						// Membership lists filter devices; other group endpoints check the group.
						if !strings.HasSuffix(route.Path, "/devices") {
							expectedEntity = "device_group"
						}
					} else if strings.Contains(route.Path, "/devices/dms/") {
						id = "dms-789"
					}
					requestPath := strings.ReplaceAll(route.Path, ":id", id)
					response := httptest.NewRecorder()
					router.ServeHTTP(response, httptest.NewRequest(route.Method, requestPath, nil))
					if !authenticated {
						assert.Equal(t, http.StatusUnauthorized, response.Code)
						assert.Zero(t, engine.calls)
						return
					}
					expectedStatus := http.StatusForbidden
					if route.Authz.Check == "filter" {
						expectedStatus = http.StatusInternalServerError
					}
					assert.Equal(t, expectedStatus, response.Code)
					assert.Equal(t, 1, engine.calls)
					assert.Equal(t, route.Authz, engine.declaration)
					assert.Equal(t, expectedEntity, engine.declaration.EntityType)
					var expectedKey map[string]string
					if route.Authz.Action != "create" && route.Authz.Check != "filter" {
						expectedKey = map[string]string{"id": id}
					}
					assert.Equal(t, expectedKey, engine.key)
				})
			}
		})
	}
}

func TestDeviceManagerEventsRequireDevicePermissionBeforeRESTOrSSE(t *testing.T) {
	for _, withSSE := range []bool{false, true} {
		for _, authenticated := range []bool{false, true} {
			for _, test := range []struct{ method, accept, action string }{
				{http.MethodGet, "application/json", "read"},
				{http.MethodGet, "text/event-stream", "read"},
				{http.MethodPost, "application/json", "metadata-update"},
			} {
				t.Run(fmt.Sprintf("SSE=%v/authenticated=%v/%s/%s", withSSE, authenticated, test.method, test.accept), func(t *testing.T) {
					router, _, engine := deviceManagerGuardRouter(authenticated, withSSE)
					request := httptest.NewRequest(test.method, "/api/devmanager/v1/devices/device-123/events", nil)
					request.Header.Set("Accept", test.accept)
					response := httptest.NewRecorder()
					router.ServeHTTP(response, request)
					if !authenticated {
						assert.Equal(t, http.StatusUnauthorized, response.Code)
						assert.Zero(t, engine.calls)
					} else {
						assert.Equal(t, http.StatusForbidden, response.Code)
						assert.Equal(t, 1, engine.calls)
						assert.Equal(t, middleware.Declaration{Namespace: "pki", SchemaName: "devicemanager", EntityType: "device", Action: test.action}, engine.declaration)
						assert.Equal(t, map[string]string{"id": "device-123"}, engine.key)
					}
					// Denial must happen before a stream opens, even when an SSE hub is available.
					assert.Contains(t, response.Header().Get("Content-Type"), "application/json")
				})
			}
		}
	}
}

func TestDeviceManagerContractDetectsDriftAndUntrackedRoutes(t *testing.T) {
	router, contract, _ := deviceManagerGuardRouter(false, false)
	spec, err := os.ReadFile("../specs/device-manager-openapi.yaml")
	require.NoError(t, err)
	for _, test := range []struct{ name, old, replacement, message string }{
		{"valid but wrong action", "action: provision", "action: read", "authz contract mismatch"},
		{"valid but wrong entity", "entity_type: device", "entity_type: device_group", "authz contract mismatch"},
		{"missing declaration", "x-authz:", "x-other:", "OpenAPI x-authz missing"},
	} {
		t.Run(test.name, func(t *testing.T) {
			require.Contains(t, string(spec), test.old)
			wrong := strings.Replace(string(spec), test.old, test.replacement, 1)
			err := contract.ValidateOpenAPI(strings.NewReader(wrong))
			require.Error(t, err)
			assert.Contains(t, err.Error(), test.message)
		})
	}
	router.GET("/api/devmanager/v1/untracked", func(*gin.Context) {})
	err = contract.ValidateRoutes(router.Routes())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "GET /api/devmanager/v1/untracked")
}
