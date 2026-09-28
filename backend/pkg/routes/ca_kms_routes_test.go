package routes

import (
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestCAAndKMSRoutesPublishV1AndTenantAwareV2Contracts(t *testing.T) {
	gin.SetMode(gin.TestMode)
	caRoutes := registeredRoutes(func(group *gin.RouterGroup) {
		NewCAHTTPLayer(group, nil)
	})
	kmsRoutes := registeredRoutes(func(group *gin.RouterGroup) {
		NewKMSHTTPLayer(group, nil)
	})
	assertV2RoutesMirrorV1(t, caRoutes)
	assertV2RoutesMirrorV1(t, kmsRoutes)

	assertRoutes(t, caRoutes, []struct {
		method string
		path   string
	}{
		{method: "GET", path: "/v1/cas"},
		{method: "POST", path: "/v1/cas"},
		{method: "GET", path: "/v1/certificates"},
		{method: "POST", path: "/v1/certificates"},
		{method: "GET", path: "/v1/profiles"},
		{method: "GET", path: "/v1/stats"},
		{method: "GET", path: "/api/v2/tenants/:tenantId/cas"},
		{method: "POST", path: "/api/v2/tenants/:tenantId/cas"},
		{method: "GET", path: "/api/v2/tenants/:tenantId/certificates"},
		{method: "POST", path: "/api/v2/tenants/:tenantId/certificates"},
		{method: "GET", path: "/api/v2/tenants/:tenantId/profiles"},
		{method: "GET", path: "/api/v2/tenants/:tenantId/stats"},
	})
	assertRoutes(t, kmsRoutes, []struct {
		method string
		path   string
	}{
		{method: "GET", path: "/v1/engines"},
		{method: "GET", path: "/v1/keys"},
		{method: "POST", path: "/v1/keys"},
		{method: "POST", path: "/v1/keys/:id/sign"},
		{method: "GET", path: "/api/v2/tenants/:tenantId/engines"},
		{method: "GET", path: "/api/v2/tenants/:tenantId/keys"},
		{method: "POST", path: "/api/v2/tenants/:tenantId/keys"},
		{method: "POST", path: "/api/v2/tenants/:tenantId/keys/:id/sign"},
	})
}

func registeredRoutes(register func(*gin.RouterGroup)) map[string]struct{} {
	router := gin.New()
	register(router.Group("/"))
	routes := make(map[string]struct{}, len(router.Routes()))
	for _, route := range router.Routes() {
		routes[route.Method+" "+route.Path] = struct{}{}
	}
	return routes
}

func assertRoutes(t *testing.T, routes map[string]struct{}, cases []struct{ method, path string }) {
	t.Helper()
	for _, testCase := range cases {
		if _, ok := routes[testCase.method+" "+testCase.path]; !ok {
			t.Errorf("missing route %s %s", testCase.method, testCase.path)
		}
	}
}

func assertV2RoutesMirrorV1(t *testing.T, routes map[string]struct{}) {
	t.Helper()
	for route := range routes {
		method, path, ok := strings.Cut(route, " ")
		if !ok || (path != "/v1" && !strings.HasPrefix(path, "/v1/")) {
			continue
		}
		v2Path := "/api/v2/tenants/:tenantId" + strings.TrimPrefix(path, "/v1")
		if _, ok := routes[method+" "+v2Path]; !ok {
			t.Errorf("missing v2 counterpart for %s", route)
		}
	}
}
