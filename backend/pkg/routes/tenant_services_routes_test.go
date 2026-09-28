package routes

import (
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

func TestTenantServiceRoutesPublishVersionedContracts(t *testing.T) {
	gin.SetMode(gin.TestMode)

	deviceRoutes := registeredRoutes(func(group *gin.RouterGroup) {
		NewDeviceManagerHTTPLayer(group, nil)
	})
	assertV2RoutesMirrorV1(t, deviceRoutes)
	assertRoutes(t, deviceRoutes, []struct{ method, path string }{
		{method: "GET", path: "/v1/devices"},
		{method: "POST", path: "/v1/devices"},
		{method: "GET", path: "/v1/device-groups"},
		{method: "GET", path: "/api/v2/tenants/:tenantId/devices"},
		{method: "POST", path: "/api/v2/tenants/:tenantId/device-groups"},
	})

	dmsRoutes := registeredRoutes(func(group *gin.RouterGroup) {
		NewDMSManagerHTTPLayer(logrus.New().WithField("test", "routes"), group, nil)
	})
	assertV2RoutesMirrorV1(t, dmsRoutes)
	assertRoutes(t, dmsRoutes, []struct{ method, path string }{
		{method: "GET", path: "/v1/dms"},
		{method: "POST", path: "/v1/dms"},
		{method: "POST", path: "/v1/dms/bind-identity"},
		{method: "GET", path: "/api/v2/tenants/:tenantId/dms"},
		{method: "POST", path: "/api/v2/tenants/:tenantId/dms/bind-identity"},
	})

	vaRoutes := registeredRoutes(func(group *gin.RouterGroup) {
		NewValidationRoutes(logrus.New().WithField("test", "routes"), group, nil, nil)
	})
	assertV2RoutesMirrorV1(t, vaRoutes)
	assertRoutes(t, vaRoutes, []struct{ method, path string }{
		{method: "GET", path: "/ocsp/:ocsp_request"},
		{method: "POST", path: "/ocsp"},
		{method: "GET", path: "/crl/:ca-ski"},
		{method: "GET", path: "/v1/roles/:ca-ski"},
		{method: "PUT", path: "/api/v2/tenants/:tenantId/roles/:ca-ski"},
	})
	if _, ok := vaRoutes["GET /api/v2/tenants/:tenantId/ocsp/:ocsp_request"]; ok {
		t.Error("OCSP must remain outside administrative v2 routes")
	}

	alertRoutes := registeredRoutes(func(group *gin.RouterGroup) {
		NewAlertsHTTPLayer(group, nil)
	})
	assertV2RoutesMirrorV1(t, alertRoutes)
	assertRoutes(t, alertRoutes, []struct{ method, path string }{
		{method: "GET", path: "/v1/events/latest"},
		{method: "POST", path: "/v1/user/:userId/subscribe"},
		{method: "GET", path: "/api/v2/tenants/:tenantId/events/latest"},
		{method: "POST", path: "/api/v2/tenants/:tenantId/user/:userId/subscribe"},
	})
}
