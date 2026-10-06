package routes

import (
	"github.com/gin-gonic/gin"
	authzcore "github.com/lamassuiot/authz/pkg/core"
	middleware "github.com/lamassuiot/authz/sdk/gin-middleware"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/controllers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	"github.com/sirupsen/logrus"
)

func NewDeviceManagerHTTPLayer(router *gin.RouterGroup, svc services.DeviceManagerService, authzConf config.AuthzClient, logger *logrus.Entry) {
	NewDeviceManagerHTTPLayerWithSSE(router, svc, nil, authzConf, logger)
}

func NewDeviceManagerHTTPLayerWithSSE(router *gin.RouterGroup, svc services.DeviceManagerService, sseHub *controllers.DeviceEventSSEHub, authzConf config.AuthzClient, logger *logrus.Entry) {
	registerDeviceManagerRoutes(router, svc, sseHub, newRemoteAuthzEngine(authzConf, models.DeviceManagerSource, logger), logger)
}

// REST and SSE requests share the same validated device permissions.
func registerDeviceManagerRoutes(router *gin.RouterGroup, svc services.DeviceManagerService, sseHub *controllers.DeviceEventSSEHub, engine authzcore.AuthzEngine, logger *logrus.Entry) *middleware.ContractRouter {
	routes := controllers.NewDeviceManagerHttpRoutesWithSSE(svc, sseHub)
	authzMw := pkiAuthz(engine, "devicemanager", "device", logger)
	deviceGroupAuthzMw := pkiAuthz(engine, "devicemanager", "device_group", logger)
	idKey := map[string]string{"id": "id"}

	rv1 := middleware.NewContractRouter(router.Group("/v1"))

	rv1.GET("/stats", authzMw.List(), routes.GetStats)
	rv1.GET("/devices", authzMw.List(), routes.GetAllDevices)
	rv1.POST("/devices", authzMw.Global("create"), routes.CreateDevice)
	rv1.GET("/devices/:id", authzMw.Resource("read", idKey), routes.GetDeviceByID)
	rv1.GET("/devices/:id/events", authzMw.Resource("read", idKey), routes.GetDeviceEvents)
	rv1.POST("/devices/:id/events", authzMw.Resource("metadata-update", idKey), routes.CreateDeviceEvent)
	rv1.DELETE("/devices/:id", authzMw.Resource("delete", idKey), routes.DeleteDevice)
	rv1.PUT("/devices/:id/idslot", authzMw.Resource("provision", idKey), routes.UpdateDeviceIdentitySlot)
	rv1.PUT("/devices/:id/metadata", authzMw.Resource("metadata-update", idKey), routes.UpdateDeviceMetadata)
	rv1.PATCH("/devices/:id/metadata", authzMw.Resource("metadata-update", idKey), routes.UpdateDeviceMetadata)
	rv1.DELETE("/devices/:id/decommission", authzMw.Resource("decommission", idKey), routes.DecommissionDevice)
	rv1.GET("/devices/dms/:id", authzMw.List(), routes.GetDevicesByDMS)

	// Device Groups routes
	rv1.POST("/device-groups", deviceGroupAuthzMw.Global("create"), routes.CreateDeviceGroup)
	rv1.GET("/device-groups", deviceGroupAuthzMw.List(), routes.GetAllDeviceGroups)
	rv1.GET("/device-groups/:id", deviceGroupAuthzMw.Resource("read", idKey), routes.GetDeviceGroupByID)
	rv1.PUT("/device-groups/:id", deviceGroupAuthzMw.Resource("update", idKey), routes.UpdateDeviceGroup)
	rv1.DELETE("/device-groups/:id", deviceGroupAuthzMw.Resource("delete", idKey), routes.DeleteDeviceGroup)
	rv1.GET("/device-groups/:id/devices", authzMw.List(), routes.GetDevicesByGroup)
	rv1.GET("/device-groups/:id/stats", deviceGroupAuthzMw.Resource("read", idKey), routes.GetDeviceGroupStats)
	return rv1
}
