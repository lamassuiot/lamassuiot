package routes

import (
	"net/http"

	"github.com/gin-gonic/gin"
	authzschemas "github.com/lamassuiot/authz"
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
	newDeviceManagerHTTPLayerWithSSE(router, svc, sseHub, authzConf, logger)
}

func newDeviceManagerHTTPLayerWithSSE(router *gin.RouterGroup, svc services.DeviceManagerService, sseHub *controllers.DeviceEventSSEHub, authzConf config.AuthzClient, logger *logrus.Entry) *middleware.ContractRouter {
	return registerDeviceManagerRoutes(router, svc, sseHub, newRemoteAuthzEngine(authzConf, models.DeviceManagerSource, logger), logger)
}

// REST and SSE requests share the same validated device permissions.
func registerDeviceManagerRoutes(router *gin.RouterGroup, svc services.DeviceManagerService, sseHub *controllers.DeviceEventSSEHub, engine authzcore.AuthzEngine, logger *logrus.Entry) *middleware.ContractRouter {
	routes := controllers.NewDeviceManagerHttpRoutesWithSSE(svc, sseHub)
	schemas, err := authzschemas.PKISchemas()
	if err != nil {
		panic(err)
	}
	authzMw := middleware.MustNewAuthzMiddleware(engine, schemas, "pki", "devicemanager", "device", logger)
	deviceGroupAuthzMw := middleware.MustNewAuthzMiddleware(engine, schemas, "pki", "devicemanager", "device_group", logger)
	idKey := map[string]string{"id": "id"}

	rv1 := router.Group("/v1")
	contract := middleware.NewContractRouter(rv1)

	contract.Handle(http.MethodGet, "/stats", authzMw.List(), routes.GetStats)
	contract.Handle(http.MethodGet, "/devices", authzMw.List(), routes.GetAllDevices)
	contract.Handle(http.MethodPost, "/devices", authzMw.Global("create"), routes.CreateDevice)
	contract.Handle(http.MethodGet, "/devices/:id", authzMw.Resource("read", idKey), routes.GetDeviceByID)
	contract.Handle(http.MethodGet, "/devices/:id/events", authzMw.Resource("read", idKey), routes.GetDeviceEvents)
	contract.Handle(http.MethodPost, "/devices/:id/events", authzMw.Resource("metadata-update", idKey), routes.CreateDeviceEvent)
	contract.Handle(http.MethodDelete, "/devices/:id", authzMw.Resource("delete", idKey), routes.DeleteDevice)
	contract.Handle(http.MethodPut, "/devices/:id/idslot", authzMw.Resource("provision", idKey), routes.UpdateDeviceIdentitySlot)
	contract.Handle(http.MethodPut, "/devices/:id/metadata", authzMw.Resource("metadata-update", idKey), routes.UpdateDeviceMetadata)
	contract.Handle(http.MethodPatch, "/devices/:id/metadata", authzMw.Resource("metadata-update", idKey), routes.UpdateDeviceMetadata)
	contract.Handle(http.MethodDelete, "/devices/:id/decommission", authzMw.Resource("decommission", idKey), routes.DecommissionDevice)
	contract.Handle(http.MethodGet, "/devices/dms/:id", authzMw.List(), routes.GetDevicesByDMS)

	// Device Groups routes
	contract.Handle(http.MethodPost, "/device-groups", deviceGroupAuthzMw.Global("create"), routes.CreateDeviceGroup)
	contract.Handle(http.MethodGet, "/device-groups", deviceGroupAuthzMw.List(), routes.GetAllDeviceGroups)
	contract.Handle(http.MethodGet, "/device-groups/:id", deviceGroupAuthzMw.Resource("read", idKey), routes.GetDeviceGroupByID)
	contract.Handle(http.MethodPut, "/device-groups/:id", deviceGroupAuthzMw.Resource("update", idKey), routes.UpdateDeviceGroup)
	contract.Handle(http.MethodDelete, "/device-groups/:id", deviceGroupAuthzMw.Resource("delete", idKey), routes.DeleteDeviceGroup)
	contract.Handle(http.MethodGet, "/device-groups/:id/devices", authzMw.List(), routes.GetDevicesByGroup)
	contract.Handle(http.MethodGet, "/device-groups/:id/stats", deviceGroupAuthzMw.Resource("read", idKey), routes.GetDeviceGroupStats)
	return contract
}
