package routes

import (
	"log"

	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/authz/sdk"
	authzSdk "github.com/lamassuiot/authz/sdk"
	middleware "github.com/lamassuiot/authz/sdk/gin-middleware"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/controllers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	"github.com/sirupsen/logrus"
)

func NewDeviceManagerHTTPLayer(router *gin.RouterGroup, svc services.DeviceManagerService, logger *logrus.Entry) {
	routes := controllers.NewDeviceManagerHttpRoutes(svc)

	config := sdk.DefaultConfig("http://localhost:8888") // Point to your authz service
	client, err := sdk.NewClient(config)
	if err != nil {
		log.Fatalf("Failed to create SDK client: %v", err)
	}

	remoteEngine := authzSdk.NewRemoteEngine(client)
	authzMw := middleware.NewAuthzMiddleware(remoteEngine, "pki", "devicemanager", "device", logger)
	deviceGroupAuthzMw := middleware.NewAuthzMiddleware(remoteEngine, "pki", "devicemanager", "device_group", logger)

	rv1 := router.Group("/v1")

	rv1.GET("/stats", authzMw.AuthListCheck(), routes.GetStats)
	rv1.GET("/devices", authzMw.AuthListCheck(), routes.GetAllDevices)
	rv1.POST("/devices", authzMw.AuthzCheck("create"), routes.CreateDevice)
	rv1.GET("/devices/:id", authzMw.AuthzCheck("read"), routes.GetDeviceByID)
	rv1.DELETE("/devices/:id", authzMw.AuthzCheck("delete"), routes.DeleteDevice)
	rv1.PUT("/devices/:id/idslot", authzMw.AuthzCheck("provision"), routes.UpdateDeviceIdentitySlot)
	rv1.PUT("/devices/:id/metadata", authzMw.AuthzCheck("metadata-update"), routes.UpdateDeviceMetadata)
	rv1.PATCH("/devices/:id/metadata", authzMw.AuthzCheck("metadata-update"), routes.UpdateDeviceMetadata)
	rv1.DELETE("/devices/:id/decommission", authzMw.AuthzCheck("decomission"), routes.DecommissionDevice)
	rv1.GET("/devices/dms/:id", authzMw.AuthListCheck(), routes.GetDevicesByDMS)

	// Device Groups routes
	deviceGroupsRoutes := rv1.Group("/device-groups")
	{
		deviceGroupsRoutes.POST("", deviceGroupAuthzMw.AuthzCheck("create"), routes.CreateDeviceGroup)
		deviceGroupsRoutes.GET("", deviceGroupAuthzMw.AuthListCheck(), routes.GetAllDeviceGroups)
		deviceGroupsRoutes.GET("/:id", deviceGroupAuthzMw.AuthzCheck("read"), routes.GetDeviceGroupByID)
		deviceGroupsRoutes.PUT("/:id", deviceGroupAuthzMw.AuthzCheck("update"), routes.UpdateDeviceGroup)
		deviceGroupsRoutes.DELETE("/:id", deviceGroupAuthzMw.AuthzCheck("delete"), routes.DeleteDeviceGroup)
		deviceGroupsRoutes.GET("/:id/devices", authzMw.AuthListCheck(), routes.GetDevicesByGroup)
		deviceGroupsRoutes.GET("/:id/stats", deviceGroupAuthzMw.AuthzCheck("read"), routes.GetDeviceGroupStats)
	}
}
