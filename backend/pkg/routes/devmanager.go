package routes

import (
	"log"

	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/controllers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	"github.com/sirupsen/logrus"
	"ikerlan.es/authz/sdk"
	authzSdk "ikerlan.es/authz/sdk"
	middleware "ikerlan.es/authz/sdk/gin-middleware"
)

func NewDeviceManagerHTTPLayer(router *gin.RouterGroup, svc services.DeviceManagerService, logger *logrus.Entry) {
	routes := controllers.NewDeviceManagerHttpRoutes(svc)

	config := sdk.DefaultConfig("http://localhost:8888") // Point to your authz service
	client, err := sdk.NewClient(config)
	if err != nil {
		log.Fatalf("Failed to create SDK client: %v", err)
	}

	remoteEngine := authzSdk.NewRemoteEngine(client)
	authzMw := middleware.NewAuthzMiddleware(remoteEngine, "device", logger)

	rv1 := router.Group("/v1")

	rv1.GET("/stats", routes.GetStats)
	rv1.GET("/devices", authzMw.AuthListCheck(), routes.GetAllDevices)
	rv1.POST("/devices", authzMw.AuthzCheck("create"), routes.CreateDevice)
	rv1.GET("/devices/:id", routes.GetDeviceByID)
	rv1.DELETE("/devices/:id", authzMw.AuthzCheck("delete"), routes.DeleteDevice)
	rv1.PUT("/devices/:id/idslot", routes.UpdateDeviceIdentitySlot)
	rv1.PUT("/devices/:id/metadata", routes.UpdateDeviceMetadata)
	rv1.PATCH("/devices/:id/metadata", routes.UpdateDeviceMetadata)
	rv1.DELETE("/devices/:id/decommission", authzMw.AuthzCheck("decomission"), routes.DecommissionDevice)
	rv1.GET("/devices/dms/:id", routes.GetDevicesByDMS)

	// Device Groups routes
	deviceGroupsRoutes := rv1.Group("/device-groups")
	{
		deviceGroupsRoutes.POST("", routes.CreateDeviceGroup)
		deviceGroupsRoutes.GET("", routes.GetAllDeviceGroups)
		deviceGroupsRoutes.GET("/:id", routes.GetDeviceGroupByID)
		deviceGroupsRoutes.PUT("/:id", routes.UpdateDeviceGroup)
		deviceGroupsRoutes.DELETE("/:id", routes.DeleteDeviceGroup)
		deviceGroupsRoutes.GET("/:id/devices", routes.GetDevicesByGroup)
		deviceGroupsRoutes.GET("/:id/stats", routes.GetDeviceGroupStats)
	}
}
