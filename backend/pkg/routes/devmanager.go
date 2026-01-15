package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/controllers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
)

func NewDeviceManagerHTTPLayer(router *gin.RouterGroup, svc services.DeviceManagerService) {
	routes := controllers.NewDeviceManagerHttpRoutes(svc)

	rv1 := router.Group("/v1")
	rv1.GET("/stats", routes.GetStats)
	rv1.GET("/devices", routes.GetAllDevices)
	rv1.POST("/devices", routes.CreateDevice)
	rv1.GET("/devices/:id", routes.GetDeviceByID)
	rv1.DELETE("/devices/:id", routes.DeleteDevice)
	rv1.PUT("/devices/:id/idslot", routes.UpdateDeviceIdentitySlot)
	rv1.PUT("/devices/:id/metadata", routes.UpdateDeviceMetadata)
	rv1.PATCH("/devices/:id/metadata", routes.UpdateDeviceMetadata)
	rv1.DELETE("/devices/:id/decommission", routes.DecommissionDevice)
	rv1.GET("/devices/dms/:id", routes.GetDevicesByDMS)

	// Device Groups routes
	deviceGroupsRoutes := rv1.Group("/device-groups")
	{
		deviceGroupsRoutes.POST("", routes.CreateDeviceGroup)
		deviceGroupsRoutes.GET("", routes.GetAllDeviceGroups)
		deviceGroupsRoutes.GET("/:id", routes.GetDeviceGroupByID)
		deviceGroupsRoutes.PUT("/:id", routes.UpdateDeviceGroup)
		deviceGroupsRoutes.DELETE("/:id", routes.DeleteDeviceGroup)
		deviceGroupsRoutes.GET("/:group_id/devices", routes.GetDevicesByGroup)
		deviceGroupsRoutes.GET("/:group_id/stats", routes.GetDeviceGroupStats)
	}
}
