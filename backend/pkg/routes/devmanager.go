package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/lamassuiot/v3/backend/pkg/controllers"
	"github.com/lamassuiot/lamassuiot/v3/core/pkg/services"
)

func NewDeviceManagerHTTPLayer(router *gin.RouterGroup, svc services.DeviceManagerService) {
	routes := controllers.NewDeviceManagerHttpRoutes(svc)

	rv1 := router.Group("/v1")
	rv1.GET("/stats", routes.GetStats)
	rv1.GET("/devices", routes.GetAllDevices)
	rv1.POST("/devices", routes.CreateDevice)
	rv1.GET("/devices/:id", routes.GetDeviceByID)
	rv1.PUT("/devices/:id/idslot", routes.UpdateDeviceIdentitySlot)
	rv1.PUT("/devices/:id/metadata", routes.UpdateDeviceMetadata)
	rv1.DELETE("/devices/:id/decommission", routes.DecommissionDevice)
	rv1.GET("/devices/dms/:id", routes.GetDevicesByDMS)

}
