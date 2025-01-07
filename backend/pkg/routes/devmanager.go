package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/controllers"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/routes/middlewares/sse"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
)

func NewDeviceManagerHTTPLayer(router *gin.RouterGroup, svc services.DeviceManagerService) {
	stream := sse.NewEvent()

	routes := controllers.NewDeviceManagerHttpRoutes(svc, stream)

	rv1 := router.Group("/v1")
	rv1.GET("/stats", routes.GetStats)
	rv1.GET("/devices", routes.GetAllDevices)
	rv1.POST("/devices", routes.CreateDevice)
	rv1.GET("/devices/:id", routes.GetDeviceByID)
	rv1.PUT("/devices/:id/idslot", routes.UpdateDeviceIdentitySlot)
	rv1.PUT("/devices/:id/metadata", routes.UpdateDeviceMetadata)
	rv1.GET("/devices/:id/events", routes.GetDeviceEvents)
	rv1.GET("/devices/:id/events/stream", stream.SSEConnMiddleware(), routes.GetDeviceEventsInStream)
	rv1.POST("/devices/:id/events", routes.CreateDeviceEvent)
	rv1.DELETE("/devices/:id/decommission", routes.DecommissionDevice)
	rv1.GET("/devices/dms/:id", routes.GetDevicesByDMS)

}
