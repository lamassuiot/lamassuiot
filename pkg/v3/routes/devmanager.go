package routes

import (
	"github.com/lamassuiot/lamassuiot/pkg/v3/config"
	"github.com/lamassuiot/lamassuiot/pkg/v3/controllers"
	"github.com/lamassuiot/lamassuiot/pkg/v3/models"
	"github.com/lamassuiot/lamassuiot/pkg/v3/services"
	"github.com/sirupsen/logrus"
)

func NewDeviceManagerHTTPLayer(logger *logrus.Entry, svc services.DeviceManagerService, httpServerCfg config.HttpServer, apiInfo models.APIServiceInfo) error {
	router := newGinEngine(logger)
	routes := controllers.NewDeviceManagerHttpRoutes(svc)

	rv1 := router.Group("/v1")
	rv1.GET("/devices", routes.GetAllDevices)
	rv1.POST("/devices", routes.CreateDevice)
	rv1.GET("/devices/:id", routes.GetDeviceByID)
	rv1.PUT("/devices/:id/idslot", routes.UpdateIdentitySlot)
	rv1.POST("/devices/:id/decommission", routes.DecommissionDevice)
	rv1.PUT("/devices/dms/:id", routes.GetAllDevices)

	return newHttpRouter(logger, router, httpServerCfg, apiInfo)
}
