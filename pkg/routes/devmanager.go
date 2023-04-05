package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/lamassuiot/pkg/config"
	"github.com/lamassuiot/lamassuiot/pkg/controllers"
	"github.com/lamassuiot/lamassuiot/pkg/models"
	"github.com/lamassuiot/lamassuiot/pkg/services"
)

func NewDeviceManagerHTTPLayer(svc services.DeviceManagerService, httpServerCfg config.HttpServer, apiInfo models.APIServiceInfo) error {
	if !httpServerCfg.DebugMode {
		gin.SetMode(gin.ReleaseMode)
	}
	router := gin.New()
	router.Use(ginResponseErorrLogger, gin.Logger(), gin.Recovery())

	routes := controllers.NewDeviceManagerHttpRoutes(svc)

	NewESTHttpRoutes(router, svc)

	rv1 := router.Group("/v1")
	rv1.GET("/devices", routes.GetAllDevices)
	rv1.POST("/devices", routes.GetAllDevices)
	rv1.GET("/devices/:id", routes.GetAllDevices)

	return newHttpRouter(router, httpServerCfg, apiInfo)
}
