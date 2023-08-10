package routes

import (
	"github.com/lamassuiot/lamassuiot/pkg/v3/config"
	"github.com/lamassuiot/lamassuiot/pkg/v3/controllers"
	"github.com/lamassuiot/lamassuiot/pkg/v3/models"
	"github.com/lamassuiot/lamassuiot/pkg/v3/services"
	"github.com/sirupsen/logrus"
)

func NewDMSManagerHTTPLayer(logger *logrus.Entry, svc services.DMSManagerService, httpServerCfg config.HttpServer, apiInfo models.APIServiceInfo) error {
	router := newGinEngine(logger)

	routes := controllers.NewDMSManagerHttpRoutes(svc)

	NewESTHttpRoutes(logger, router, svc)

	rv1 := router.Group("/v1")

	rv1.GET("/dms", routes.GetAllDMSs)
	rv1.POST("/dms", routes.CreateDMS)
	rv1.GET("/dms/:id", routes.GetDMSByID)
	rv1.PUT("/dms/:id/id-profile", routes.UpdateIdentityProfile)

	return newHttpRouter(logger, router, httpServerCfg, apiInfo)
}
