package routes

import (
	"github.com/lamassuiot/lamassuiot/pkg/v3/config"
	"github.com/lamassuiot/lamassuiot/pkg/v3/controllers"
	"github.com/lamassuiot/lamassuiot/pkg/v3/models"
	"github.com/lamassuiot/lamassuiot/pkg/v3/services"
	"github.com/sirupsen/logrus"
)

func NewValidationRoutes(logger *logrus.Entry, ocsp services.OCSPService, crl services.CRLService, httpServerCfg config.HttpServer, apiInfo models.APIServiceInfo) error {
	router := newGinEngine(logger)
	vaRoutes := controllers.NewVAHttpRoutes(logger, ocsp, crl)

	rv1 := router.Group("/v1")
	rv1.GET("/ocsp", vaRoutes.Verify)
	rv1.POST("/ocsp", vaRoutes.Verify)
	rv1.GET("/crl/:id", vaRoutes.CRL)

	return newHttpRouter(logger, router, httpServerCfg, apiInfo)
}
