package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/lamassuiot/pkg/v3/controllers"
	"github.com/lamassuiot/lamassuiot/pkg/v3/services"
	"github.com/sirupsen/logrus"
)

func NewValidationRoutes(logger *logrus.Entry, ocsp services.OCSPService, crl services.CRLService) *gin.Engine {
	router := newGinEngine(logger)
	vaRoutes := controllers.NewVAHttpRoutes(logger, ocsp, crl)

	router.GET("/ocsp/:ocsp_request", vaRoutes.Verify)
	router.POST("/ocsp", vaRoutes.Verify)
	router.GET("/crl/:id", vaRoutes.CRL)

	return router
}
