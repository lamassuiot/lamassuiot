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

	rv1 := router.Group("/v1")
	rv1.GET("/ocsp", vaRoutes.Verify)
	rv1.POST("/ocsp", vaRoutes.Verify)
	rv1.GET("/crl/:id", vaRoutes.CRL)

	return router
}
