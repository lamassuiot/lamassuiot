package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/lamassuiot/pkg/v3/controllers"
	"github.com/lamassuiot/lamassuiot/pkg/v3/services"
	"github.com/sirupsen/logrus"
)

func NewValidationRoutes(logger *logrus.Entry, httpGrp *gin.RouterGroup, ocsp services.OCSPService, crl services.CRLService) {
	vaRoutes := controllers.NewVAHttpRoutes(logger, ocsp, crl)

	httpGrp.GET("/ocsp/:ocsp_request", vaRoutes.Verify)
	httpGrp.POST("/ocsp", vaRoutes.Verify)
	httpGrp.GET("/crl/:id", vaRoutes.CRL)
}
