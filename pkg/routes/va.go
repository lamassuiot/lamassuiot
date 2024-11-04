package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/lamassuiot/v2/core/pkg/services"
	"github.com/lamassuiot/lamassuiot/v2/pkg/controllers"
	"github.com/sirupsen/logrus"
)

func NewValidationRoutes(logger *logrus.Entry, httpGrp *gin.RouterGroup, ocsp services.OCSPService, crl services.CRLService) {
	vaRoutes := controllers.NewVAHttpRoutes(logger, ocsp, crl)

	httpGrp.GET("/ocsp/:ocsp_request", vaRoutes.Verify)
	httpGrp.POST("/ocsp", vaRoutes.Verify)
	httpGrp.GET("/crl/:id", vaRoutes.CRL)
}
