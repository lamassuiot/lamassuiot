package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/lamassuiot/v2/pkg/controllers"
	"github.com/lamassuiot/lamassuiot/v2/pkg/services"
)

func NewCAHTTPLayer(parentRouterGroup *gin.RouterGroup, svc services.CAService) {
	routes := controllers.NewCAHttpRoutes(svc)

	router := parentRouterGroup
	rv1 := router.Group("/v1")

	rv1.GET("/cas", routes.GetAllCAs)
	rv1.POST("/cas", routes.CreateCA)
	rv1.POST("/cas/import", routes.ImportCA)

	rv1.GET("/cas/:id", routes.GetCAByID)
	rv1.GET("/cas/cn/:cn", routes.GetCAsByCommonName)

	rv1.PUT("/cas/:id/metadata", routes.UpdateCAMetadata)
	rv1.POST("/cas/:id/status", routes.UpdateCAStatus)
	rv1.GET("/cas/:id/certificates", routes.GetCertificatesByCA)
	rv1.GET("/cas/:id/certificates/status/:status", routes.GetCertificatesByCAAndStatus)
	rv1.POST("/cas/:id/certificates/sign", routes.SignCertificate)
	rv1.POST("/cas/:id/signature/sign", routes.SignatureSign)
	rv1.POST("/cas/:id/signature/verify", routes.SignatureVerify)
	rv1.GET("/cas/:id/certificates/:sn", routes.GetCertificateBySerialNumber)
	rv1.PUT("/cas/:id/issuance-expiration", routes.UpdateCAIssuanceExpiration)
	rv1.DELETE("/cas/:id", routes.DeleteCA)

	rv1.GET("/certificates", routes.GetCertificates)
	rv1.GET("/certificates/status/:status", routes.GetCertificatesByStatus)
	rv1.GET("/certificates/expiration", routes.GetCertificatesByExpirationDate)
	rv1.GET("/certificates/:sn", routes.GetCertificateBySerialNumber)
	rv1.PUT("/certificates/:sn/status", routes.UpdateCertificateStatus)
	rv1.PUT("/certificates/:sn/metadata", routes.UpdateCertificateMetadata)
	rv1.POST("/certificates/import", routes.ImportCertificate)

	rv1.GET("/engines", routes.GetCryptoEngineProvider)
	rv1.GET("/stats", routes.GetStats)
	rv1.GET("/stats/:id", routes.GetStatsByCAID)
}
