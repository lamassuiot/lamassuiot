package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/controllers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
)

func NewCAHTTPLayer(parentRouterGroup *gin.RouterGroup, svc services.CAService) {
	routes := controllers.NewCAHttpRoutes(svc)

	router := parentRouterGroup
	rv1 := router.Group("/v1")

	// GET CAS
	rv1.GET("/cas", routes.GetAllCAs)
	rv1.POST("/cas", routes.CreateCA)

	rv1.POST("/cas/pq", routes.CreateHybridCA)

	rv1.POST("/cas/import", routes.ImportCA)
	rv1.GET("/cas/:id", routes.GetCAByID)
	rv1.GET("/cas/cn/:cn", routes.GetCAsByCommonName)

	rv1.PUT("/cas/:id/metadata", routes.UpdateCAMetadata)
	rv1.PATCH("/cas/:id/metadata", routes.UpdateCAMetadata)
	rv1.POST("/cas/:id/status", routes.UpdateCAStatus)
	rv1.POST("/cas/:id/profile", routes.UpdateCAProfile)
	rv1.GET("/cas/:id/certificates", routes.GetCertificatesByCA)
	rv1.GET("/cas/:id/certificates/status/:status", routes.GetCertificatesByCAAndStatus)
	rv1.POST("/cas/:id/certificates/sign", routes.SignCertificate)
	rv1.POST("/cas/:id/signature/sign", routes.SignatureSign)
	rv1.POST("/cas/:id/signature/verify", routes.SignatureVerify)
	rv1.GET("/cas/:id/certificates/:sn", routes.GetCertificateBySerialNumber)
	rv1.DELETE("/cas/:id", routes.DeleteCA)

	rv1.GET("/certificates", routes.GetCertificates)
	rv1.GET("/certificates/status/:status", routes.GetCertificatesByStatus)
	rv1.GET("/certificates/expiration", routes.GetCertificatesByExpirationDate)
	rv1.GET("/certificates/:sn", routes.GetCertificateBySerialNumber)
	rv1.PUT("/certificates/:sn/status", routes.UpdateCertificateStatus)
	rv1.PUT("/certificates/:sn/metadata", routes.UpdateCertificateMetadata)
	rv1.PATCH("/certificates/:sn/metadata", routes.UpdateCertificateMetadata)
	rv1.DELETE("/certificates/:sn", routes.DeleteCertificate)
	rv1.POST("/certificates/import", routes.ImportCertificate)

	rv1.GET("/stats", routes.GetStats)
	rv1.GET("/stats/:id", routes.GetStatsByCAID)

	rv1.GET("/profiles", routes.GetIssuanceProfiles)
	rv1.GET("/profiles/:id", routes.GetIssuanceProfileByID)
	rv1.POST("/profiles", routes.CreateIssuanceProfile)
	rv1.PUT("/profiles/:id", routes.UpdateIssuanceProfile)
	rv1.DELETE("/profiles/:id", routes.DeleteIssuanceProfile)
}
