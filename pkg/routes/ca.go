package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/lamassuiot/pkg/config"
	"github.com/lamassuiot/lamassuiot/pkg/controllers"
	"github.com/lamassuiot/lamassuiot/pkg/models"
	"github.com/lamassuiot/lamassuiot/pkg/services"
)

func NewCAHTTPLayer(svc services.CAService, httpServerCfg config.HttpServer, apiInfo models.APIServiceInfo) error {
	if !httpServerCfg.DebugMode {
		gin.SetMode(gin.ReleaseMode)
	}
	router := gin.New()
	router.Use(ginResponseErorrLogger, gin.Logger(), gin.Recovery())

	routes := controllers.NewCAHttpRoutes(svc)

	rv1 := router.Group("/v1")

	rv1.GET("/cas", routes.GetAllCAs)
	rv1.POST("/cas", routes.CreateCA)
	rv1.POST("/cas/import", routes.ImportCA)

	rv1.GET("/cas/:id", routes.GetCAByID)
	rv1.POST("/cas/:id/sign", routes.SignCertificate)
	rv1.POST("/cas/:id/revoke", routes.RevokeCA)
	rv1.GET("/cas/:id/certificates", routes.GetCertificatesByCA)
	rv1.GET("/cas/:id/certificates/:sn", routes.GetCertificateBySerialNumber)
	rv1.DELETE("/cas/:id", routes.DeleteCA)

	rv1.GET("/certificates", routes.GetCertificates)
	rv1.GET("/certificates/:sn", routes.GetCertificateBySerialNumber)

	rv1.GET("/engines", routes.GetCryptoEngineProvider)
	rv1.GET("/stats", routes.GetCryptoEngineProvider)

	return newHttpRouter(router, httpServerCfg, apiInfo)
}
