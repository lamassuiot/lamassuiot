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

	routes := controllers.NewCAHttpRoutes(svc)
	router := gin.Default()

	rv1 := router.Group("/v1")

	rv1.GET("/cas", routes.GetAllCAs)
	rv1.POST("/cas", routes.CreateCA)
	rv1.POST("/cas/import", routes.ImportCA)

	rv1.GET("/cas/:id", routes.CreateCA)
	//TODO
	rv1.DELETE("/cas/:id", routes.DeleteCA)
	rv1.POST("/cas/:id/sign", routes.SignCertificate)
	//TODO
	rv1.POST("/cas/:id/revoke", routes.SignCertificate)
	rv1.GET("/cas/:id/certificates", routes.GetCertificatesByCA)
	//TODO
	rv1.GET("/cas/:id/certificates/:serialNumber", routes.CreateCA)

	rv1.GET("/certificates", routes.GetCertificates)
	rv1.GET("/certificates/:sn", routes.GetCertificateBySerialNumber)

	rv1.GET("/engines", routes.GetCryptoEngineProviders)
	rv1.GET("/stats", routes.GetCryptoEngineProviders)

	return newHttpRouter(router, httpServerCfg, apiInfo)
}
