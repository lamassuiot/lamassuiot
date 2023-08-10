package routes

import (
	"github.com/lamassuiot/lamassuiot/pkg/v3/config"
	"github.com/lamassuiot/lamassuiot/pkg/v3/controllers"
	"github.com/lamassuiot/lamassuiot/pkg/v3/models"
	"github.com/lamassuiot/lamassuiot/pkg/v3/services"
	docs "github.com/lamassuiot/lamassuiot/pkg/v3/swagger/ca"
	"github.com/sirupsen/logrus"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

func NewCAHTTPLayer(logger *logrus.Entry, svc services.CAService, httpServerCfg config.HttpServer, apiInfo models.APIServiceInfo) error {
	docs.SwaggerInfo.Title = "Lamassu CA Service API"
	docs.SwaggerInfo.Description = "These are the endpoints available in the Lamassu CA Service."
	docs.SwaggerInfo.Version = "1.0"
	docs.SwaggerInfo.BasePath = "/v1"
	docs.SwaggerInfo.InfoInstanceName = "Lamassu CA"
	docs.SwaggerInfo.Host = httpServerCfg.ListenAddress
	docs.SwaggerInfo.Schemes = []string{string(httpServerCfg.Protocol)}

	routes := controllers.NewCAHttpRoutes(svc)

	router := newGinEngine(logger)
	rv1 := router.Group("/v1")

	rv1.GET("/cas", routes.GetAllCAs)
	rv1.POST("/cas", routes.CreateCA)
	rv1.POST("/cas/import", routes.ImportCA)

	rv1.GET("/cas/:id", routes.GetCAByID)
	rv1.PUT("/cas/:id/metadata", routes.UpdateCAMetadata)
	rv1.POST("/cas/:id/revoke", routes.RevokeCA)
	rv1.GET("/cas/:id/certificates", routes.GetCertificatesByCA)
	rv1.POST("/cas/:id/certificates/sign", routes.SignCertificate)
	rv1.POST("/cas/:id/signature/sign", routes.SignatureSign)
	rv1.POST("/cas/:id/signature/verify", routes.SignatureVerify)
	rv1.GET("/cas/:id/certificates/:sn", routes.GetCertificateBySerialNumber)
	rv1.DELETE("/cas/:id", routes.DeleteCA)

	rv1.GET("/certificates", routes.GetCertificates)
	rv1.GET("/certificates/:sn", routes.GetCertificateBySerialNumber)
	rv1.PUT("/certificates/:sn/status", routes.UpdateCertificateStatus)

	rv1.GET("/engines", routes.GetCryptoEngineProvider)
	rv1.GET("/stats", routes.GetCryptoEngineProvider)

	rv1.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))
	return newHttpRouter(logger, router, httpServerCfg, apiInfo)
}
