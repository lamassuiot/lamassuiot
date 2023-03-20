package routes

import (
	"fmt"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/lamassuiot/pkg/controllers"
	"github.com/lamassuiot/lamassuiot/pkg/models"
	"github.com/lamassuiot/lamassuiot/pkg/services"
)

func NewCAHTTPLayer(svc services.CAService, listenAddress string, port int, debugMode bool, apiInfo models.APIServiceInfo) error {
	if !debugMode {
		gin.SetMode(gin.ReleaseMode)
	}

	hcheckRoute := controllers.NewHealthCheckRoute(apiInfo)
	routes := controllers.NewCAHttpRoutes(svc)
	router := gin.Default()

	config := cors.DefaultConfig()
	config.AllowAllOrigins = true
	config.AllowHeaders = []string{"*"}

	router.Use(cors.New(config))
	rv1 := router.Group("/v1")

	rv1.GET("/cas", routes.GetAllCAs)
	rv1.POST("/cas", routes.CreateCA)
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

	rv1.GET("/health", hcheckRoute.HealtCheck)

	addr := fmt.Sprintf("%s:%d", listenAddress, port)
	err := router.Run(addr)

	return err
}
