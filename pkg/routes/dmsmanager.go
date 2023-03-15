package routes

import (
	"fmt"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/lamassuiot/pkg/controllers"
	"github.com/lamassuiot/lamassuiot/pkg/services"
)

func NewDMSManagerHTTPLayer(svc services.DMSManagerService, listenAddress string, port int, debugMode bool) error {
	if !debugMode {
		gin.SetMode(gin.ReleaseMode)
	}

	routes := controllers.NewDMSManagerdmsManagerHttpRoutes(svc)
	router := gin.Default()

	config := cors.DefaultConfig()
	config.AllowAllOrigins = true
	config.AllowHeaders = []string{"*"}

	router.Use(cors.New(config))
	NewESTHttpRoutes(router, svc)

	rv1 := router.Group("/v1")

	rv1.GET("/dms", routes.GetAllDMSs)
	rv1.POST("/dms", routes.CreateDMS)
	rv1.GET("/dms/:id", routes.GetDMSByID)
	rv1.PUT("/cas/:id/status", routes.UpdateStatus)
	rv1.PUT("/cas/:id/id-profile", routes.UpdateIdentityProfile)

	addr := fmt.Sprintf("%s:%d", listenAddress, port)
	err := router.Run(addr)

	return err
}
