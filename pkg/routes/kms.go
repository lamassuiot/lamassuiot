package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/lamassuiot/v2/pkg/controllers"
	"github.com/lamassuiot/lamassuiot/v2/pkg/services"
)

func NewKMSHTTPLayer(parentRouterGroup *gin.RouterGroup, svc services.KMSService) {
	routes := controllers.NewKmsHttpRoutes(svc)

	router := parentRouterGroup
	rv1 := router.Group("/v1")

	rv1.GET("/engines", routes.GetCryptoEngineProvider)

	rv1.POST("/", routes.CreatePrivateKey)
	rv1.POST("/import", routes.ImportPrivateKey)
	rv1.GET("/:engineId/:kid", routes.GetKey)
	rv1.POST("/:engineId/:kid/sign", routes.Sign)
	rv1.POST("/:engineId/:kid/verify", routes.Verify)
}
