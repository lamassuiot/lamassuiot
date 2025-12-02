package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/controllers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
)

func NewKMSHTTPLayer(parentRouterGroup *gin.RouterGroup, svc services.KMSService) {
	routes := controllers.NewKMSHttpRoutes(svc)

	router := parentRouterGroup
	rv1 := router.Group("/v1")

	rv1.GET("/engines", routes.GetCryptoEngineProvider)

	// KMS
	rv1.GET("/keys", routes.GetKeys)
	rv1.GET("/keys/:id", routes.GetKeyByID)
	rv1.POST("/keys", routes.CreateKey)
	rv1.POST("/keys/import", routes.ImportKey)
	rv1.PUT("/keys/:id/alias", routes.UpdateKeyAliases)
	rv1.PUT("/keys/:id/name", routes.UpdateKeyName)
	rv1.PUT("/keys/:id/tags", routes.UpdateKeyTags)
	rv1.PUT("/keys/:id/metadata", routes.UpdateKeyMetadata)
	rv1.DELETE("/keys/:id", routes.DeleteKeyByID)
	rv1.POST("/keys/:id/sign", routes.SignMessage)
	rv1.POST("/keys/:id/verify", routes.VerifySignature)
}
