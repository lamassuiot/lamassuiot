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
	rv1.GET("/kms/keys", routes.GetKeys)
	rv1.GET("/kms/keys/:id", routes.GetKeyByID)
	rv1.POST("/kms/keys", routes.CreateKey)
	rv1.POST("/kms/keys/import", routes.ImportKey)
	rv1.PUT("/kms/keys/:id/alias", routes.UpdateKeyAliases)
	rv1.PUT("/kms/keys/:id/name", routes.UpdateKeyName)
	rv1.PUT("/kms/keys/:id/metadata", routes.UpdateKeyMetadata)
	rv1.DELETE("/kms/keys/:id", routes.DeleteKeyByID)
	rv1.POST("/kms/keys/:id/sign", routes.SignMessage)
	rv1.POST("/kms/keys/:id/verify", routes.VerifySignature)
}
