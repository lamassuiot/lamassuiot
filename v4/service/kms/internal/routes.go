package internal

import (
	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/lamassuiot/service/kms"
)

func NewKMSHTTPLayer(parentRouterGroup *gin.RouterGroup, svc kms.KMSService) {
	routes := NewKMSHttpRoutes(svc)

	router := parentRouterGroup
	rv1 := router.Group("/v1")

	rv1.GET("/kms/keys", routes.GetKeys)
	rv1.GET("/kms/keys/:id", routes.GetKeyByID)
	rv1.POST("/kms/keys", routes.CreateKey)
	rv1.DELETE("/kms/keys/:id", routes.DeleteKeyByID)
	rv1.POST("/kms/keys/import", routes.ImportKey)
	rv1.POST("/kms/keys/:id/sign", routes.SignMessage)
	rv1.POST("/kms/keys/:id/verify", routes.VerifySignature)
}
