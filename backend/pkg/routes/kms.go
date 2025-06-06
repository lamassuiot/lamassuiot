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

	// GET keys
	rv1.GET("/keys", routes.GetKeys)
	// GET key
	rv1.GET("/keys/:id", routes.GetKeyByID)
	// POST key
	rv1.POST("/keys", routes.CreateKey)
	// DELETE key
	rv1.DELETE("/keys/:id", routes.DeleteKeyByID)
	// POST key import
	rv1.POST("/keys/import", routes.ImportKey)
	// POST key export
	//rv1.POST("/keys/:id/export", routes.ExportKey)
	// POST key sign
	rv1.POST("/keys/:id/sign", routes.SignMessage)
	// POST key verify
	rv1.POST("/keys/:id/verify", routes.VerifySignature)
}
