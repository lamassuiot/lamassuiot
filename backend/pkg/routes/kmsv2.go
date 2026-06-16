package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/controllers"
	cryptoenginesv2 "github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/cryptoengines_v2"
)

func NewKMSV2HTTPLayer(parentRouterGroup *gin.RouterGroup, svc cryptoenginesv2.Service) {
	r := controllers.NewKMSV2HttpRoutes(svc)
	g := parentRouterGroup.Group("/v2/kms")

	// Keys — lifecycle
	g.GET("/keys", r.ListKeys)
	g.POST("/keys", r.CreateOrImportKey)
	g.GET("/keys/:id", r.GetKey)
	g.PATCH("/keys/:id", r.UpdateKey)
	g.DELETE("/keys/:id", r.DeleteKey)

	// Keys — state machine
	g.PUT("/keys/:id/state", r.SetKeyState)

	// Keys — backup / restore
	g.PUT("/keys/:id/backup", r.BackupKey)
	g.POST("/keys/restore", r.RestoreKey) // static segment registered before :id wildcard

	// Aliases
	g.PUT("/aliases/:name", r.UpsertAlias)
	g.DELETE("/aliases/:name", r.DeleteAlias)
	g.GET("/aliases/:name", r.ResolveAlias)

	// RNG
	g.POST("/random", r.GenerateRandom)
}
