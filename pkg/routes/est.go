package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/lamassuiot/pkg/controllers"
	"github.com/lamassuiot/lamassuiot/pkg/services"
)

func NewESTHttpRoutes(router *gin.Engine, svc services.ESTService) *gin.RouterGroup {
	routes := controllers.NewESTHttpRoutes(svc)

	est := router.Group("/.well-known/est")

	est.GET("/cacerts", routes.GetCACerts)
	est.GET("/:aps/cacerts", routes.GetCACerts)

	est.POST("/simpleenroll", routes.Enroll)
	est.POST("/:aps/simpleenroll", routes.Enroll)

	est.POST("/simplereenroll", routes.Reenroll)
	est.POST("/:aps/simplereenroll", routes.Reenroll)

	// est.POST("/serverkeygen", routes.ServerKeygen)
	// est.POST("/:aps/serverkeygen", routes.ServerKeygenWithAPS)

	return est
}
