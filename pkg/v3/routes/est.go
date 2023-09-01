package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/lamassuiot/pkg/v3/controllers"
	"github.com/lamassuiot/lamassuiot/pkg/v3/services"
	"github.com/sirupsen/logrus"
)

func NewESTHttpRoutes(logger *logrus.Entry, router *gin.Engine, svc services.ESTService) *gin.RouterGroup {
	routes := controllers.NewESTHttpRoutes(logger, svc)

	est := router.Group("/.well-known/est")

	est.GET("/cacerts", routes.GetCACerts)
	est.GET("/:aps/cacerts", routes.GetCACerts)

	est.POST("/simpleenroll", routes.EnrollReenroll)
	est.POST("/:aps/simpleenroll", routes.EnrollReenroll)

	est.POST("/simplereenroll", routes.EnrollReenroll)
	est.POST("/:aps/simplereenroll", routes.EnrollReenroll)

	// est.POST("/serverkeygen", routes.ServerKeygen)
	// est.POST("/:aps/serverkeygen", routes.ServerKeygenWithAPS)

	return est
}
