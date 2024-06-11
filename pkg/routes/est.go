package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/lamassuiot/v2/pkg/controllers"
	"github.com/lamassuiot/lamassuiot/v2/pkg/services"
	"github.com/sirupsen/logrus"
)

func NewESTHttpRoutes(logger *logrus.Entry, router *gin.RouterGroup, svc services.ESTService) *gin.RouterGroup {
	routes := controllers.NewESTHttpRoutes(logger, svc)

	est := router.Group("/.well-known/est")

	est.GET("/cacerts", routes.GetCACerts)
	est.GET("/:aps/cacerts", routes.GetCACerts)

	est.POST("/simpleenroll", routes.EnrollReenroll)
	est.POST("/:aps/simpleenroll", routes.EnrollReenroll)

	est.POST("/simplereenroll", routes.EnrollReenroll)
	est.POST("/:aps/simplereenroll", routes.EnrollReenroll)

	est.POST("/serverkeygen", routes.ServerKeyGen)
	est.POST("/:aps/serverkeygen", routes.ServerKeyGen)

	return est
}
