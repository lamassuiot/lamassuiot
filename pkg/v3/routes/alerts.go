package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/lamassuiot/pkg/v3/controllers"
	"github.com/lamassuiot/lamassuiot/pkg/v3/services"
	"github.com/sirupsen/logrus"
)

func NewAlertsHTTPLayer(logger *logrus.Entry, svc services.AlertsService) *gin.Engine {
	routes := controllers.NewAlertsHttpRoutes(svc)

	router := newGinEngine(logger)
	rv1 := router.Group("/v1")

	rv1.GET("/events/latest", routes.GetUserSubscriptions)

	rv1.GET("/user/:userId/subscriptions", routes.GetUserSubscriptions)
	rv1.POST("/user/:userId/subscribe", routes.Subscribe)
	rv1.POST("/user/:userId/unsubscribe/:subId", routes.Unsubscribe)
	return router
}
