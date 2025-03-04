package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/controllers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
)

func NewAlertsHTTPLayer(router *gin.RouterGroup, svc services.AlertsService) {
	routes := controllers.NewAlertsHttpRoutes(svc)

	rv1 := router.Group("/v1")

	rv1.GET("/events/latest", routes.GetLatestEventsPerEventType)

	rv1.GET("/user/:userId/subscriptions", routes.GetUserSubscriptions)
	rv1.POST("/user/:userId/subscribe", routes.Subscribe)
	rv1.POST("/user/:userId/unsubscribe/:subId", routes.Unsubscribe)
}
