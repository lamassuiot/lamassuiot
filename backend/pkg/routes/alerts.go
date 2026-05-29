package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/controllers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
)

func NewAlertsHTTPLayer(router *gin.RouterGroup, svc services.AlertsService) {
	routes := controllers.NewAlertsHttpRoutes(svc)

	rv1 := router.Group("/v1")

	// registered before /:eventId to avoid route conflict
	rv1.GET("/events/latest", routes.GetLatestEventsPerEventType)
	rv1.GET("/events", routes.GetEvents)
	rv1.GET("/events/:eventId", routes.GetEventByID)

	rv1.GET("/config/event-retention", routes.GetEventRetentionSettings)
	rv1.PUT("/config/event-retention", routes.UpdateEventRetentionSettings)

	rv1.GET("/user/:userId/subscriptions", routes.GetUserSubscriptions)
	rv1.POST("/user/:userId/subscribe", routes.Subscribe)
	rv1.POST("/user/:userId/unsubscribe/:subId", routes.Unsubscribe)
}
