package routes

import (
	"github.com/gin-gonic/gin"
	middleware "github.com/lamassuiot/authz/sdk/gin-middleware"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/controllers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	"github.com/sirupsen/logrus"
)

func NewAlertsHTTPLayer(logger *logrus.Entry, router *gin.RouterGroup, svc services.AlertsService, authzConf config.AuthzClient) {
	routes := controllers.NewAlertsHttpRoutes(svc)

	remoteEngine := newRemoteAuthzEngine(authzConf, models.AlertsSource, logger)
	eventAuthzMw := middleware.NewSimpleAuthzMiddleware(remoteEngine, "pki", "alerts", "event", logger)
	subscriptionAuthzMw := middleware.NewSimpleAuthzMiddleware(remoteEngine, "pki", "alerts", "subscription", logger)

	rv1 := router.Group("/v1")

	rv1.GET("/events/latest", eventAuthzMw.AuthListCheck(), routes.GetLatestEventsPerEventType)

	rv1.GET("/user/:userId/subscriptions", subscriptionAuthzMw.AuthListCheck(), routes.GetUserSubscriptions)
	rv1.POST("/user/:userId/subscribe", subscriptionAuthzMw.AuthzCheck("create"), routes.Subscribe)
	rv1.POST("/user/:userId/unsubscribe/:subId", subscriptionAuthzMw.AuthzCheckCustomField("delete", []string{"subId"}), routes.Unsubscribe)
}
