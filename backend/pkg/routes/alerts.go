package routes

import (
	"log"

	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/authz/sdk"
	authzSdk "github.com/lamassuiot/authz/sdk"
	middleware "github.com/lamassuiot/authz/sdk/gin-middleware"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/controllers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	"github.com/sirupsen/logrus"
)

func NewAlertsHTTPLayer(logger *logrus.Entry, router *gin.RouterGroup, svc services.AlertsService) {
	routes := controllers.NewAlertsHttpRoutes(svc)

	config := sdk.DefaultConfig("http://localhost:8888")
	client, err := sdk.NewClient(config)
	if err != nil {
		log.Fatalf("Failed to create SDK client: %v", err)
	}

	remoteEngine := authzSdk.NewRemoteEngine(client)
	eventAuthzMw := middleware.NewAuthzMiddleware(remoteEngine, "pki", "alerts", "event", logger)
	subscriptionAuthzMw := middleware.NewAuthzMiddleware(remoteEngine, "pki", "alerts", "subscription", logger)

	rv1 := router.Group("/v1")

	rv1.GET("/events/latest", eventAuthzMw.AuthListCheck(), routes.GetLatestEventsPerEventType)

	rv1.GET("/user/:userId/subscriptions", subscriptionAuthzMw.AuthListCheck(), routes.GetUserSubscriptions)
	rv1.POST("/user/:userId/subscribe", subscriptionAuthzMw.AuthzCheck("create"), routes.Subscribe)
	rv1.POST("/user/:userId/unsubscribe/:subId", subscriptionAuthzMw.AuthzCheckCustomField("delete", "subId"), routes.Unsubscribe)
}
