package routes

import (
	"github.com/gin-gonic/gin"
	authzcore "github.com/lamassuiot/authz/pkg/core"
	middleware "github.com/lamassuiot/authz/sdk/gin-middleware"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/controllers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	"github.com/sirupsen/logrus"
)

func NewAlertsHTTPLayer(logger *logrus.Entry, router *gin.RouterGroup, svc services.AlertsService, authzConf config.AuthzClient) {
	registerAlertsRoutes(logger, router, svc, newRemoteAuthzEngine(authzConf, models.AlertsSource, logger))
}

func registerAlertsRoutes(logger *logrus.Entry, router *gin.RouterGroup, svc services.AlertsService, engine authzcore.AuthzEngine) *middleware.ContractRouter {
	routes := controllers.NewAlertsHttpRoutes(svc)

	eventAuthzMw := pkiAuthz(engine, "alerts", "event", logger)
	subscriptionAuthzMw := pkiAuthz(engine, "alerts", "subscription", logger)

	rv1 := middleware.NewContractRouter(router.Group("/v1"))

	rv1.GET("/events/latest", eventAuthzMw.List(), routes.GetLatestEventsPerEventType)

	rv1.GET("/user/:userId/subscriptions", subscriptionAuthzMw.List(), routes.GetUserSubscriptions)
	rv1.POST("/user/:userId/subscribe", subscriptionAuthzMw.Global("create"), routes.Subscribe)
	rv1.POST("/user/:userId/unsubscribe/:subId", subscriptionAuthzMw.Resource("delete", map[string]string{"id": "subId"}), routes.Unsubscribe)
	return rv1
}
