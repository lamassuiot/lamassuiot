package routes

import (
	"net/http"

	"github.com/gin-gonic/gin"
	authzschemas "github.com/lamassuiot/authz"
	authzcore "github.com/lamassuiot/authz/pkg/core"
	middleware "github.com/lamassuiot/authz/sdk/gin-middleware"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/controllers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	"github.com/sirupsen/logrus"
)

func NewAlertsHTTPLayer(logger *logrus.Entry, router *gin.RouterGroup, svc services.AlertsService, authzConf config.AuthzClient) {
	newAlertsHTTPLayer(logger, router, svc, authzConf)
}

func newAlertsHTTPLayer(logger *logrus.Entry, router *gin.RouterGroup, svc services.AlertsService, authzConf config.AuthzClient) *middleware.ContractRouter {
	return registerAlertsRoutes(logger, router, svc, newRemoteAuthzEngine(authzConf, models.AlertsSource, logger))
}

func registerAlertsRoutes(logger *logrus.Entry, router *gin.RouterGroup, svc services.AlertsService, engine authzcore.AuthzEngine) *middleware.ContractRouter {
	routes := controllers.NewAlertsHttpRoutes(svc)

	schemas, err := authzschemas.PKISchemas()
	if err != nil {
		panic(err)
	}
	eventAuthzMw := middleware.MustNewAuthzMiddleware(engine, schemas, "pki", "alerts", "event", logger)
	subscriptionAuthzMw := middleware.MustNewAuthzMiddleware(engine, schemas, "pki", "alerts", "subscription", logger)

	rv1 := router.Group("/v1")
	contract := middleware.NewContractRouter(rv1)

	contract.Handle(http.MethodGet, "/events/latest", eventAuthzMw.List(), routes.GetLatestEventsPerEventType)

	contract.Handle(http.MethodGet, "/user/:userId/subscriptions", subscriptionAuthzMw.List(), routes.GetUserSubscriptions)
	contract.Handle(http.MethodPost, "/user/:userId/subscribe", subscriptionAuthzMw.Global("create"), routes.Subscribe)
	contract.Handle(http.MethodPost, "/user/:userId/unsubscribe/:subId", subscriptionAuthzMw.Resource("delete", map[string]string{"id": "subId"}), routes.Unsubscribe)
	return contract
}
