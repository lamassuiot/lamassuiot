package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/controllers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
)

func NewAlertsHTTPLayer(router *gin.RouterGroup, svc services.AlertsService, options ...TenantRouteOptions) {
	routes := controllers.NewAlertsHttpRoutes(svc)

	config := tenantRouteOptions(options)
	v1, v2 := TenantAwareGroups(router, config)
	register := func(version *gin.RouterGroup) {
		alertRead := PermissionGroup(version, "alert.read", config.Authorization)
		subscriptionManage := PermissionGroup(version, "subscription.manage", config.Authorization)
		alertRead.GET("/events/latest", routes.GetLatestEventsPerEventType)
		alertRead.GET("/user/:userId/subscriptions", routes.GetUserSubscriptions)
		subscriptionManage.POST("/user/:userId/subscribe", routes.Subscribe)
		subscriptionManage.POST("/user/:userId/unsubscribe/:subId", routes.Unsubscribe)
	}
	register(v1)
	register(v2)
}
