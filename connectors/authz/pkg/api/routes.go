package api

import (
	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/authz/pkg/engine"
	"github.com/lamassuiot/authz/pkg/service"
	middleware "github.com/lamassuiot/authz/sdk/gin-middleware"
	"github.com/sirupsen/logrus"
)

// SetupRoutes configures all HTTP routes
func NewAuthzRoutes(router *gin.RouterGroup, principalManager *service.PrincipalManager, eng *engine.Engine, policyManager *service.PolicyManager, resolver *service.IdentityResolver, logger *logrus.Entry) {
	// Controllers
	authzCtrl := NewAuthzController(eng, resolver, logger)
	principalCtrl := NewPrincipalController(principalManager)
	schemaCtrl := NewSchemaController(eng)
	policyCtrl := NewPolicyController(policyManager, principalManager)
	capabilitiesCtrl := NewCapabilitiesController(eng, principalManager, policyManager, resolver, logger)

	svc := service.NewAuthzService(eng, principalManager, policyManager, service.WithServiceLogger(logger))

	authzMwPrincipals := middleware.NewSimpleAuthzMiddleware(svc, "authz", "public", "principal", logger)
	authzMwPolicies := middleware.NewSimpleAuthzMiddleware(svc, "authz", "public", "policy", logger)

	_ = authzMwPrincipals
	_ = authzMwPolicies

	// API v1
	v1 := router.Group("/v1")
	{
		// Authorization endpoints
		authzGrp := v1.Group("/authz")
		{
			// Direct authorization with known principal IDs
			authzGrp.POST("/authorize", authzCtrl.Authorize)
			authzGrp.POST("/filter", authzCtrl.GetFilter)
			authzGrp.POST("/match/authorize", authzCtrl.MatchAndAuthorize)
			authzGrp.POST("/match/filter", authzCtrl.MatchAndGetFilter)

			// Global capabilities (principal only – returns global actions per entity type)
			authzGrp.POST("/capabilities/global", capabilitiesCtrl.GetGlobalCapabilities)
			authzGrp.POST("/match/capabilities/global", capabilitiesCtrl.MatchAndGetGlobalCapabilities)

			// Entity capabilities (principal + entity – returns atomic actions for that entity)
			authzGrp.POST("/capabilities/entity", capabilitiesCtrl.GetEntityCapabilities)
			authzGrp.POST("/match/capabilities/entity", capabilitiesCtrl.MatchAndGetEntityCapabilities)
		}

		// Principal management endpoints
		principals := v1.Group("/principals")
		{
			principals.POST("", principalCtrl.CreatePrincipal)
			principals.GET("", principalCtrl.ListPrincipals)
			principals.GET("/:id", principalCtrl.GetPrincipal)
			principals.PUT("/:id", principalCtrl.UpdatePrincipal)
			principals.DELETE("/:id", principalCtrl.DeletePrincipal)

			// Policy assignments
			principals.GET("/:id/policies", principalCtrl.GetPrincipalPolicies)
			principals.POST("/:id/policies", principalCtrl.GrantPolicy)
			principals.DELETE("/:id/policies/:policyId", principalCtrl.RevokePolicy)
		}

		// Policy management endpoints
		policies := v1.Group("/policies")
		{
			policies.POST("", policyCtrl.CreatePolicy)
			policies.GET("", policyCtrl.ListPolicies)
			policies.GET("/search", policyCtrl.SearchPolicies)
			policies.GET("/:id", policyCtrl.GetPolicy)
			policies.PUT("/:id", policyCtrl.UpdatePolicy)
			policies.DELETE("/:id", policyCtrl.DeletePolicy)
			policies.GET("/:id/stats", policyCtrl.GetPolicyStats)
		}

		// Schema endpoints
		v1.GET("/schemas", schemaCtrl.GetSchemas)
	}
}
