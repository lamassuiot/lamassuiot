package api

import (
	"fmt"

	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/authz/pkg/authz"
	middleware "github.com/lamassuiot/authz/sdk/gin-middleware"
	"github.com/sirupsen/logrus"
)

// SetupRoutes configures all HTTP routes
func NewAuthzRoutes(router *gin.RouterGroup, principalManager *authz.PrincipalManager, engine *authz.Engine, policyManager *authz.PolicyManager, resolver *authz.IdentityResolver, logger *logrus.Entry) {
	// Controllers
	authzCtrl := NewAuthzController(engine, resolver)
	principalCtrl := NewPrincipalController(principalManager)
	schemaCtrl := NewSchemaController(engine)
	policyCtrl := NewPolicyController(policyManager, principalManager)
	capabilitiesCtrl := NewCapabilitiesController(engine, principalManager, policyManager, resolver)

	svc := authz.NewAuthzService(engine, principalManager, policyManager)

	authzMwPrincipals := middleware.NewSimpleAuthzMiddleware(svc, "authz", "public", "principal", logger)
	authzMwPolicies := middleware.NewSimpleAuthzMiddleware(svc, "authz", "public", "policy", logger)

	fmt.Printf("Setting up routes with authz middleware: %v\n", authzMwPrincipals)
	fmt.Printf("Setting up routes with authz middleware: %v\n", authzMwPolicies)

	// API v1
	v1 := router.Group("/v1")
	{
		// Authorization endpoints
		authz := v1.Group("/authz")
		{
			// Direct authorization with known principal IDs
			authz.POST("/authorize", authzCtrl.Authorize)
			authz.POST("/filter", authzCtrl.GetFilter)
			authz.POST("/match/authorize", authzCtrl.MatchAndAuthorize)
			authz.POST("/match/filter", authzCtrl.MatchAndGetFilter)

			// Global capabilities (principal only – returns global actions per entity type)
			authz.POST("/capabilities/global", capabilitiesCtrl.GetGlobalCapabilities)
			authz.POST("/match/capabilities/global", capabilitiesCtrl.MatchAndGetGlobalCapabilities)

			// Entity capabilities (principal + entity – returns atomic actions for that entity)
			authz.POST("/capabilities/entity", capabilitiesCtrl.GetEntityCapabilities)
			authz.POST("/match/capabilities/entity", capabilitiesCtrl.MatchAndGetEntityCapabilities)
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
