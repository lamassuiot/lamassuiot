package api

import (
	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/authz/pkg/core"
	"github.com/lamassuiot/authz/pkg/engine"
	"github.com/lamassuiot/authz/pkg/service"
	middleware "github.com/lamassuiot/authz/sdk/gin-middleware"
	"github.com/sirupsen/logrus"
)

// NewAuthzRoutes configures all HTTP routes for the authz service.
// authzEngine is the pre-built core.AuthzEngine (built from concrete managers before any
// event-publisher wrapping so it always holds the real storage references).
// principalSvc and policySvc may be wrapped with event/audit publishers.
func NewAuthzRoutes(
	router *gin.RouterGroup,
	authzEngine core.AuthzEngine,
	principalSvc service.PrincipalService,
	eng *engine.Engine,
	policySvc service.PolicyService,
	resolver *service.IdentityResolver,
	logger *logrus.Entry,
) {
	authzCtrl := NewAuthzController(eng, resolver, logger)
	principalCtrl := NewPrincipalController(principalSvc)
	schemaCtrl := NewSchemaController(eng)
	policyCtrl := NewPolicyController(policySvc, principalSvc)
	capabilitiesCtrl := NewCapabilitiesController(eng, principalSvc, policySvc, resolver, logger)

	authzMwPrincipals := middleware.NewSimpleAuthzMiddleware(authzEngine, "authz", "public", "principal", logger)
	authzMwPolicies := middleware.NewSimpleAuthzMiddleware(authzEngine, "authz", "public", "policy", logger)

	v1 := router.Group("/v1")
	{
		// Authorization endpoints — open to any authenticated caller
		authzGrp := v1.Group("/authz")
		{
			authzGrp.POST("/authorize", authzCtrl.Authorize)
			authzGrp.POST("/filter", authzCtrl.GetFilter)
			authzGrp.POST("/match/authorize", authzCtrl.MatchAndAuthorize)
			authzGrp.POST("/match/filter", authzCtrl.MatchAndGetFilter)

			authzGrp.POST("/capabilities/global", capabilitiesCtrl.GetGlobalCapabilities)
			authzGrp.POST("/match/capabilities/global", capabilitiesCtrl.MatchAndGetGlobalCapabilities)

			authzGrp.POST("/capabilities/entity", capabilitiesCtrl.GetEntityCapabilities)
			authzGrp.POST("/match/capabilities/entity", capabilitiesCtrl.MatchAndGetEntityCapabilities)
		}

		// Principal management — protected by authzMwPrincipals
		principals := v1.Group("/principals")
		{
			principals.GET("", authzMwPrincipals.AuthListCheck(), principalCtrl.ListPrincipals)
			principals.POST("", principalCtrl.CreatePrincipal)
			principals.GET("/:id", authzMwPrincipals.AuthzCheck("read"), principalCtrl.GetPrincipal)
			principals.PUT("/:id", authzMwPrincipals.AuthzCheck("update"), principalCtrl.UpdatePrincipal)
			principals.DELETE("/:id", authzMwPrincipals.AuthzCheck("delete"), principalCtrl.DeletePrincipal)

			principals.GET("/:id/policies", authzMwPrincipals.AuthzCheck("read"), principalCtrl.GetPrincipalPolicies)
			principals.POST("/:id/policies", authzMwPrincipals.AuthzCheck("grant"), principalCtrl.GrantPolicy)
			principals.DELETE("/:id/policies/:policyId", authzMwPrincipals.AuthzCheck("revoke"), principalCtrl.RevokePolicy)
		}

		// Policy management — protected by authzMwPolicies
		policies := v1.Group("/policies")
		{
			policies.GET("", authzMwPolicies.AuthListCheck(), policyCtrl.ListPolicies)
			policies.POST("", policyCtrl.CreatePolicy)
			policies.GET("/search", authzMwPolicies.AuthListCheck(), policyCtrl.SearchPolicies)
			policies.GET("/:id", authzMwPolicies.AuthzCheck("read"), policyCtrl.GetPolicy)
			policies.PUT("/:id", authzMwPolicies.AuthzCheck("update"), policyCtrl.UpdatePolicy)
			policies.DELETE("/:id", authzMwPolicies.AuthzCheck("delete"), policyCtrl.DeletePolicy)
			policies.GET("/:id/stats", authzMwPolicies.AuthzCheck("read"), policyCtrl.GetPolicyStats)
		}

		v1.GET("/schemas", schemaCtrl.GetSchemas)
	}
}
