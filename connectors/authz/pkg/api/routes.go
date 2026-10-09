package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	authzschemas "github.com/lamassuiot/authz"
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
	registerAuthzRoutes(router, authzEngine, principalSvc, eng, policySvc, resolver, logger)
}

func registerAuthzRoutes(router *gin.RouterGroup, authzEngine core.AuthzEngine, principalSvc service.PrincipalService, eng *engine.Engine, policySvc service.PolicyService, resolver *service.IdentityResolver, logger *logrus.Entry) *middleware.ContractRouter {
	authzCtrl := NewAuthzController(eng, resolver, logger)
	principalCtrl := NewPrincipalController(principalSvc)
	schemaCtrl := NewSchemaController(eng)
	policyCtrl := NewPolicyController(policySvc, principalSvc)
	capabilitiesCtrl := NewCapabilitiesController(eng, principalSvc, policySvc, resolver, logger)
	extAuthzCtrl := NewExtAuthzController(eng, resolver, logger)

	schemas, err := authzschemas.AuthzSchemas()
	if err != nil {
		panic(err)
	}
	principals := middleware.MustNewAuthzMiddleware(authzEngine, schemas, "authz", "public", "principal", logger)
	policies := middleware.MustNewAuthzMiddleware(authzEngine, schemas, "authz", "public", "policy", logger)
	bindings := middleware.MustNewAuthzMiddleware(authzEngine, schemas, "authz", "public", "principal_policy", logger)
	contract := middleware.NewContractRouter(router.Group("/v1"))
	// SDK evaluation calls carry credentials in their body; controllers evaluate them.
	contract.Handle(http.MethodPost, "/authz/authorize", middleware.HandlerAuthorization("evaluation").WithTrustBoundary("internal-service"), authzCtrl.Authorize)
	contract.Handle(http.MethodPost, "/authz/filter", middleware.HandlerAuthorization("evaluation").WithTrustBoundary("internal-service"), authzCtrl.GetFilter)
	contract.Handle(http.MethodPost, "/authz/match/authorize", middleware.HandlerAuthorization("evaluation").WithTrustBoundary("internal-service"), authzCtrl.MatchAndAuthorize)
	contract.Handle(http.MethodPost, "/authz/match/filter", middleware.HandlerAuthorization("evaluation").WithTrustBoundary("internal-service"), authzCtrl.MatchAndGetFilter)
	contract.Handle(http.MethodPost, "/authz/http/check", middleware.HandlerAuthorization("evaluation").WithTrustBoundary("internal-service"), authzCtrl.CheckHTTP)
	contract.Handle(http.MethodPost, "/authz/match/http/check", middleware.HandlerAuthorization("evaluation").WithTrustBoundary("internal-service"), authzCtrl.MatchAndCheckHTTP)
	contract.Handle(http.MethodPost, "/authz/capabilities/global", middleware.HandlerAuthorization("evaluation").WithTrustBoundary("internal-service"), capabilitiesCtrl.GetGlobalCapabilities)
	contract.Handle(http.MethodPost, "/authz/match/capabilities/global", middleware.HandlerAuthorization("evaluation").WithTrustBoundary("internal-service"), capabilitiesCtrl.MatchAndGetGlobalCapabilities)
	contract.Handle(http.MethodPost, "/authz/capabilities/entity", middleware.HandlerAuthorization("evaluation").WithTrustBoundary("internal-service"), capabilitiesCtrl.GetEntityCapabilities)
	contract.Handle(http.MethodPost, "/authz/match/capabilities/entity", middleware.HandlerAuthorization("evaluation").WithTrustBoundary("internal-service"), capabilitiesCtrl.MatchAndGetEntityCapabilities)
	contract.Handle(http.MethodGet, "/principals", principals.List(), principalCtrl.ListPrincipals)
	contract.Handle(http.MethodPost, "/principals", principals.Global("create"), principalCtrl.CreatePrincipal)
	contract.Handle(http.MethodGet, "/principals/:id", principals.Resource("read", map[string]string{"id": "id"}), principalCtrl.GetPrincipal)
	contract.Handle(http.MethodPut, "/principals/:id", principals.Resource("update", map[string]string{"id": "id"}), principalCtrl.UpdatePrincipal)
	contract.Handle(http.MethodDelete, "/principals/:id", principals.Resource("delete", map[string]string{"id": "id"}), principalCtrl.DeletePrincipal)
	contract.Handle(http.MethodGet, "/policies", policies.List(), policyCtrl.ListPolicies)
	contract.Handle(http.MethodPost, "/policies", policies.Global("create"), policyCtrl.CreatePolicy)
	contract.Handle(http.MethodGet, "/policies/:id", policies.Resource("read", map[string]string{"id": "id"}), policyCtrl.GetPolicy)
	contract.Handle(http.MethodPut, "/policies/:id", policies.Resource("update", map[string]string{"id": "id"}), policyCtrl.UpdatePolicy)
	contract.Handle(http.MethodDelete, "/policies/:id", policies.Resource("delete", map[string]string{"id": "id"}), policyCtrl.DeletePolicy)
	contract.Handle(http.MethodGet, "/principals/:id/policies", bindings.Global("read"), principalCtrl.GetPrincipalPolicies)
	contract.Handle(http.MethodPost, "/principals/:id/policies", bindings.Global("grant"), principalCtrl.GrantPolicy)
	contract.Handle(http.MethodDelete, "/principals/:id/policies/:policyId", bindings.Global("revoke"), principalCtrl.RevokePolicy)
	contract.Handle(http.MethodGet, "/policies/search", policies.List(), policyCtrl.SearchPolicies)
	contract.Handle(http.MethodGet, "/policies/:id/stats", policies.Resource("read", map[string]string{"id": "id"}), policyCtrl.GetPolicyStats)
	contract.Handle(http.MethodGet, "/schemas", middleware.Public(), schemaCtrl.GetSchemas)
	// Envoy forwards the original method; record each one so coverage cannot skip it.
	for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodHead, http.MethodOptions, http.MethodDelete, http.MethodTrace} {
		for _, path := range []string{"/ext_authz/check", "/ext_authz/check/*original_url"} {
			contract.Handle(method, path, middleware.HandlerAuthorization("envoy").WithTrustBoundary("internal-gateway"), extAuthzCtrl.Check)
		}
	}
	return contract
}
