package routes

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/controllers"
	tenantcontext "github.com/lamassuiot/lamassuiot/backend/v3/pkg/routes/middlewares/tenant-context"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/services"
	"github.com/sirupsen/logrus"
)

// requireJWTIdentity rejects requests without a validated JWT identity. The
// tenant-manager API does not accept client certificates as identity.
func requireJWTIdentity() gin.HandlerFunc {
	return func(c *gin.Context) {
		if _, err := tenantcontext.JWTIdentityProvider(c.Request.Context()); err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"err": "authenticated identity is required"})
			return
		}
		c.Next()
	}
}

func NewTenantManagerHTTPLayer(logger *logrus.Entry, router *gin.RouterGroup, svc *services.TenantManagerService, options TenantRouteOptions) {
	routes := controllers.NewTenantManagerHttpRoutes(logger, svc)

	api := router.Group("/api/v2", requireJWTIdentity())
	api.GET("/me/memberships", routes.MyMemberships)
	api.POST("/invitations/:code/accept", routes.AcceptInvitation)

	provisioning := api.Group("/provisioning")
	provisioning.POST("/organizations", routes.CreateOrganization)
	provisioning.GET("/organizations", routes.ListOrganizations)
	provisioning.POST("/tenants", routes.CreateTenant)
	provisioning.GET("/tenants", routes.ListTenants)
	provisioning.PUT("/tenants/:tenantId/status", routes.SetTenantStatus)

	config := tenantRouteOptions([]TenantRouteOptions{options})
	config.IdentityProvider = tenantcontext.JWTIdentityProvider
	_, tenantScoped := TenantAwareGroups(router, config)
	membershipRead := PermissionGroup(tenantScoped, "membership.read", config.Authorization)
	membershipWrite := PermissionGroup(tenantScoped, "membership.write", config.Authorization)
	membershipRead.GET("/memberships", routes.ListMemberships)
	membershipWrite.POST("/memberships", routes.AssignMembership)
	membershipWrite.PATCH("/memberships/:membershipId", routes.UpdateMembership)
	membershipWrite.DELETE("/memberships/:membershipId", routes.RevokeMembership)
	membershipRead.GET("/invitations", routes.ListInvitations)
	membershipWrite.POST("/invitations", routes.CreateInvitation)
	membershipWrite.DELETE("/invitations/:invitationId", routes.RevokeInvitation)
}
