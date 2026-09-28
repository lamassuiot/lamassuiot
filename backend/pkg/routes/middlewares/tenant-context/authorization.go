package tenantcontext

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/lamassuiot/core/v3"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
)

type AuthorizationRequest struct {
	Identity      AuthenticatedIdentity
	TenantContext core.TenantContext
	Operation     string
}

type AuthorizationEngine interface {
	Authorize(context.Context, AuthorizationRequest) error
}

type AuthorizationEngineFunc func(context.Context, AuthorizationRequest) error

func (engine AuthorizationEngineFunc) Authorize(ctx context.Context, request AuthorizationRequest) error {
	return engine(ctx, request)
}

var viewerRolePermissions = permissionSet(
	"ca.read", "certificate.read", "profile.read",
	"device.read", "group.read", "dms.read", "va.read", "alert.read",
)

var tenantRolePermissions = map[models.TenantRole]map[string]struct{}{
	models.RoleViewer: viewerRolePermissions,
	models.RoleAuditor: extendPermissionSet(viewerRolePermissions,
		"audit.read",
	),
	models.RoleEnroller: permissionSet(
		"device.read", "dms.read", "dms.enroll", "dms.renew",
	),
	models.RoleOperator: extendPermissionSet(viewerRolePermissions,
		"certificate.issue", "device.write", "device.decommission", "identity.bind",
	),
	models.RolePKIAdmin: extendPermissionSet(viewerRolePermissions,
		"certificate.issue", "certificate.write", "certificate.revoke",
		"ca.write", "profile.write", "role.manage",
	),
	models.RoleTenantAdmin: extendPermissionSet(viewerRolePermissions,
		"tenant.configure", "membership.read", "membership.write", "dms.write", "group.write",
	),
}

func permissionSet(permissions ...string) map[string]struct{} {
	result := make(map[string]struct{}, len(permissions))
	for _, permission := range permissions {
		result[permission] = struct{}{}
	}
	return result
}

func extendPermissionSet(base map[string]struct{}, additional ...string) map[string]struct{} {
	result := make(map[string]struct{}, len(base)+len(additional))
	for permission := range base {
		result[permission] = struct{}{}
	}
	for _, permission := range additional {
		result[permission] = struct{}{}
	}
	return result
}

func NewPermissionAuthorizationEngine() AuthorizationEngine {
	return AuthorizationEngineFunc(func(_ context.Context, request AuthorizationRequest) error {
		if request.TenantContext.ActorType == InternalServiceActorType {
			// Internal services act for a request whose user was already
			// authorized; their certificate is only accepted on the internal
			// listener.
			return nil
		}
		if strings.EqualFold(request.TenantContext.ActorType, "MTLS") {
			return errors.New("mTLS identity has no permission grants")
		}
		rolePermissions, roleExists := tenantRolePermissions[request.TenantContext.EffectiveRole]
		_, roleGrant := rolePermissions[request.Operation]
		serviceKMSGrant := request.TenantContext.EffectiveRole == models.RolePKIAdmin &&
			strings.EqualFold(request.TenantContext.ActorType, "SERVICE") &&
			isServiceKMSPermission(request.Operation)
		if !roleExists || (!roleGrant && !serviceKMSGrant) {
			return errors.New("operation is not granted to the active membership role")
		}

		scopes := lamassuScopes(request.TenantContext.Permissions)
		if serviceKMSGrant || len(scopes) > 0 {
			for _, permission := range scopes {
				if permission == request.Operation {
					return nil
				}
			}
			return errors.New("operation is outside the identity scope")
		}
		return nil
	})
}

// lamassuScopes keeps the token scopes that name a Lamassu permission. Only
// those restrict the role grants; standard OIDC scopes such as "openid",
// "profile" or "email", present in every user token, are ignored so they do
// not deny every operation.
func lamassuScopes(scopes []string) []string {
	result := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		if isLamassuPermission(scope) {
			result = append(result, scope)
		}
	}
	return result
}

func isLamassuPermission(permission string) bool {
	if isServiceKMSPermission(permission) {
		return true
	}
	for _, permissions := range tenantRolePermissions {
		if _, ok := permissions[permission]; ok {
			return true
		}
	}
	return false
}

func isServiceKMSPermission(operation string) bool {
	switch operation {
	case "kms.read", "key.read", "key.manage", "key.import", "key.sign", "key.verify":
		return true
	default:
		return false
	}
}

type authenticatedIdentityContextKey struct{}

func withAuthenticatedIdentity(ctx context.Context, identity AuthenticatedIdentity) context.Context {
	return context.WithValue(ctx, authenticatedIdentityContextKey{}, identity)
}

func AuthenticatedIdentityFromContext(ctx context.Context) (AuthenticatedIdentity, error) {
	identity, ok := ctx.Value(authenticatedIdentityContextKey{}).(AuthenticatedIdentity)
	if !ok || identity.Issuer == "" || identity.Subject == "" || identity.ActorType == "" {
		return AuthenticatedIdentity{}, errors.New("authenticated identity is missing")
	}
	return identity, nil
}

func RequireAuthorizationMiddleware(operation string, engine AuthorizationEngine) gin.HandlerFunc {
	return func(c *gin.Context) {
		if operation == "" {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "authorization is not configured"})
			return
		}
		tenantContext, err := core.RequireTenantContext(c.Request.Context())
		if err != nil {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "tenant context is required"})
			return
		}
		identity, err := AuthenticatedIdentityFromContext(c.Request.Context())
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "authenticated identity is required"})
			return
		}
		if engine == nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "authorization is not configured"})
			return
		}
		if err := engine.Authorize(c.Request.Context(), AuthorizationRequest{
			Identity:      identity,
			TenantContext: tenantContext,
			Operation:     operation,
		}); err != nil {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "operation not authorized"})
			return
		}
		c.Next()
	}
}
