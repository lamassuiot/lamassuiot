package routes

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	identityextractors "github.com/lamassuiot/lamassuiot/backend/v3/pkg/routes/middlewares/identity-extractors"
	tenantcontext "github.com/lamassuiot/lamassuiot/backend/v3/pkg/routes/middlewares/tenant-context"
	cconfig "github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/storage"
)

type TenantRouteOptions struct {
	Memberships      storage.ControlPlaneMembershipRepo
	IdentityProvider tenantcontext.IdentityProvider
	Authorization    tenantcontext.AuthorizationEngine
	JWTValidator     *identityextractors.JWTValidator
	Versioning       cconfig.HttpServerVersioning
	RateLimit        cconfig.HttpServerTenantRateLimit
}

func VersionedGroups(router *gin.RouterGroup) (*gin.RouterGroup, *gin.RouterGroup) {
	return router.Group("/v1"), router.Group("/api/v2/tenants/:tenantId")
}

func TenantAwareGroups(router *gin.RouterGroup, options TenantRouteOptions) (*gin.RouterGroup, *gin.RouterGroup) {
	v1, v2 := VersionedGroups(router)
	v1.Use(NewV1CompatibilityMiddleware(options.Versioning, nil))

	identityProvider := options.IdentityProvider
	if identityProvider == nil {
		identityProvider = func(context.Context) (tenantcontext.AuthenticatedIdentity, error) {
			return tenantcontext.AuthenticatedIdentity{}, errors.New("tenant identity provider is not configured")
		}
	}
	identityRateLimit := tenantcontext.NewIdentityRateLimitMiddleware(options.RateLimit, identityProvider)
	v1.Use(identityRateLimit)
	v1.Use(tenantcontext.NewTenantContextMiddleware(options.Memberships, identityProvider))
	v1.Use(tenantcontext.RequireTenantContextMiddleware())
	v2.Use(identityRateLimit)
	v2.Use(tenantcontext.NewTenantContextMiddleware(options.Memberships, identityProvider))
	v2.Use(tenantcontext.RequireTenantContextMiddleware())
	rateLimit := tenantcontext.NewTenantRateLimitMiddleware(options.RateLimit)
	v1.Use(rateLimit)
	v2.Use(rateLimit)
	return v1, v2
}

func PermissionGroup(router *gin.RouterGroup, operation string, engine tenantcontext.AuthorizationEngine) *gin.RouterGroup {
	if engine == nil {
		return router.Group("", tenantcontext.RequireAuthorizationMiddleware(operation, nil))
	}
	return router.Group("", tenantcontext.RequireAuthorizationMiddleware(operation, engine))
}

func NewV1CompatibilityMiddleware(config cconfig.HttpServerVersioning, now func() time.Time) gin.HandlerFunc {
	if now == nil {
		now = time.Now
	}
	return func(c *gin.Context) {
		if !strings.HasPrefix(c.Request.URL.Path, "/v1/") && c.Request.URL.Path != "/v1" {
			c.Next()
			return
		}
		if config.V1DefaultTenantID == "" || config.V1SunsetAt.IsZero() {
			c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{"error": "v1 compatibility is not configured"})
			return
		}
		if !now().Before(config.V1SunsetAt) {
			c.AbortWithStatusJSON(http.StatusGone, gin.H{"error": "v1 API has been retired; use v2"})
			return
		}
		for _, header := range []string{tenantcontext.TenantIDHeader, tenantcontext.LegacyTenantIDHeader} {
			if value := strings.TrimSpace(c.GetHeader(header)); value != "" && value != config.V1DefaultTenantID {
				c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid v1 tenant context"})
				return
			}
		}
		c.Header("Deprecation", "true")
		c.Header("Sunset", config.V1SunsetAt.UTC().Format(http.TimeFormat))
		c.Header("Link", "</api/v2/tenants/"+config.V1DefaultTenantID+">; rel=\"successor-version\"")
		c.Request.Header.Set(tenantcontext.TenantIDHeader, config.V1DefaultTenantID)
		c.Next()
	}
}
