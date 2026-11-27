package tenantcontext

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"unicode"

	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/lamassuiot/v4/core"
)

const (
	HeaderTenantID    = "X-Tenant-ID"
	PathParamTenantID = "tenant_id"
	maxTenantIDLength = 128
)

var (
	ErrMissingTenantID     = errors.New("missing tenant_id in path or X-Tenant-ID header")
	ErrConflictingTenantID = errors.New("conflicting tenant_id between path and X-Tenant-ID header")
	ErrInvalidTenantID     = errors.New("invalid tenant_id format")
)

// ResolveTenantID extracts and validates tenant_id from the route path (:tenant_id)
// or the X-Tenant-ID header. If both are provided, they must match.
func ResolveTenantID(c *gin.Context) (string, error) {
	pathTenant := strings.TrimSpace(c.Param(PathParamTenantID))
	headerTenant := strings.TrimSpace(c.GetHeader(HeaderTenantID))

	if pathTenant != "" && headerTenant != "" && pathTenant != headerTenant {
		return "", ErrConflictingTenantID
	}

	tenantID := pathTenant
	if tenantID == "" {
		tenantID = headerTenant
	}
	if tenantID == "" {
		return "", ErrMissingTenantID
	}
	if !isValidTenantID(tenantID) {
		return "", ErrInvalidTenantID
	}

	return tenantID, nil
}

func isValidTenantID(tenantID string) bool {
	if len(tenantID) == 0 || len(tenantID) > maxTenantIDLength {
		return false
	}
	for _, r := range tenantID {
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			return false
		}
	}
	return true
}

// TenantContextMiddleware resolves tenant_id once per request and stores it in both
// gin.Context and request.Context. Requests without a valid tenant_id fail closed with 400.
func TenantContextMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		tenantID, err := ResolveTenantID(c)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		c.Set(core.LamassuContextKeyTenantID, tenantID)
		c.Request = c.Request.WithContext(core.WithTenantID(c.Request.Context(), tenantID))
		c.Next()
	}
}

// TenantIDFromContext retrieves the resolved tenant_id from a standard context.Context.
func TenantIDFromContext(ctx context.Context) (string, bool) {
	return core.TenantIDFromContext(ctx)
}
