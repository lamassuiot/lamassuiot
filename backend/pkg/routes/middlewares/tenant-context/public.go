package tenantcontext

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/lamassuiot/lamassuiot/core/v3"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
)

// PublicActorType identifies unauthenticated PKI clients (CRL/OCSP relying
// parties and EST devices before the service checks their credentials).
const PublicActorType = "PUBLIC"

// NewPublicTenantContextMiddleware builds the TenantContext of public PKI
// endpoints (CRL, OCSP, EST) from the tenant in the route, or from
// legacyTenantID on routes without a tenant, which serve certificates issued
// before tenant-scoped URLs. The tenant must exist and be ACTIVE; unknown,
// suspended and malformed tenants get the same 404 so tenants cannot be
// enumerated. No membership is involved: the endpoint remains responsible for
// authenticating the client when the protocol requires it.
func NewPublicTenantContextMiddleware(tenants storage.ActiveTenantGetter, legacyTenantID string, source string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if tenants == nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"err": "tenant resolution is not configured"})
			return
		}
		tenantID := strings.TrimSpace(c.Param("tenantId"))
		if tenantID == "" {
			tenantID = legacyTenantID
		}
		if !validTenantID(tenantID) {
			c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"err": "not found"})
			return
		}
		tenant, err := tenants.GetActiveTenant(c.Request.Context(), tenantID)
		if err != nil || tenant == nil || tenant.Status != models.TenantActive {
			c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"err": "not found"})
			return
		}
		correlationID := c.GetHeader(models.HttpRequestIDHeader)
		if correlationID == "" {
			correlationID = uuid.NewString()
		}
		c.Request = c.Request.WithContext(core.WithTenantContext(c.Request.Context(), core.TenantContext{
			OrganizationID: tenant.OrganizationID,
			TenantID:       tenant.ID,
			ActorID:        "anonymous",
			ActorType:      PublicActorType,
			CorrelationID:  correlationID,
			Source:         source,
			TenantStatus:   core.TenantActive,
			Validated:      true,
		}))
		c.Next()
	}
}
