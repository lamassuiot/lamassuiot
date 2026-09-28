package routes

import (
	"github.com/gin-gonic/gin"
	tenantcontext "github.com/lamassuiot/lamassuiot/backend/v3/pkg/routes/middlewares/tenant-context"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
)

// publicTenantMiddleware resolves the tenant of public PKI routes (CRL, OCSP,
// EST). Routes without a tenant serve the v1 default tenant, or the migration
// default tenant when none is configured, because certificates issued before
// tenant-scoped URLs belong to it.
func publicTenantMiddleware(options TenantRouteOptions, source string) gin.HandlerFunc {
	getter, _ := options.Memberships.(storage.ActiveTenantGetter)
	legacyTenantID := options.Versioning.V1DefaultTenantID
	if legacyTenantID == "" {
		legacyTenantID = models.DefaultTenantID
	}
	return tenantcontext.NewPublicTenantContextMiddleware(getter, legacyTenantID, source)
}
