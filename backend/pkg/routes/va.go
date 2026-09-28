package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/controllers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	"github.com/sirupsen/logrus"
)

func NewValidationRoutes(logger *logrus.Entry, httpGrp *gin.RouterGroup, ocsp services.OCSPService, crl services.CRLService, options ...TenantRouteOptions) {
	vaRoutes := controllers.NewVAHttpRoutes(logger, ocsp, crl)

	config := tenantRouteOptions(options)
	// CRL and OCSP are public. Certificates carry /tenants/{tenantId}/... URLs;
	// the legacy routes without a tenant serve the default tenant.
	for _, public := range []*gin.RouterGroup{
		httpGrp.Group("", publicTenantMiddleware(config, "va")),
		httpGrp.Group("/tenants/:tenantId", publicTenantMiddleware(config, "va")),
	} {
		public.GET("/ocsp/:ocsp_request", vaRoutes.Verify)
		public.POST("/ocsp", vaRoutes.Verify)
		public.GET("/crl/:ca-ski", vaRoutes.CRL)
	}

	v1, v2 := TenantAwareGroups(httpGrp, config)
	register := func(version *gin.RouterGroup) {
		roleRead := PermissionGroup(version, "va.read", config.Authorization)
		roleManage := PermissionGroup(version, "role.manage", config.Authorization)
		roleRead.GET("/roles/:ca-ski", vaRoutes.GetRoleByID)
		roleManage.PUT("/roles/:ca-ski", vaRoutes.UpdateRole)
	}
	register(v1)
	register(v2)
}
