package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/controllers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	"github.com/sirupsen/logrus"
)

func NewDMSManagerHTTPLayer(logger *logrus.Entry, httpGrp *gin.RouterGroup, svc services.DMSManagerService, options ...TenantRouteOptions) {
	routes := controllers.NewDMSManagerHttpRoutes(svc)

	config := tenantRouteOptions(options)
	// EST is public: devices authenticate with their certificates inside the
	// EST service. The tenant comes from the URL, or is the default tenant on
	// the legacy /.well-known/est routes.
	NewESTHttpRoutes(logger, httpGrp, svc, publicTenantMiddleware(config, "est"))
	NewESTHttpRoutes(logger, httpGrp.Group("/tenants/:tenantId"), svc, publicTenantMiddleware(config, "est"))

	v1, v2 := TenantAwareGroups(httpGrp, config)
	register := func(version *gin.RouterGroup) {
		dmsRead := PermissionGroup(version, "dms.read", config.Authorization)
		dmsWrite := PermissionGroup(version, "dms.write", config.Authorization)
		identityBind := PermissionGroup(version, "identity.bind", config.Authorization)
		dmsRead.GET("/stats", routes.GetStats)
		dmsRead.GET("/dms", routes.GetAllDMSs)
		dmsWrite.POST("/dms", routes.CreateDMS)
		dmsRead.GET("/dms/:id", routes.GetDMSByID)
		dmsWrite.PUT("/dms/:id", routes.UpdateDMS)
		dmsWrite.PUT("/dms/:id/metadata", routes.UpdateDMSMetadata)
		dmsWrite.PATCH("/dms/:id/metadata", routes.UpdateDMSMetadata)
		dmsWrite.DELETE("/dms/:id", routes.DeleteDMS)
		identityBind.POST("/dms/bind-identity", routes.BindIdentityToDevice)
	}
	register(v1)
	register(v2)
}
