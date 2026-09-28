package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/controllers"
	tenantcontext "github.com/lamassuiot/lamassuiot/backend/v3/pkg/routes/middlewares/tenant-context"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
)

func NewCAHTTPLayer(parentRouterGroup *gin.RouterGroup, svc services.CAService, options ...TenantRouteOptions) {
	routes := controllers.NewCAHttpRoutes(svc)
	config := tenantRouteOptions(options)
	v1, v2 := TenantAwareGroups(parentRouterGroup, config)
	register := func(router *gin.RouterGroup) {
		caRead := PermissionGroup(router, "ca.read", config.Authorization)
		caWrite := PermissionGroup(router, "ca.write", config.Authorization)
		caSign := PermissionGroup(router, "ca.sign", config.Authorization)
		certificateRead := PermissionGroup(router, "certificate.read", config.Authorization)
		certificateWrite := PermissionGroup(router, "certificate.write", config.Authorization)
		certificateIssue := PermissionGroup(router, "certificate.issue", config.Authorization)
		certificateRevoke := PermissionGroup(router, "certificate.revoke", config.Authorization)
		profileRead := PermissionGroup(router, "profile.read", config.Authorization)
		profileWrite := PermissionGroup(router, "profile.write", config.Authorization)

		caRead.GET("/cas", routes.GetAllCAs)
		caWrite.POST("/cas", routes.CreateCA)
		caWrite.POST("/cas/import", routes.ImportCA)
		caRead.GET("/cas/:id", routes.GetCAByID)
		caRead.GET("/cas/cn/:cn", routes.GetCAsByCommonName)
		caWrite.PUT("/cas/:id/metadata", routes.UpdateCAMetadata)
		caWrite.PATCH("/cas/:id/metadata", routes.UpdateCAMetadata)
		caWrite.POST("/cas/:id/status", routes.UpdateCAStatus)
		caWrite.POST("/cas/:id/profile", routes.UpdateCAProfile)
		caWrite.POST("/cas/:id/reissue", routes.ReissueCA)
		certificateRead.GET("/cas/:id/certificates", routes.GetCertificatesByCA)
		certificateRead.GET("/cas/:id/certificates/status/:status", routes.GetCertificatesByCAAndStatus)
		certificateIssue.POST("/cas/:id/certificates/sign", routes.SignCertificate)
		caSign.POST("/cas/:id/signature/sign", routes.SignatureSign)
		caSign.POST("/cas/:id/signature/verify", routes.SignatureVerify)
		certificateRead.GET("/cas/:id/certificates/:sn", routes.GetCertificateBySerialNumber)
		caWrite.DELETE("/cas/:id", routes.DeleteCA)

		certificateRead.GET("/certificates", routes.GetCertificates)
		certificateRead.GET("/certificates/status/:status", routes.GetCertificatesByStatus)
		certificateRead.GET("/certificates/expiration", routes.GetCertificatesByExpirationDate)
		certificateRead.GET("/certificates/:sn", routes.GetCertificateBySerialNumber)
		certificateRevoke.PUT("/certificates/:sn/status", routes.UpdateCertificateStatus)
		certificateWrite.PUT("/certificates/:sn/metadata", routes.UpdateCertificateMetadata)
		certificateWrite.PATCH("/certificates/:sn/metadata", routes.UpdateCertificateMetadata)
		certificateWrite.DELETE("/certificates/:sn", routes.DeleteCertificate)
		certificateWrite.POST("/certificates/import", routes.ImportCertificate)
		certificateIssue.POST("/certificates", routes.CreateCertificate)

		caRead.GET("/stats", routes.GetStats)
		caRead.GET("/stats/:id", routes.GetStatsByCAID)
		profileRead.GET("/profiles", routes.GetIssuanceProfiles)
		profileRead.GET("/profiles/:id", routes.GetIssuanceProfileByID)
		profileWrite.POST("/profiles", routes.CreateIssuanceProfile)
		profileWrite.PUT("/profiles/:id", routes.UpdateIssuanceProfile)
		profileWrite.DELETE("/profiles/:id", routes.DeleteIssuanceProfile)
	}
	register(v1)
	register(v2)
}

func tenantRouteOptions(options []TenantRouteOptions) TenantRouteOptions {
	if len(options) == 0 {
		return TenantRouteOptions{Authorization: tenantcontext.NewPermissionAuthorizationEngine()}
	}
	config := options[0]
	if config.Authorization == nil {
		config.Authorization = tenantcontext.NewPermissionAuthorizationEngine()
	}
	return config
}
