package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/lamassuiot/v4/backend/pkg/config"
	"github.com/lamassuiot/lamassuiot/v4/backend/pkg/controllers"
	tenantcontext "github.com/lamassuiot/lamassuiot/v4/backend/pkg/routes/middlewares/tenant-context"
	authzcore "github.com/lamassuiot/lamassuiot/v4/connectors/authz/pkg/core"
	middleware "github.com/lamassuiot/lamassuiot/v4/connectors/authz/sdk/gin-middleware"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/services"
	"github.com/sirupsen/logrus"
)

func NewCAHTTPLayer(parentRouterGroup *gin.RouterGroup, svc services.CAService, authzConf config.AuthzClient, logger *logrus.Entry) {
	registerCARoutes(parentRouterGroup, svc, newRemoteAuthzEngine(authzConf, models.CASource, logger), logger)
}

type caRouteContracts struct {
	v1 *middleware.ContractRouter
	v2 *middleware.ContractRouter
}

// Production and tests share these registrations; tests inject a fake authz engine.
func registerCARoutes(parentRouterGroup *gin.RouterGroup, svc services.CAService, engine authzcore.AuthzEngine, logger *logrus.Entry) caRouteContracts {
	routes := controllers.NewCAHttpRoutes(svc)

	// Reject invalid domain declarations before accepting requests.
	caAuthzMw := pkiAuthz(engine, "ca", "ca_certificate", logger)
	certAuthzMw := pkiAuthz(engine, "ca", "certificate", logger)
	profileAuthzMw := pkiAuthz(engine, "ca", "issuance_profile", logger)

	idKey := map[string]string{"id": "id"}
	// Certificate URLs use :sn; the domain primary key is serial_number.
	certSNKey := map[string]string{"serial_number": "sn"}

	registerEndpoints := func(r *middleware.ContractRouter) {
		// Global checks need no resource key; Resource checks use path keys; List computes a read filter.
		// CA endpoints
		r.GET("/cas", caAuthzMw.List(), routes.GetAllCAs)
		r.POST("/cas", caAuthzMw.Global("create"), routes.CreateCA)
		r.POST("/cas/import", caAuthzMw.Global("create"), routes.ImportCA)
		r.GET("/cas/:id", caAuthzMw.Resource("read", idKey), routes.GetCAByID)
		r.GET("/cas/cn/:cn", caAuthzMw.List(), routes.GetCAsByCommonName)
		r.PUT("/cas/:id/metadata", caAuthzMw.Resource("metadata-update", idKey), routes.UpdateCAMetadata)
		r.PATCH("/cas/:id/metadata", caAuthzMw.Resource("metadata-update", idKey), routes.UpdateCAMetadata)
		r.POST("/cas/:id/status", caAuthzMw.Resource("status-update", idKey), routes.UpdateCAStatus)
		r.POST("/cas/:id/profile", caAuthzMw.Resource("metadata-update", idKey), routes.UpdateCAProfile)
		r.POST("/cas/:id/reissue", caAuthzMw.Resource("reissue", idKey), routes.ReissueCA)
		r.GET("/cas/:id/certificates", certAuthzMw.List(), routes.GetCertificatesByCA)
		r.GET("/cas/:id/certificates/status/:status", certAuthzMw.List(), routes.GetCertificatesByCAAndStatus)
		r.POST("/cas/:id/certificates/sign", caAuthzMw.Resource("sign", idKey), routes.SignCertificate)
		r.GET("/cas/:id/certificates/:sn", certAuthzMw.Resource("read", certSNKey), routes.GetCertificateBySerialNumber)
		r.DELETE("/cas/:id", caAuthzMw.Resource("delete", idKey), routes.DeleteCA)

		// Certificate endpoints
		r.GET("/certificates", certAuthzMw.List(), routes.GetCertificates)
		r.GET("/certificates/status/:status", certAuthzMw.List(), routes.GetCertificatesByStatus)
		r.GET("/certificates/expiration", certAuthzMw.List(), routes.GetCertificatesByExpirationDate)
		r.GET("/certificates/stats", certAuthzMw.List(), routes.GetCertificatesStats)
		r.GET("/certificates/:sn", certAuthzMw.Resource("read", certSNKey), routes.GetCertificateBySerialNumber)
		r.GET("/certificates/:sn/key", certAuthzMw.Resource("read-key", certSNKey), routes.GetCertificateKey)
		r.PUT("/certificates/:sn/status", certAuthzMw.Resource("status-update", certSNKey), routes.UpdateCertificateStatus)
		r.PUT("/certificates/:sn/metadata", certAuthzMw.Resource("metadata-update", certSNKey), routes.UpdateCertificateMetadata)
		r.PATCH("/certificates/:sn/metadata", certAuthzMw.Resource("metadata-update", certSNKey), routes.UpdateCertificateMetadata)
		r.DELETE("/certificates/:sn", certAuthzMw.Resource("delete", certSNKey), routes.DeleteCertificate)
		r.POST("/certificates", certAuthzMw.Global("create"), routes.CreateCertificate)
		r.POST("/certificates/import", certAuthzMw.Global("import"), routes.ImportCertificate)

		// Stats endpoints
		r.GET("/stats", caAuthzMw.List(), routes.GetStats)
		r.GET("/stats/:id", caAuthzMw.Resource("read", idKey), routes.GetStatsByCAID)

		// Issuance profile endpoints
		r.GET("/profiles", profileAuthzMw.List(), routes.GetIssuanceProfiles)
		r.GET("/profiles/:id", profileAuthzMw.Resource("read", idKey), routes.GetIssuanceProfileByID)
		r.POST("/profiles", profileAuthzMw.Global("create"), routes.CreateIssuanceProfile)
		r.PUT("/profiles/:id", profileAuthzMw.Resource("update", idKey), routes.UpdateIssuanceProfile)
		r.DELETE("/profiles/:id", profileAuthzMw.Resource("delete", idKey), routes.DeleteIssuanceProfile)
	}

	v1Group := parentRouterGroup.Group("/v1")
	v1Group.Use(tenantcontext.TenantContextMiddleware())
	rv1 := middleware.NewContractRouter(v1Group)
	registerEndpoints(rv1)

	v2Group := parentRouterGroup.Group("/v2/tenants/:" + tenantcontext.PathParamTenantID)
	v2Group.Use(tenantcontext.TenantContextMiddleware())
	rv2 := middleware.NewContractRouter(v2Group)
	registerEndpoints(rv2)

	return caRouteContracts{v1: rv1, v2: rv2}
}
