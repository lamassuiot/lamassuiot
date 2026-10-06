package routes

import (
	"github.com/gin-gonic/gin"
	authzcore "github.com/lamassuiot/authz/pkg/core"
	middleware "github.com/lamassuiot/authz/sdk/gin-middleware"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/controllers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	"github.com/sirupsen/logrus"
)

func NewCAHTTPLayer(parentRouterGroup *gin.RouterGroup, svc services.CAService, authzConf config.AuthzClient, logger *logrus.Entry) {
	registerCARoutes(parentRouterGroup, svc, newRemoteAuthzEngine(authzConf, models.CASource, logger), logger)
}

// Production and tests share these registrations; tests inject a fake authz engine.
func registerCARoutes(parentRouterGroup *gin.RouterGroup, svc services.CAService, engine authzcore.AuthzEngine, logger *logrus.Entry) *middleware.ContractRouter {
	routes := controllers.NewCAHttpRoutes(svc)

	// Reject invalid domain declarations before accepting requests.
	caAuthzMw := pkiAuthz(engine, "ca", "ca_certificate", logger)
	certAuthzMw := pkiAuthz(engine, "ca", "certificate", logger)
	profileAuthzMw := pkiAuthz(engine, "ca", "issuance_profile", logger)
	idKey := map[string]string{"id": "id"}
	// Certificate URLs use :sn; the domain primary key is serial_number.
	certSNKey := map[string]string{"serial_number": "sn"}

	rv1 := middleware.NewContractRouter(parentRouterGroup.Group("/v1"))

	// Global checks need no resource key; Resource checks use path keys; List computes a read filter.
	// CA endpoints
	rv1.GET("/cas", caAuthzMw.List(), routes.GetAllCAs)
	rv1.POST("/cas", caAuthzMw.Global("create"), routes.CreateCA)
	rv1.POST("/cas/import", caAuthzMw.Global("create"), routes.ImportCA)
	rv1.GET("/cas/:id", caAuthzMw.Resource("read", idKey), routes.GetCAByID)
	rv1.GET("/cas/cn/:cn", caAuthzMw.List(), routes.GetCAsByCommonName)
	rv1.PUT("/cas/:id/metadata", caAuthzMw.Resource("metadata-update", idKey), routes.UpdateCAMetadata)
	rv1.PATCH("/cas/:id/metadata", caAuthzMw.Resource("metadata-update", idKey), routes.UpdateCAMetadata)
	rv1.POST("/cas/:id/status", caAuthzMw.Resource("status-update", idKey), routes.UpdateCAStatus)
	rv1.POST("/cas/:id/profile", caAuthzMw.Resource("metadata-update", idKey), routes.UpdateCAProfile)
	rv1.POST("/cas/:id/reissue", caAuthzMw.Resource("reissue", idKey), routes.ReissueCA)
	rv1.GET("/cas/:id/certificates", certAuthzMw.List(), routes.GetCertificatesByCA)
	rv1.GET("/cas/:id/certificates/status/:status", certAuthzMw.List(), routes.GetCertificatesByCAAndStatus)
	rv1.POST("/cas/:id/certificates/sign", caAuthzMw.Resource("sign", idKey), routes.SignCertificate)
	rv1.POST("/cas/:id/signature/sign", caAuthzMw.Resource("sign", idKey), routes.SignatureSign)
	rv1.POST("/cas/:id/signature/verify", caAuthzMw.Resource("read", idKey), routes.SignatureVerify)
	rv1.GET("/cas/:id/certificates/:sn", certAuthzMw.Resource("read", certSNKey), routes.GetCertificateBySerialNumber)
	rv1.DELETE("/cas/:id", caAuthzMw.Resource("delete", idKey), routes.DeleteCA)

	// Certificate endpoints
	rv1.GET("/certificates", certAuthzMw.List(), routes.GetCertificates)
	rv1.GET("/certificates/status/:status", certAuthzMw.List(), routes.GetCertificatesByStatus)
	rv1.GET("/certificates/expiration", certAuthzMw.List(), routes.GetCertificatesByExpirationDate)
	rv1.GET("/certificates/:sn", certAuthzMw.Resource("read", certSNKey), routes.GetCertificateBySerialNumber)
	rv1.PUT("/certificates/:sn/status", certAuthzMw.Resource("status-update", certSNKey), routes.UpdateCertificateStatus)
	rv1.PUT("/certificates/:sn/metadata", certAuthzMw.Resource("metadata-update", certSNKey), routes.UpdateCertificateMetadata)
	rv1.PATCH("/certificates/:sn/metadata", certAuthzMw.Resource("metadata-update", certSNKey), routes.UpdateCertificateMetadata)
	rv1.DELETE("/certificates/:sn", certAuthzMw.Resource("delete", certSNKey), routes.DeleteCertificate)
	rv1.POST("/certificates", certAuthzMw.Global("create"), routes.CreateCertificate)
	rv1.POST("/certificates/import", certAuthzMw.Global("import"), routes.ImportCertificate)

	// Stats endpoints
	rv1.GET("/stats", caAuthzMw.List(), routes.GetStats)
	rv1.GET("/stats/:id", caAuthzMw.Resource("read", idKey), routes.GetStatsByCAID)

	// Issuance profile endpoints
	rv1.GET("/profiles", profileAuthzMw.List(), routes.GetIssuanceProfiles)
	rv1.GET("/profiles/:id", profileAuthzMw.Resource("read", idKey), routes.GetIssuanceProfileByID)
	rv1.POST("/profiles", profileAuthzMw.Global("create"), routes.CreateIssuanceProfile)
	rv1.PUT("/profiles/:id", profileAuthzMw.Resource("update", idKey), routes.UpdateIssuanceProfile)
	rv1.DELETE("/profiles/:id", profileAuthzMw.Resource("delete", idKey), routes.DeleteIssuanceProfile)
	return rv1
}
