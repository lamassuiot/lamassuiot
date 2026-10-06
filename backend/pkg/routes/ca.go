package routes

import (
	"net/http"

	"github.com/gin-gonic/gin"
	authzschemas "github.com/lamassuiot/authz"
	authzcore "github.com/lamassuiot/authz/pkg/core"
	middleware "github.com/lamassuiot/authz/sdk/gin-middleware"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/controllers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	"github.com/sirupsen/logrus"
)

func NewCAHTTPLayer(parentRouterGroup *gin.RouterGroup, svc services.CAService, authzConf config.AuthzClient, logger *logrus.Entry) {
	newCAHTTPLayer(parentRouterGroup, svc, authzConf, logger)
}

// Return the declarations for offline contract tests; the public entry point stays unchanged.
func newCAHTTPLayer(parentRouterGroup *gin.RouterGroup, svc services.CAService, authzConf config.AuthzClient, logger *logrus.Entry) *middleware.ContractRouter {
	return registerCARoutes(parentRouterGroup, svc, newRemoteAuthzEngine(authzConf, models.CASource, logger), logger)
}

// Production and tests share these registrations; tests inject a fake authz engine.
func registerCARoutes(parentRouterGroup *gin.RouterGroup, svc services.CAService, engine authzcore.AuthzEngine, logger *logrus.Entry) *middleware.ContractRouter {
	routes := controllers.NewCAHttpRoutes(svc)
	schemas, err := authzschemas.PKISchemas()
	if err != nil {
		panic(err)
	}
	// Reject invalid domain declarations before accepting requests.
	caAuthzMw := middleware.MustNewAuthzMiddleware(engine, schemas, "pki", "ca", "ca_certificate", logger)
	certAuthzMw := middleware.MustNewAuthzMiddleware(engine, schemas, "pki", "ca", "certificate", logger)
	profileAuthzMw := middleware.MustNewAuthzMiddleware(engine, schemas, "pki", "ca", "issuance_profile", logger)
	idKey := map[string]string{"id": "id"}
	// Certificate URLs use :sn; the domain primary key is serial_number.
	certSNKey := map[string]string{"serial_number": "sn"}

	router := parentRouterGroup
	rv1 := router.Group("/v1")
	contract := middleware.NewContractRouter(rv1)

	// Global checks need no resource key; Resource checks use path keys; List computes a read filter.
	// CA endpoints
	contract.Handle(http.MethodGet, "/cas", caAuthzMw.List(), routes.GetAllCAs)
	contract.Handle(http.MethodPost, "/cas", caAuthzMw.Global("create"), routes.CreateCA)
	contract.Handle(http.MethodPost, "/cas/import", caAuthzMw.Global("create"), routes.ImportCA)
	contract.Handle(http.MethodGet, "/cas/:id", caAuthzMw.Resource("read", idKey), routes.GetCAByID)
	contract.Handle(http.MethodGet, "/cas/cn/:cn", caAuthzMw.List(), routes.GetCAsByCommonName)
	contract.Handle(http.MethodPut, "/cas/:id/metadata", caAuthzMw.Resource("metadata-update", idKey), routes.UpdateCAMetadata)
	contract.Handle(http.MethodPatch, "/cas/:id/metadata", caAuthzMw.Resource("metadata-update", idKey), routes.UpdateCAMetadata)
	contract.Handle(http.MethodPost, "/cas/:id/status", caAuthzMw.Resource("status-update", idKey), routes.UpdateCAStatus)
	contract.Handle(http.MethodPost, "/cas/:id/profile", caAuthzMw.Resource("metadata-update", idKey), routes.UpdateCAProfile)
	contract.Handle(http.MethodPost, "/cas/:id/reissue", caAuthzMw.Resource("reissue", idKey), routes.ReissueCA)
	contract.Handle(http.MethodGet, "/cas/:id/certificates", certAuthzMw.List(), routes.GetCertificatesByCA)
	contract.Handle(http.MethodGet, "/cas/:id/certificates/status/:status", certAuthzMw.List(), routes.GetCertificatesByCAAndStatus)
	contract.Handle(http.MethodPost, "/cas/:id/certificates/sign", caAuthzMw.Resource("sign", idKey), routes.SignCertificate)
	contract.Handle(http.MethodPost, "/cas/:id/signature/sign", caAuthzMw.Resource("sign", idKey), routes.SignatureSign)
	contract.Handle(http.MethodPost, "/cas/:id/signature/verify", caAuthzMw.Resource("read", idKey), routes.SignatureVerify)
	contract.Handle(http.MethodGet, "/cas/:id/certificates/:sn", certAuthzMw.Resource("read", certSNKey), routes.GetCertificateBySerialNumber)
	contract.Handle(http.MethodDelete, "/cas/:id", caAuthzMw.Resource("delete", idKey), routes.DeleteCA)

	// Certificate endpoints
	contract.Handle(http.MethodGet, "/certificates", certAuthzMw.List(), routes.GetCertificates)
	contract.Handle(http.MethodGet, "/certificates/status/:status", certAuthzMw.List(), routes.GetCertificatesByStatus)
	contract.Handle(http.MethodGet, "/certificates/expiration", certAuthzMw.List(), routes.GetCertificatesByExpirationDate)
	contract.Handle(http.MethodGet, "/certificates/:sn", certAuthzMw.Resource("read", certSNKey), routes.GetCertificateBySerialNumber)
	contract.Handle(http.MethodPut, "/certificates/:sn/status", certAuthzMw.Resource("status-update", certSNKey), routes.UpdateCertificateStatus)
	contract.Handle(http.MethodPut, "/certificates/:sn/metadata", certAuthzMw.Resource("metadata-update", certSNKey), routes.UpdateCertificateMetadata)
	contract.Handle(http.MethodPatch, "/certificates/:sn/metadata", certAuthzMw.Resource("metadata-update", certSNKey), routes.UpdateCertificateMetadata)
	contract.Handle(http.MethodDelete, "/certificates/:sn", certAuthzMw.Resource("delete", certSNKey), routes.DeleteCertificate)
	contract.Handle(http.MethodPost, "/certificates", certAuthzMw.Global("create"), routes.CreateCertificate)
	contract.Handle(http.MethodPost, "/certificates/import", certAuthzMw.Global("import"), routes.ImportCertificate)

	// Stats endpoints
	contract.Handle(http.MethodGet, "/stats", caAuthzMw.List(), routes.GetStats)
	contract.Handle(http.MethodGet, "/stats/:id", caAuthzMw.Resource("read", idKey), routes.GetStatsByCAID)

	// Issuance profile endpoints
	contract.Handle(http.MethodGet, "/profiles", profileAuthzMw.List(), routes.GetIssuanceProfiles)
	contract.Handle(http.MethodGet, "/profiles/:id", profileAuthzMw.Resource("read", idKey), routes.GetIssuanceProfileByID)
	contract.Handle(http.MethodPost, "/profiles", profileAuthzMw.Global("create"), routes.CreateIssuanceProfile)
	contract.Handle(http.MethodPut, "/profiles/:id", profileAuthzMw.Resource("update", idKey), routes.UpdateIssuanceProfile)
	contract.Handle(http.MethodDelete, "/profiles/:id", profileAuthzMw.Resource("delete", idKey), routes.DeleteIssuanceProfile)
	return contract
}
