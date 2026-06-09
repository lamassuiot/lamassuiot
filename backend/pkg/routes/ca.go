package routes

import (
	"fmt"
	"log"

	"github.com/gin-gonic/gin"
	authzSdk "github.com/lamassuiot/authz/sdk"
	middleware "github.com/lamassuiot/authz/sdk/gin-middleware"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/controllers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	"github.com/sirupsen/logrus"
)

func NewCAHTTPLayer(parentRouterGroup *gin.RouterGroup, svc services.CAService, authzConf config.AuthzClient, logger *logrus.Entry) {
	routes := controllers.NewCAHttpRoutes(svc)

	sdkCfg := authzSdk.DefaultConfig(
		fmt.Sprintf("%s://%s:%d%s", authzConf.Protocol, authzConf.Hostname, authzConf.Port, authzConf.BasePath),
		models.CASource,
	)
	sdkCfg.InsecureSkipVerify = authzConf.InsecureSkipVerify
	client, err := authzSdk.NewClient(sdkCfg)
	if err != nil {
		log.Fatalf("Failed to create SDK client: %v", err)
	}

	remoteEngine := authzSdk.NewRemoteEngine(client)
	caAuthzMw := middleware.NewSimpleAuthzMiddleware(remoteEngine, "pki", "ca", "ca_certificate", logger)
	certAuthzMw := middleware.NewSimpleAuthzMiddleware(remoteEngine, "pki", "ca", "certificate", logger)
	profileAuthzMw := middleware.NewSimpleAuthzMiddleware(remoteEngine, "pki", "ca", "issuance_profile", logger)

	// certSNKey maps the :sn URL param to the "serial_number" primary key column
	// expected by the certificate authz schema.
	certSNKey := func(c *gin.Context) map[string]string {
		return map[string]string{"serial_number": c.Param("sn")}
	}

	router := parentRouterGroup
	rv1 := router.Group("/v1")

	// CA endpoints
	rv1.GET("/cas", caAuthzMw.AuthListCheck(), routes.GetAllCAs)
	rv1.POST("/cas", caAuthzMw.AuthzCheck("create"), routes.CreateCA)
	rv1.POST("/cas/import", caAuthzMw.AuthzCheck("create"), routes.ImportCA)
	rv1.GET("/cas/:id", caAuthzMw.AuthzCheck("read"), routes.GetCAByID)
	rv1.GET("/cas/cn/:cn", caAuthzMw.AuthListCheck(), routes.GetCAsByCommonName)
	rv1.PUT("/cas/:id/metadata", caAuthzMw.AuthzCheck("metadata-update"), routes.UpdateCAMetadata)
	rv1.PATCH("/cas/:id/metadata", caAuthzMw.AuthzCheck("metadata-update"), routes.UpdateCAMetadata)
	rv1.POST("/cas/:id/status", caAuthzMw.AuthzCheck("status-update"), routes.UpdateCAStatus)
	rv1.POST("/cas/:id/profile", caAuthzMw.AuthzCheck("metadata-update"), routes.UpdateCAProfile)
	rv1.POST("/cas/:id/reissue", caAuthzMw.AuthzCheck("reissue"), routes.ReissueCA)
	rv1.GET("/cas/:id/certificates", certAuthzMw.AuthListCheck(), routes.GetCertificatesByCA)
	rv1.GET("/cas/:id/certificates/status/:status", certAuthzMw.AuthListCheck(), routes.GetCertificatesByCAAndStatus)
	rv1.POST("/cas/:id/certificates/sign", caAuthzMw.AuthzCheck("sign"), routes.SignCertificate)
	rv1.POST("/cas/:id/signature/sign", caAuthzMw.AuthzCheck("sign"), routes.SignatureSign)
	rv1.POST("/cas/:id/signature/verify", caAuthzMw.AuthzCheck("read"), routes.SignatureVerify)
	rv1.GET("/cas/:id/certificates/:sn", certAuthzMw.AuthzCheckCustom("read", certSNKey), routes.GetCertificateBySerialNumber)
	rv1.DELETE("/cas/:id", caAuthzMw.AuthzCheck("delete"), routes.DeleteCA)

	// Certificate endpoints
	rv1.GET("/certificates", certAuthzMw.AuthListCheck(), routes.GetCertificates)
	rv1.GET("/certificates/status/:status", certAuthzMw.AuthListCheck(), routes.GetCertificatesByStatus)
	rv1.GET("/certificates/expiration", certAuthzMw.AuthListCheck(), routes.GetCertificatesByExpirationDate)
	rv1.GET("/certificates/:sn", certAuthzMw.AuthzCheckCustom("read", certSNKey), routes.GetCertificateBySerialNumber)
	rv1.PUT("/certificates/:sn/status", certAuthzMw.AuthzCheckCustom("status-update/revoke", certSNKey), routes.UpdateCertificateStatus)
	rv1.PUT("/certificates/:sn/metadata", certAuthzMw.AuthzCheckCustom("metadata-update", certSNKey), routes.UpdateCertificateMetadata)
	rv1.PATCH("/certificates/:sn/metadata", certAuthzMw.AuthzCheckCustom("metadata-update", certSNKey), routes.UpdateCertificateMetadata)
	rv1.DELETE("/certificates/:sn", certAuthzMw.AuthzCheckCustom("delete", certSNKey), routes.DeleteCertificate)
	rv1.POST("/certificates", certAuthzMw.AuthzCheck("create"), routes.CreateCertificate)
	rv1.POST("/certificates/import", certAuthzMw.AuthzCheck("import"), routes.ImportCertificate)

	// Stats endpoints
	rv1.GET("/stats", caAuthzMw.AuthListCheck(), routes.GetStats)
	rv1.GET("/stats/:id", caAuthzMw.AuthzCheck("read"), routes.GetStatsByCAID)

	// Issuance profile endpoints
	rv1.GET("/profiles", profileAuthzMw.AuthListCheck(), routes.GetIssuanceProfiles)
	rv1.GET("/profiles/:id", profileAuthzMw.AuthzCheck("read"), routes.GetIssuanceProfileByID)
	rv1.POST("/profiles", profileAuthzMw.AuthzCheck("create"), routes.CreateIssuanceProfile)
	rv1.PUT("/profiles/:id", profileAuthzMw.AuthzCheck("update"), routes.UpdateIssuanceProfile)
	rv1.DELETE("/profiles/:id", profileAuthzMw.AuthzCheck("delete"), routes.DeleteIssuanceProfile)
}
