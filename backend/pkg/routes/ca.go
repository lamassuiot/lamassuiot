package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/controllers"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/routes/middlewares/authz"
	cconfig "github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	"github.com/sirupsen/logrus"
)

func NewCAHTTPLayer(logger *logrus.Entry, parentRouterGroup *gin.RouterGroup, routes controllers.CAHttpRoutes, authzConf cconfig.Authorization) error {
	authzMW, err := authz.NewAuthorizationMiddleware(logger, authzConf.RolesClaim, authzConf.RoleMapping, authzConf.Enabled)
	if err != nil {
		return err
	}

	router := parentRouterGroup
	rv1 := router.Group("/v1")

	// Get Crypto Engine Provider
	rv1ViewEngines := rv1.Group("/", authzMW.Use([]authz.Role{authz.RoleCAAdmin, authz.RoleCAUser, authz.RoleCertAdmin, authz.RoleCertUser}))
	rv1ViewEngines.GET("/engines", routes.GetCryptoEngineProvider)

	// Create CA
	rv1CreateCA := rv1.Group("/", authzMW.Use([]authz.Role{authz.RoleCAAdmin}))
	rv1CreateCA.POST("/cas", routes.CreateCA)
	rv1CreateCA.POST("/cas/import", routes.ImportCA)

	// Edit CA
	rv1EditCA := rv1.Group("/", authzMW.Use([]authz.Role{authz.RoleCAAdmin}))
	rv1EditCA.PUT("/cas/:id/issuance-expiration", routes.UpdateCAIssuanceExpiration)

	// View CA
	rv1ViewCA := rv1.Group("/", authzMW.Use([]authz.Role{authz.RoleCAAdmin, authz.RoleCAUser}))
	rv1ViewCA.GET("/cas", routes.GetAllCAs)
	rv1ViewCA.GET("/cas/:id", routes.GetCAByID)
	rv1ViewCA.GET("/cas/cn/:cn", routes.GetCAsByCommonName)

	// Get CA Stats
	rv1GetCAStats := rv1.Group("/", authzMW.Use([]authz.Role{authz.RoleCAAdmin, authz.RoleCAUser}))
	rv1GetCAStats.GET("/stats", routes.GetStats)
	rv1GetCAStats.GET("/stats/:id", routes.GetStatsByCAID)

	// Issue Certificate
	rv1IssueCertificate := rv1.Group("/", authzMW.Use([]authz.Role{authz.RoleCAAdmin, authz.RoleCAIssuer}))
	rv1IssueCertificate.POST("/cas/:id/certificates/sign", routes.SignCertificate)

	// Update CA Status (Revoke CA)
	rv1UpdateCAStatus := rv1.Group("/", authzMW.Use([]authz.Role{authz.RoleCAAdmin}))
	rv1UpdateCAStatus.POST("/cas/:id/status", routes.UpdateCAStatus)

	// Delete CA
	rv1DeleteCA := rv1.Group("/", authzMW.Use([]authz.Role{authz.RoleCAAdmin}))
	rv1DeleteCA.DELETE("/cas/:id", routes.DeleteCA)

	// Sign Arbitrary Data
	rv1CASign := rv1.Group("/", authzMW.Use([]authz.Role{authz.RoleCAAdmin, authz.RoleCASigner}))
	rv1CASign.POST("/cas/:id/signature/sign", routes.SignatureSign)

	rv1.POST("/cas/:id/signature/verify", routes.SignatureVerify) // No authz

	// CA Metadata
	rv1EditCAMetadata := rv1.Group("/", authzMW.Use([]authz.Role{authz.RoleCAAdmin}))
	rv1EditCAMetadata.PUT("/cas/:id/metadata", routes.UpdateCAMetadata)

	//View Certificates
	rv1ViewCerts := rv1.Group("/", authzMW.Use([]authz.Role{
		authz.RoleCAAdmin,
		authz.RoleCAUser,
		authz.RoleCertAdmin,
		authz.RoleCertUser,
	}))
	rv1ViewCerts.GET("/cas/:id/certificates", routes.GetCertificatesByCA)
	rv1ViewCerts.GET("/cas/:id/certificates/status/:status", routes.GetCertificatesByCAAndStatus)
	rv1ViewCerts.GET("/cas/:id/certificates/:sn", routes.GetCertificateBySerialNumber)
	rv1ViewCerts.GET("/certificates", routes.GetCertificates)
	rv1ViewCerts.GET("/certificates/status/:status", routes.GetCertificatesByStatus)
	rv1ViewCerts.GET("/certificates/expiration", routes.GetCertificatesByExpirationDate)
	rv1ViewCerts.GET("/certificates/:sn", routes.GetCertificateBySerialNumber)

	// Update Certificate Status (Revoke Certificate)
	rv1UpdateCertStatus := rv1.Group("/", authzMW.Use([]authz.Role{authz.RoleCAAdmin, authz.RoleCertAdmin}))
	rv1UpdateCertStatus.PUT("/certificates/:sn/status", routes.UpdateCertificateStatus)

	// Update Certificate Metadata
	rv1UpdateCertMetadata := rv1.Group("/", authzMW.Use([]authz.Role{authz.RoleCAAdmin, authz.RoleCertAdmin}))
	rv1UpdateCertMetadata.PUT("/certificates/:sn/metadata", routes.UpdateCertificateMetadata)

	// Import Certificate
	rv1ImportCert := rv1.Group("/", authzMW.Use([]authz.Role{authz.RoleCAAdmin, authz.RoleCertAdmin}))
	rv1ImportCert.POST("/certificates/import", routes.ImportCertificate)

	// Get CA Requests
	rv1GetCARequests := rv1.Group("/", authzMW.Use([]authz.Role{authz.RoleCAAdmin, authz.RoleCAUser}))
	rv1GetCARequests.GET("/cas/:id/requests", routes.GetCARequests)
	rv1GetCARequests.GET("/cas/requests", routes.GetAllRequests)
	rv1GetCARequests.GET("/cas/requests/:id", routes.GetCARequestByID)

	// Request CA
	rv1RequestCA := rv1.Group("/", authzMW.Use([]authz.Role{authz.RoleCAAdmin}))
	rv1RequestCA.POST("/cas/requests", routes.RequestCA)

	// Delete CA Request
	rv1DeleteCARequest := rv1.Group("/", authzMW.Use([]authz.Role{authz.RoleCAAdmin}))
	rv1DeleteCARequest.DELETE("/cas/requests/:id", routes.DeleteCARequestByID)

	return nil
}
