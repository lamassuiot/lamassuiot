package routes

import (
	"github.com/gin-gonic/gin"
	authzcore "github.com/lamassuiot/lamassuiot/v4/connectors/authz/pkg/core"
	middleware "github.com/lamassuiot/lamassuiot/v4/connectors/authz/sdk/gin-middleware"
	"github.com/lamassuiot/lamassuiot/v4/backend/pkg/config"
	"github.com/lamassuiot/lamassuiot/v4/backend/pkg/controllers"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/services"
	"github.com/sirupsen/logrus"
)

func NewValidationRoutes(logger *logrus.Entry, httpGrp *gin.RouterGroup, ocsp services.OCSPService, crl services.CRLService, authzConf config.AuthzClient) {
	registerVARoutes(logger, httpGrp, ocsp, crl, newRemoteAuthzEngine(authzConf, models.VASource, logger))
}

// Public PKI endpoints and protected CRL settings share one complete route contract.
func registerVARoutes(logger *logrus.Entry, httpGrp *gin.RouterGroup, ocsp services.OCSPService, crl services.CRLService, engine authzcore.AuthzEngine) *middleware.ContractRouter {
	vaRoutes := controllers.NewVAHttpRoutes(logger, ocsp, crl)

	vaAuthzMw := pkiAuthz(engine, "va", "crl_settings", logger)
	contract := middleware.NewContractRouter(httpGrp)

	// OCSP and CRL are public PKI infrastructure endpoints.
	contract.GET("/ocsp/:ocsp_request", middleware.Public(), vaRoutes.Verify)
	contract.POST("/ocsp", middleware.Public(), vaRoutes.Verify)
	// :id is the ID of a CA or, for the CDP of the certificates issued before CRL settings moved to the CA ID, its SKI.
	contract.GET("/crl/:id", middleware.Public(), vaRoutes.CRL)

	v1 := contract.Group("/v1")

	// The domain primary key ca_id is exposed as :ca-id in the URL.
	caIDKey := map[string]string{"ca_id": "ca-id"}
	v1.GET("/crl-settings", vaAuthzMw.List(), vaRoutes.GetCRLSettingsList)
	v1.GET("/crl-settings/:ca-id", vaAuthzMw.Resource("read", caIDKey), vaRoutes.GetCRLSettingsByID)
	v1.PUT("/crl-settings/:ca-id", vaAuthzMw.Resource("update", caIDKey), vaRoutes.UpdateCRLSettings)
	return contract
}
