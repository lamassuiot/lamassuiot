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

func NewValidationRoutes(logger *logrus.Entry, httpGrp *gin.RouterGroup, ocsp services.OCSPService, crl services.CRLService, authzConf config.AuthzClient) {
	registerVARoutes(logger, httpGrp, ocsp, crl, newRemoteAuthzEngine(authzConf, models.VASource, logger))
}

// Public PKI endpoints and protected roles share one complete route contract.
func registerVARoutes(logger *logrus.Entry, httpGrp *gin.RouterGroup, ocsp services.OCSPService, crl services.CRLService, engine authzcore.AuthzEngine) *middleware.ContractRouter {
	vaRoutes := controllers.NewVAHttpRoutes(logger, ocsp, crl)

	vaAuthzMw := pkiAuthz(engine, "va", "va_role", logger)
	contract := middleware.NewContractRouter(httpGrp)

	// OCSP and CRL are public PKI infrastructure endpoints.
	contract.GET("/ocsp/:ocsp_request", middleware.Public(), vaRoutes.Verify)
	contract.POST("/ocsp", middleware.Public(), vaRoutes.Verify)
	contract.GET("/crl/:ca-ski", middleware.Public(), vaRoutes.CRL)

	v1 := contract.Group("/v1")

	// The domain primary key ca_ski is exposed as :ca-ski in the URL.
	skiKey := map[string]string{"ca_ski": "ca-ski"}
	v1.GET("/roles/:ca-ski", vaAuthzMw.Resource("read", skiKey), vaRoutes.GetRoleByID)
	v1.PUT("/roles/:ca-ski", vaAuthzMw.Resource("update", skiKey), vaRoutes.UpdateRole)
	return contract
}
