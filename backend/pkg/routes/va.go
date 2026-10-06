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

func NewValidationRoutes(logger *logrus.Entry, httpGrp *gin.RouterGroup, ocsp services.OCSPService, crl services.CRLService, authzConf config.AuthzClient) {
	newValidationRoutes(logger, httpGrp, ocsp, crl, authzConf)
}

func newValidationRoutes(logger *logrus.Entry, httpGrp *gin.RouterGroup, ocsp services.OCSPService, crl services.CRLService, authzConf config.AuthzClient) *middleware.ContractRouter {
	return registerVARoutes(logger, httpGrp, ocsp, crl, newRemoteAuthzEngine(authzConf, models.VASource, logger))
}

// Public PKI endpoints and protected roles share one complete route contract.
func registerVARoutes(logger *logrus.Entry, httpGrp *gin.RouterGroup, ocsp services.OCSPService, crl services.CRLService, engine authzcore.AuthzEngine) *middleware.ContractRouter {
	vaRoutes := controllers.NewVAHttpRoutes(logger, ocsp, crl)
	schemas, err := authzschemas.PKISchemas()
	if err != nil {
		panic(err)
	}
	vaAuthzMw := middleware.MustNewAuthzMiddleware(engine, schemas, "pki", "va", "va_role", logger)
	contract := middleware.NewContractRouter(httpGrp)

	// OCSP and CRL are public PKI infrastructure endpoints.
	contract.Handle(http.MethodGet, "/ocsp/:ocsp_request", middleware.Public(), vaRoutes.Verify)
	contract.Handle(http.MethodPost, "/ocsp", middleware.Public(), vaRoutes.Verify)
	contract.Handle(http.MethodGet, "/crl/:ca-ski", middleware.Public(), vaRoutes.CRL)

	// The domain primary key ca_ski is exposed as :ca-ski in the URL.
	skiKey := map[string]string{"ca_ski": "ca-ski"}
	contract.Handle(http.MethodGet, "/v1/roles/:ca-ski", vaAuthzMw.Resource("read", skiKey), vaRoutes.GetRoleByID)
	contract.Handle(http.MethodPut, "/v1/roles/:ca-ski", vaAuthzMw.Resource("update", skiKey), vaRoutes.UpdateRole)
	return contract
}
