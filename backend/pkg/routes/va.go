package routes

import (
	"log"

	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/authz/sdk"
	authzSdk "github.com/lamassuiot/authz/sdk"
	middleware "github.com/lamassuiot/authz/sdk/gin-middleware"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/controllers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	"github.com/sirupsen/logrus"
)

func NewValidationRoutes(logger *logrus.Entry, httpGrp *gin.RouterGroup, ocsp services.OCSPService, crl services.CRLService) {
	vaRoutes := controllers.NewVAHttpRoutes(logger, ocsp, crl)

	config := sdk.DefaultConfig("http://localhost:8888")
	client, err := sdk.NewClient(config)
	if err != nil {
		log.Fatalf("Failed to create SDK client: %v", err)
	}

	remoteEngine := authzSdk.NewRemoteEngine(client)
	vaAuthzMw := middleware.NewSimpleAuthzMiddleware(remoteEngine, "pki", "va", "va_role", logger)

	// OCSP and CRL are public PKI infrastructure endpoints - no authz required
	httpGrp.GET("/ocsp/:ocsp_request", vaRoutes.Verify)
	httpGrp.POST("/ocsp", vaRoutes.Verify)
	httpGrp.GET("/crl/:ca-ski", vaRoutes.CRL)

	v1 := httpGrp.Group("/v1")

	v1.GET("/roles/:ca-ski", vaAuthzMw.AuthzCheckCustomField("read", []string{"ca-ski"}), vaRoutes.GetRoleByID)
	v1.PUT("/roles/:ca-ski", vaAuthzMw.AuthzCheckCustomField("update", []string{"ca-ski"}), vaRoutes.UpdateRole)
}
