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

func NewValidationRoutes(logger *logrus.Entry, httpGrp *gin.RouterGroup, ocsp services.OCSPService, crl services.CRLService, authzConf config.AuthzClient) {
	vaRoutes := controllers.NewVAHttpRoutes(logger, ocsp, crl)

	sdkCfg := authzSdk.DefaultConfig(
		fmt.Sprintf("%s://%s:%d%s", authzConf.Protocol, authzConf.Hostname, authzConf.Port, authzConf.BasePath),
		models.VASource,
	)
	sdkCfg.InsecureSkipVerify = authzConf.InsecureSkipVerify
	client, err := authzSdk.NewClient(sdkCfg)
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

	skiKey := func(c *gin.Context) map[string]string { return map[string]string{"ca_ski": c.Param("ca-ski")} }
	v1.GET("/roles/:ca-ski", vaAuthzMw.AuthzCheckCustom("read", skiKey), vaRoutes.GetRoleByID)
	v1.PUT("/roles/:ca-ski", vaAuthzMw.AuthzCheckCustom("update", skiKey), vaRoutes.UpdateRole)
}
