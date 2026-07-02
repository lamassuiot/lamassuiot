package routes

import (
	"github.com/gin-gonic/gin"
	middleware "github.com/lamassuiot/authz/sdk/gin-middleware"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/controllers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	"github.com/sirupsen/logrus"
)

func NewDMSManagerHTTPLayer(logger *logrus.Entry, httpGrp *gin.RouterGroup, svc services.DMSManagerService, authzConf config.AuthzClient) {
	routes := controllers.NewDMSManagerHttpRoutes(svc)

	remoteEngine := newRemoteAuthzEngine(authzConf, models.DMSManagerSource, logger)
	dmsAuthzMw := middleware.NewSimpleAuthzMiddleware(remoteEngine, "pki", "dmsmanager", "dms", logger)

	NewESTHttpRoutes(logger, httpGrp, svc)

	rv1 := httpGrp.Group("/v1")

	rv1.GET("/stats", dmsAuthzMw.AuthListCheck(), routes.GetStats)
	rv1.GET("/dms", dmsAuthzMw.AuthListCheck(), routes.GetAllDMSs)
	rv1.POST("/dms", dmsAuthzMw.AuthzCheck("create"), routes.CreateDMS)
	rv1.GET("/dms/:id", dmsAuthzMw.AuthzCheck("read"), routes.GetDMSByID)
	rv1.PUT("/dms/:id", dmsAuthzMw.AuthzCheck("update"), routes.UpdateDMS)
	rv1.PUT("/dms/:id/metadata", dmsAuthzMw.AuthzCheck("update"), routes.UpdateDMSMetadata)
	rv1.PATCH("/dms/:id/metadata", dmsAuthzMw.AuthzCheck("update"), routes.UpdateDMSMetadata)
	rv1.DELETE("/dms/:id", dmsAuthzMw.AuthzCheck("delete"), routes.DeleteDMS)
	rv1.POST("/dms/bind-identity", dmsAuthzMw.AuthzCheck("bind-identity"), routes.BindIdentityToDevice)
}
