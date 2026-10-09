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

func NewDMSManagerHTTPLayer(logger *logrus.Entry, httpGrp *gin.RouterGroup, svc services.DMSManagerService, authzConf config.AuthzClient) {
	registerDMSManagerRoutes(logger, httpGrp, svc, newRemoteAuthzEngine(authzConf, models.DMSManagerSource, logger))
}

func registerDMSManagerRoutes(logger *logrus.Entry, httpGrp *gin.RouterGroup, svc services.DMSManagerService, engine authzcore.AuthzEngine) *middleware.ContractRouter {
	routes := controllers.NewDMSManagerHttpRoutes(svc)

	dmsAuthzMw := pkiAuthz(engine, "dmsmanager", "dms", logger)
	idKey := map[string]string{"id": "id"}

	contract := middleware.NewContractRouter(httpGrp)
	RegisterESTRoutes(logger, contract, svc)

	rv1 := contract.Group("/v1")

	rv1.GET("/stats", dmsAuthzMw.List(), routes.GetStats)
	rv1.GET("/dms", dmsAuthzMw.List(), routes.GetAllDMSs)
	rv1.POST("/dms", dmsAuthzMw.Global("create"), routes.CreateDMS)
	rv1.GET("/dms/:id", dmsAuthzMw.Resource("read", idKey), routes.GetDMSByID)
	rv1.PUT("/dms/:id", dmsAuthzMw.Resource("update", idKey), routes.UpdateDMS)
	rv1.PUT("/dms/:id/metadata", dmsAuthzMw.Resource("update", idKey), routes.UpdateDMSMetadata)
	rv1.PATCH("/dms/:id/metadata", dmsAuthzMw.Resource("update", idKey), routes.UpdateDMSMetadata)
	rv1.DELETE("/dms/:id", dmsAuthzMw.Resource("delete", idKey), routes.DeleteDMS)
	rv1.POST("/dms/bind-identity", dmsAuthzMw.Global("bind-identity"), routes.BindIdentityToDevice)
	return contract
}
