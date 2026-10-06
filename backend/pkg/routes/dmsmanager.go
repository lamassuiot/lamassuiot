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

func NewDMSManagerHTTPLayer(logger *logrus.Entry, httpGrp *gin.RouterGroup, svc services.DMSManagerService, authzConf config.AuthzClient) {
	newDMSManagerHTTPLayer(logger, httpGrp, svc, authzConf)
}

func newDMSManagerHTTPLayer(logger *logrus.Entry, httpGrp *gin.RouterGroup, svc services.DMSManagerService, authzConf config.AuthzClient) *middleware.ContractRouter {
	return registerDMSManagerRoutes(logger, httpGrp, svc, newRemoteAuthzEngine(authzConf, models.DMSManagerSource, logger))
}

func registerDMSManagerRoutes(logger *logrus.Entry, httpGrp *gin.RouterGroup, svc services.DMSManagerService, engine authzcore.AuthzEngine) *middleware.ContractRouter {
	routes := controllers.NewDMSManagerHttpRoutes(svc)

	schemas, err := authzschemas.PKISchemas()
	if err != nil {
		panic(err)
	}
	dmsAuthzMw := middleware.MustNewAuthzMiddleware(engine, schemas, "pki", "dmsmanager", "dms", logger)

	contract := middleware.NewContractRouter(httpGrp)
	registerESTContract(logger, contract, svc)

	contract.Handle(http.MethodGet, "/v1/stats", dmsAuthzMw.List(), routes.GetStats)
	contract.Handle(http.MethodGet, "/v1/dms", dmsAuthzMw.List(), routes.GetAllDMSs)
	contract.Handle(http.MethodPost, "/v1/dms", dmsAuthzMw.Global("create"), routes.CreateDMS)
	contract.Handle(http.MethodGet, "/v1/dms/:id", dmsAuthzMw.Resource("read", map[string]string{"id": "id"}), routes.GetDMSByID)
	contract.Handle(http.MethodPut, "/v1/dms/:id", dmsAuthzMw.Resource("update", map[string]string{"id": "id"}), routes.UpdateDMS)
	contract.Handle(http.MethodPut, "/v1/dms/:id/metadata", dmsAuthzMw.Resource("update", map[string]string{"id": "id"}), routes.UpdateDMSMetadata)
	contract.Handle(http.MethodPatch, "/v1/dms/:id/metadata", dmsAuthzMw.Resource("update", map[string]string{"id": "id"}), routes.UpdateDMSMetadata)
	contract.Handle(http.MethodDelete, "/v1/dms/:id", dmsAuthzMw.Resource("delete", map[string]string{"id": "id"}), routes.DeleteDMS)
	contract.Handle(http.MethodPost, "/v1/dms/bind-identity", dmsAuthzMw.Global("bind-identity"), routes.BindIdentityToDevice)
	return contract
}
