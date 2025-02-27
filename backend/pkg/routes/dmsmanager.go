package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/controllers"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/routes/middlewares/authz"
	cconfig "github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	"github.com/sirupsen/logrus"
)

func NewDMSManagerHTTPLayer(logger *logrus.Entry, parentRouterGroup *gin.RouterGroup, routes controllers.DMSManagerHttpRoutes, authzConf cconfig.Authorization) error {
	authzMW, err := authz.NewAuthorizationMiddleware(logger, authzConf.RolesClaim, authzConf.RoleMapping, authzConf.Enabled)
	if err != nil {
		return err
	}

	router := parentRouterGroup
	rv1 := router.Group("/v1")

	//Create DMS
	rv1Create := rv1.Group("/", authzMW.Use([]authz.Role{authz.RoleDMSAdmin}))
	rv1Create.POST("/dms", routes.CreateDMS)

	//Update DMS
	rv1Update := rv1.Group("/", authzMW.Use([]authz.Role{authz.RoleDMSAdmin}))
	rv1Update.PUT("/dms/:id", routes.UpdateDMS)

	//Bind identity to device
	rv1BindIdentity := rv1.Group("/", authzMW.Use([]authz.Role{authz.RoleDMSAdmin, authz.RoleDMSUser}))
	rv1BindIdentity.POST("/dms/bind-identity", routes.BindIdentityToDevice)

	//Get DMS stats
	rv1Stats := rv1.Group("/", authzMW.Use([]authz.Role{authz.RoleDMSAdmin, authz.RoleDMSUser}))
	rv1Stats.GET("/stats", routes.GetStats)

	//View DMS
	rv1View := rv1.Group("/", authzMW.Use([]authz.Role{authz.RoleDMSAdmin, authz.RoleDMSUser}))
	rv1View.GET("/dms/:id", routes.GetDMSByID)
	rv1View.GET("/dms", routes.GetAllDMSs)

	return nil
}
