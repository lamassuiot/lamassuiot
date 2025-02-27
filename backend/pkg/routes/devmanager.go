package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/controllers"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/routes/middlewares/authz"
	cconfig "github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	"github.com/sirupsen/logrus"
)

func NewDeviceManagerHTTPLayer(logger *logrus.Entry, parentRouterGroup *gin.RouterGroup, routes controllers.DeviceManagerHttpRoutes, authzConf cconfig.Authorization) error {
	authzMW, err := authz.NewAuthorizationMiddleware(logger, authzConf.RolesClaim, authzConf.RoleMapping, authzConf.Enabled)
	if err != nil {
		return err
	}

	router := parentRouterGroup
	rv1 := router.Group("/v1")

	//Create device
	rv1Create := rv1.Group("/", authzMW.Use([]authz.Role{authz.RoleDeviceAdmin}))
	rv1Create.POST("/devices", routes.CreateDevice)

	//Update device slot
	rv1UpdateSlot := rv1.Group("/", authzMW.Use([]authz.Role{authz.RoleDeviceAdmin}))
	rv1UpdateSlot.PUT("/devices/:id/idslot", routes.UpdateDeviceIdentitySlot)
	rv1UpdateSlot.DELETE("/devices/:id/decommission", routes.DecommissionDevice)

	//Update device metadata
	rv1UpdateMetadata := rv1.Group("/", authzMW.Use([]authz.Role{authz.RoleDeviceAdmin}))
	rv1UpdateMetadata.PUT("/devices/:id/metadata", routes.UpdateDeviceMetadata)

	//Get device stats
	rv1Stats := rv1.Group("/", authzMW.Use([]authz.Role{authz.RoleDeviceAdmin}))
	rv1Stats.GET("/devices/:id/stats", routes.GetStats)

	//View device
	rv1View := rv1.Group("/", authzMW.Use([]authz.Role{authz.RoleDeviceAdmin, authz.RoleDeviceUser}))
	rv1View.GET("/devices/:id", routes.GetDeviceByID)
	rv1View.GET("/devices", routes.GetAllDevices)
	rv1View.GET("/devices/dms/:id", routes.GetDevicesByDMS)

	return nil
}
