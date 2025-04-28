package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/controllers"
	cconfig "github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	"github.com/sirupsen/logrus"
)

func NewVAHTTPLayer(logger *logrus.Entry, parentRouterGroup *gin.RouterGroup, routes controllers.VAHttpRoutes, authzConf cconfig.Authorization) error {
	router := parentRouterGroup
	r := router.Group("/")

	r.GET("/ocsp/:ocsp_request", routes.Verify)
	r.POST("/ocsp", routes.Verify)
	r.GET("/crl/:ca-ski", routes.CRL)

	r.GET("/roles", routes.GetRoles)
	r.GET("/roles/:ca-ski", routes.GetRoleByID)
	r.PUT("/roles/:ca-ski", routes.UpdateRole)

	return nil
}
