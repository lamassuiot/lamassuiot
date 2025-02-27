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
	r.GET("/crl/:aki", routes.CRL)

	return nil
}
