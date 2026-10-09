package routes

import (
	middleware "github.com/lamassuiot/authz/sdk/gin-middleware"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/controllers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	"github.com/sirupsen/logrus"
)

// RegisterESTRoutes mounts the EST endpoints (RFC 7030) under /.well-known/est on the given
// contract router. It is backed by any services.ESTService, so it can be reused by other
// modules (e.g. an EST proxy) besides the DMS Manager.
//
// Enrollment policy is evaluated by ESTService using the selected authentication profile.
func RegisterESTRoutes(logger *logrus.Entry, contract *middleware.ContractRouter, svc services.ESTService) {
	routes := controllers.NewESTHttpRoutes(logger, svc)

	est := contract.Group("/.well-known/est")

	est.GET("/cacerts", middleware.Public(), routes.GetCACerts)
	est.GET("/:aps/cacerts", middleware.Public(), routes.GetCACerts)

	est.POST("/simpleenroll", middleware.HandlerAuthorization("est"), routes.EnrollReenroll)
	est.POST("/:aps/simpleenroll", middleware.HandlerAuthorization("est"), routes.EnrollReenroll)

	est.POST("/simplereenroll", middleware.HandlerAuthorization("est"), routes.EnrollReenroll)
	est.POST("/:aps/simplereenroll", middleware.HandlerAuthorization("est"), routes.EnrollReenroll)

	est.POST("/serverkeygen", middleware.HandlerAuthorization("est"), routes.ServerKeyGen)
	est.POST("/:aps/serverkeygen", middleware.HandlerAuthorization("est"), routes.ServerKeyGen)
}
