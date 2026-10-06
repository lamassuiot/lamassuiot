package routes

import (
	"net/http"

	"github.com/gin-gonic/gin"
	middleware "github.com/lamassuiot/authz/sdk/gin-middleware"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/controllers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	"github.com/sirupsen/logrus"
)

func NewESTHttpRoutes(logger *logrus.Entry, router *gin.RouterGroup, svc services.ESTService) *gin.RouterGroup {
	est := router.Group("/.well-known/est")
	contract := middleware.NewContractRouter(router)
	registerESTContract(logger, contract, svc)
	return est
}

// Enrollment policy is evaluated by ESTService using the selected authentication profile.
func registerESTContract(logger *logrus.Entry, contract *middleware.ContractRouter, svc services.ESTService) {
	routes := controllers.NewESTHttpRoutes(logger, svc)
	for _, prefix := range []string{"/.well-known/est", "/.well-known/est/:aps"} {
		contract.Handle(http.MethodGet, prefix+"/cacerts", middleware.Public(), routes.GetCACerts)
		contract.Handle(http.MethodPost, prefix+"/simpleenroll", middleware.HandlerAuthorization("est"), routes.EnrollReenroll)
		contract.Handle(http.MethodPost, prefix+"/simplereenroll", middleware.HandlerAuthorization("est"), routes.EnrollReenroll)
		contract.Handle(http.MethodPost, prefix+"/serverkeygen", middleware.HandlerAuthorization("est"), routes.ServerKeyGen)
	}
}
