package routes

import (
	"github.com/gin-gonic/gin"
	cmpctl "github.com/lamassuiot/lamassuiot/backend/v3/pkg/controllers/cmp"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	"github.com/sirupsen/logrus"
)

// NewCMPHTTPLayer registers the CMP RA endpoint on the provided router group.
//
// The path /.well-known/cmp/p/:id conforms to RFC 9480 §3.3 (well-known URI
// registration) where :id is the DMS identifier (equivalent to the CMP profile
// name). This path structure is understood natively by standard CMP clients
// such as `openssl cmp -server <host>/.well-known/cmp/p/<dms-id>`.
func NewCMPHTTPLayer(logger *logrus.Entry, rg *gin.RouterGroup, svc services.LightweightCMPService) error {
	routes, err := cmpctl.NewCMPHttpRoutes(logger, svc)
	if err != nil {
		return err
	}

	cmpGrp := rg.Group("/.well-known/cmp")
	cmpGrp.Use(cmpctl.RequirePKIXCMP())
	cmpGrp.POST("/p/:id", routes.HandleCMP)
	return nil
}
