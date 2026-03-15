package routes

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/controllers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	"github.com/sirupsen/logrus"
)

// NewCMPHTTPLayer registers the CMP RA endpoint on the provided router group.
//
// The path /.well-known/cmp/p/:id conforms to RFC 9480 §3.3 (well-known URI
// registration) where :id is the DMS identifier (equivalent to the CMP profile
// name). This path structure is understood natively by standard CMP clients
// such as `openssl cmp -server <host>/.well-known/cmp/p/<dms-id>`.
//
// A content-type guard middleware rejects requests that do not carry the
// application/pkixcmp media type (RFC 6712 §3.1).
func NewCMPHTTPLayer(logger *logrus.Entry, rg *gin.RouterGroup, svc services.LightweightCMPService) {
	routes := controllers.NewCMPHttpRoutes(logger, svc)

	cmpGrp := rg.Group("/.well-known/cmp")
	cmpGrp.Use(requirePKIXCMP())
	cmpGrp.POST("/p/:id", routes.HandleCMP)
}

// requirePKIXCMP is a Gin middleware that rejects requests whose Content-Type
// is not application/pkixcmp with HTTP 415 Unsupported Media Type.
func requirePKIXCMP() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		ct := ctx.GetHeader("Content-Type")
		if ct != "application/pkixcmp" {
			ctx.AbortWithStatusJSON(http.StatusUnsupportedMediaType, gin.H{
				"error": "Content-Type must be application/pkixcmp",
			})
			return
		}
		ctx.Next()
	}
}
