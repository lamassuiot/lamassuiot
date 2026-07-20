package identityextractors

import (
	"net/http"

	"github.com/gin-gonic/gin"
	core "github.com/lamassuiot/lamassuiot/core/v3"
	"github.com/sirupsen/logrus"
)

type IdentityExtractor string

const (
	IdentityExtractorNoAuth IdentityExtractor = "NO_AUTH"
)

type HttpAuthReqExtractor interface {
	ExtractAuthentication(ctx *gin.Context, req http.Request)
}

func RequestMetadataToContextMiddleware(logger *logrus.Entry) gin.HandlerFunc {
	authExtractors := []HttpAuthReqExtractor{
		ClientCertificateExtractor{
			logger: logger,
		},

		JWTExtractor{
			logger: logger,
		},
	}

	return func(c *gin.Context) {
		for _, authExtractor := range authExtractors {
			authExtractor.ExtractAuthentication(c, *c.Request)
			if _, ok := c.Get(core.LamassuContextKeyAuthType); ok {
				break
			}
		}

		c.Next()
	}
}
