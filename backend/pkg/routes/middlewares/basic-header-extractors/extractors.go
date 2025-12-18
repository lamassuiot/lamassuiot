package headerextractors

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/lamassuiot/core/v3"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/sirupsen/logrus"
)

func updateContextWithSource(ctx *gin.Context, headers http.Header) {
	sourceHeader := headers.Get(models.HttpSourceHeader)
	if sourceHeader != "" {
		// Store in gin.Context for backward compatibility
		ctx.Set(core.LamassuContextKeySource, sourceHeader)
		// Store in request.Context for service access
		reqCtx := context.WithValue(ctx.Request.Context(), core.LamassuContextKeySource, sourceHeader)
		ctx.Request = ctx.Request.WithContext(reqCtx)
	}
}

func RequestMetadataToContextMiddleware(logger *logrus.Entry) gin.HandlerFunc {
	return func(c *gin.Context) {

		updateContextWithSource(c, c.Request.Header)

		// Store the HTTP request in context for services that need access to headers/URL
		reqCtx := context.WithValue(c.Request.Context(), core.LamassuContextKeyHTTPRequest, c.Request)
		c.Request = c.Request.WithContext(reqCtx)

		c.Next()
	}
}
