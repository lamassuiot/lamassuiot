package headerextractors

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/lamassuiot/core/v3"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/sirupsen/logrus"
)

func updateContextWithRequestWithSource(ctx *gin.Context, headers http.Header) {
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

		updateContextWithRequestWithSource(c, c.Request.Header)
		c.Next()
	}
}
