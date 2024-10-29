package headerextractors

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/lamassuiot/v2/core/pkg/models"
	"github.com/sirupsen/logrus"
)

const CtxSource = "REQ_SOURCE"
const CtxRequestID = "REQ_ID"

func updateContextWithRequestWithRequestID(ctx *gin.Context, headers http.Header) {
	reqID := headers.Get("x-request-id")
	if reqID != "" {
		ctx.Set(CtxRequestID, reqID)
	}
}

func updateContextWithRequestWithSource(ctx *gin.Context, headers http.Header) {
	sourceHeader := headers.Get(models.HttpSourceHeader)
	if sourceHeader != "" {
		ctx.Set(CtxSource, sourceHeader)
	}
}

func RequestMetadataToContextMiddleware(logger *logrus.Entry) gin.HandlerFunc {
	return func(c *gin.Context) {

		updateContextWithRequestWithRequestID(c, c.Request.Header)
		updateContextWithRequestWithSource(c, c.Request.Header)
		c.Next()
	}
}
