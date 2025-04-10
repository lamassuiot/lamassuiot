package headerextractors

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel/trace"
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
		parentTracer := c.Value("otel-go-contrib-tracer")
		tracer, ok := parentTracer.(trace.Tracer)
		var span trace.Span
		if ok {
			_, span = tracer.Start(c.Request.Context(), "Header Extractor")
		}

		updateContextWithRequestWithRequestID(c, c.Request.Header)
		updateContextWithRequestWithSource(c, c.Request.Header)

		span.End()
		c.Next()
	}
}
