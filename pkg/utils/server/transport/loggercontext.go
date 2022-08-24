package transport

import (
	"context"
	"net/http"

	httptransport "github.com/go-kit/kit/transport/http"
	"github.com/go-kit/log"
	"github.com/lamassuiot/lamassuiot/pkg/utils/server"
	stdopentracing "github.com/opentracing/opentracing-go"
)

func HTTPToContext(logger log.Logger) httptransport.RequestFunc {
	return func(ctx context.Context, req *http.Request) context.Context {
		// Try to join to a trace propagated in `req`.
		uberTraceId := req.Header.Values("Uber-Trace-Id")
		if uberTraceId != nil {
			logger = log.With(logger, "span_id", uberTraceId)
		} else {
			span := stdopentracing.SpanFromContext(ctx)
			logger = log.With(logger, "span_id", span)
		}
		return context.WithValue(ctx, server.LoggerContextKey, logger)
	}
}
