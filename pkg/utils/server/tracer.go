package server

import (
	"context"
	"net/http"
	"strings"

	amqptransport "github.com/go-kit/kit/transport/amqp"
	"github.com/streadway/amqp"
	"go.opentelemetry.io/otel/trace"
)

func InjectTracingToContext(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		xRequestID := r.Header.Get("X-Request-ID")
		splitRequestID := strings.Split(xRequestID, ":")
		if len(splitRequestID) != 2 {
			next.ServeHTTP(w, r)
		} else {
			traceID, _ := trace.TraceIDFromHex(splitRequestID[0])
			spanID, _ := trace.SpanIDFromHex(splitRequestID[1])

			spanContext := trace.NewSpanContext(trace.SpanContextConfig{
				TraceID: traceID,
				SpanID:  spanID,
			})

			ctx := trace.ContextWithSpanContext(r.Context(), spanContext)

			r = r.WithContext(ctx)
			next.ServeHTTP(w, r)
		}
	})
}

func InjectTracingToContextFromAMQP() amqptransport.RequestFunc {
	return func(ctx context.Context, pub *amqp.Publishing, del *amqp.Delivery) context.Context {
		traceHeader, ok := del.Headers["traceparent"].(string)
		if !ok {
			return ctx
		}

		splitedTrace := strings.Split(traceHeader, ":")
		traceID, err := trace.TraceIDFromHex(splitedTrace[0])
		if err != nil {
			return ctx
		}

		spanID, err := trace.SpanIDFromHex(splitedTrace[1])
		if err != nil {
			return ctx
		}

		parentSpanContext := trace.NewSpanContext(trace.SpanContextConfig{
			TraceID: traceID,
			SpanID:  spanID,
		})

		ctx = trace.ContextWithSpanContext(ctx, parentSpanContext)

		return ctx
	}
}
