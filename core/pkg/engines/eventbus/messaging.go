package eventbus

import (
	"fmt"
	"time"

	"github.com/ThreeDotsLabs/watermill/message"
	"github.com/ThreeDotsLabs/watermill/message/router/middleware"
	"github.com/ThreeDotsLabs/watermill/message/router/plugin"
	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel"
	semconv "go.opentelemetry.io/otel/semconv/v1.17.0"
	"go.opentelemetry.io/otel/trace"
)

// messageMetadataCarrier implements propagation.TextMapCarrier for Watermill message metadata
type messageMetadataCarrier struct {
	metadata message.Metadata
}

func (c messageMetadataCarrier) Get(key string) string {
	return c.metadata.Get(key)
}

func (c messageMetadataCarrier) Set(key, value string) {
	c.metadata.Set(key, value)
}

func (c messageMetadataCarrier) Keys() []string {
	keys := make([]string, 0, len(c.metadata))
	for k := range c.metadata {
		keys = append(keys, k)
	}
	return keys
}

// OtelTraceExtractor is a middleware that extracts OTEL trace context from message metadata
// and creates a new span linked to the parent trace
func OtelTraceExtractor(h message.HandlerFunc) message.HandlerFunc {
	return func(msg *message.Message) ([]*message.Message, error) {
		// Extract trace context from message metadata
		ctx := otel.GetTextMapPropagator().Extract(msg.Context(), messageMetadataCarrier{metadata: msg.Metadata})

		// Start a new span as a child of the extracted trace context
		tracer := otel.GetTracerProvider().Tracer("watermill/subscriber")
		handlerName := message.HandlerNameFromCtx(msg.Context())
		topic := message.SubscribeTopicFromCtx(msg.Context())

		ctx, span := tracer.Start(ctx, handlerName,
			trace.WithSpanKind(trace.SpanKindConsumer),
			trace.WithAttributes(
				semconv.MessagingSystem("amqp"),
				semconv.MessagingDestinationName(topic),
				semconv.MessagingOperationReceive,
			),
		)
		defer span.End()

		// Update the message context with the new span context
		msg.SetContext(ctx)

		msgs, err := h(msg)
		if err != nil {
			span.RecordError(err)
		}

		return msgs, err
	}
}

func NewMessageRouter(logger *logrus.Entry, dlqPub message.Publisher) (*message.Router, error) {
	lEventBus := NewLoggerAdapter(logger.WithField("subsystem-provider", "EventBus - Router"))

	router, err := message.NewRouter(message.RouterConfig{}, lEventBus)
	if err != nil {
		return nil, fmt.Errorf("could not create event bus router: %s", err)
	}

	dlqMw, err := middleware.PoisonQueue(dlqPub, "lamassu-dlq")
	if err != nil {
		return nil, fmt.Errorf("could not create poison queue middleware: %s", err)
	}

	router.AddPlugin(plugin.SignalsHandler)

	//mw are applied in order they are added. So the first one is the outermost one (recovery wraps all the others for example)
	router.AddMiddleware(
		// Recoverer handles panics from handlers.
		middleware.Recoverer,

		// Dead letter queue middleware will move messages that have been Nacked more than MaxRetries to a separate topic.
		dlqMw,

		// CorrelationID will copy the correlation id from the incoming message's metadata to the produced messages
		middleware.CorrelationID,

		// Extract OTEL trace context from message metadata and create a child span
		OtelTraceExtractor,

		// The handler function is retried if it returns an error.
		// After MaxRetries, it's up to the PubSub to resend it, mark as ACK or NACK.
		middleware.Retry{
			MaxRetries:      3,
			InitialInterval: time.Second * 2,
			MaxInterval:     time.Second * 10,
			Multiplier:      3,
			Logger:          lEventBus,
		}.Middleware,
	)

	return router, nil
}
