package eventbus

import (
	"github.com/ThreeDotsLabs/watermill/message"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/eventbus/builder"
	cconfig "github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel"
	semconv "go.opentelemetry.io/otel/semconv/v1.17.0"
	"go.opentelemetry.io/otel/trace"
)

func NewEventBusSubscriber(conf cconfig.EventBusEngine, serviceID string, logger *logrus.Entry) (message.Subscriber, error) {
	engine, err := builder.BuildEventBusEngine(string(conf.Provider), conf.Config, serviceID, logger)
	if err != nil {
		logger.Errorf("could not generate Event Bus Subscriber: %s", err)
		return nil, err
	}

	return engine.Subscriber()
}

func NewEventBusPublisher(conf cconfig.EventBusEngine, serviceID string, logger *logrus.Entry) (message.Publisher, error) {
	engine, err := builder.BuildEventBusEngine(string(conf.Provider), conf.Config, serviceID, logger)
	if err != nil {
		logger.Errorf("could not generate Event Bus Publisher: %s", err)
		return nil, err
	}

	pub, err := engine.Publisher()
	if err != nil {
		logger.Errorf("could not generate Event Bus Publisher: %s", err)
		return nil, err
	}

	return &otelPublisherDecorator{pub: pub}, nil
}

// otelPublisherDecorator wraps a publisher to add OTEL tracing with proper context propagation
type otelPublisherDecorator struct {
	pub message.Publisher
}

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

func (p *otelPublisherDecorator) Publish(topic string, messages ...*message.Message) error {
	if len(messages) == 0 {
		return nil
	}

	// Get context from the first message
	ctx := messages[0].Context()

	// Start a producer span
	tracer := otel.GetTracerProvider().Tracer("watermill/publisher")
	ctx, span := tracer.Start(ctx, "amqp.Publisher",
		trace.WithSpanKind(trace.SpanKindProducer),
		trace.WithAttributes(
			semconv.MessagingSystem("amqp"),
			semconv.MessagingDestinationName(topic),
			semconv.MessagingOperationPublish,
		),
	)
	defer span.End()

	// Inject the NEW span context (not the parent) into message metadata
	// This ensures the subscriber span becomes a child of THIS publisher span
	otel.GetTextMapPropagator().Inject(ctx, messageMetadataCarrier{metadata: messages[0].Metadata})

	// Update message context with the span context
	messages[0].SetContext(ctx)

	err := p.pub.Publish(topic, messages...)
	if err != nil {
		span.RecordError(err)
	}

	return err
}

func (p *otelPublisherDecorator) Close() error {
	return p.pub.Close()
}
