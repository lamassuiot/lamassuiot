package eventbus

import (
	"fmt"

	"github.com/ThreeDotsLabs/watermill/message"
	"github.com/lamassuiot/lamassuiot/v4/backend/pkg/eventbus/builder"
	cconfig "github.com/lamassuiot/lamassuiot/v4/core/pkg/config"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/engines/eventbus"
	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
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

// NewEventBusEphemeralSubscriber builds a subscriber meant for a per-process serviceID, whose
// broker-side state is removed once the subscriber goes away. Engines that do not implement
// eventbus.EphemeralSubscriberEngine fall back to the regular subscriber, which leaves one queue per
// process behind, and a warning is logged.
func NewEventBusEphemeralSubscriber(conf cconfig.EventBusEngine, serviceID string, logger *logrus.Entry) (message.Subscriber, error) {
	engine, err := builder.BuildEventBusEngine(string(conf.Provider), conf.Config, serviceID, logger)
	if err != nil {
		logger.Errorf("could not generate Event Bus Ephemeral Subscriber: %s", err)
		return nil, err
	}
	if engine == nil {
		err := fmt.Errorf("unknown event bus provider %q", conf.Provider)
		logger.Errorf("could not generate Event Bus Ephemeral Subscriber: %s", err)
		return nil, err
	}

	if ephemeral, ok := engine.(eventbus.EphemeralSubscriberEngine); ok {
		return ephemeral.EphemeralSubscriber()
	}

	logger.Warnf("event bus provider %q does not support ephemeral subscribers; falling back to a regular subscriber (providers that create one durable queue per process, such as AWS SQS/SNS, will leave a queue behind per process)", conf.Provider)
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

	// The topic a CloudEvent is published on is always its event type (see
	// eventpub.CloudEventPublisher.PublishCloudEvent), and the message UUID is its event ID.
	eventType := topic
	eventID := messages[0].UUID

	// Start a producer span
	tracer := otel.GetTracerProvider().Tracer("watermill/publisher")
	ctx, span := tracer.Start(ctx, fmt.Sprintf("amqp.Publisher %s", eventType),
		trace.WithSpanKind(trace.SpanKindProducer),
		trace.WithAttributes(
			semconv.MessagingSystem("amqp"),
			semconv.MessagingDestinationName(topic),
			semconv.MessagingOperationPublish,
			attribute.String("event.type", eventType),
			attribute.String("event.id", eventID),
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
