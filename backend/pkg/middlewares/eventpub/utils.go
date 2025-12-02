package eventpub

import (
	"context"
	"encoding/json"

	"github.com/ThreeDotsLabs/watermill/message"
	"github.com/lamassuiot/lamassuiot/core/v3"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/sirupsen/logrus"
)

type ICloudEventPublisher interface {
	PublishCloudEvent(ctx context.Context, payload interface{})
}

type CloudEventPublisher struct {
	Publisher message.Publisher
	ServiceID string
	Logger    *logrus.Entry
}

func (cemp *CloudEventPublisher) PublishCloudEvent(ctx context.Context, payload interface{}) {
	event := helpers.BuildCloudEvent(ctx, payload)

	eventBytes, marshalErr := json.Marshal(event)
	if marshalErr != nil {
		cemp.Logger.Errorf("error while serializing event: %s", marshalErr)
		return
	}

	cemp.Logger.Tracef("publishing event: Type=%s Source=%s \n%s", event.Type(), event.Source(), string(eventBytes))

	msg := message.NewMessage(event.ID(), eventBytes)
	msg.SetContext(ctx) // Pass context to publisher decorator for OTEL trace propagation

	cemp.Publisher.Publish(event.Type(), msg)
}

type EventPublisherWithSourceMiddleware struct {
	Publisher ICloudEventPublisher
	Source    string
}

func NewEventPublisherWithSourceMiddleware(publisher ICloudEventPublisher, source string) ICloudEventPublisher {
	return &EventPublisherWithSourceMiddleware{
		Publisher: publisher,
		Source:    source,
	}
}

func (epws *EventPublisherWithSourceMiddleware) PublishCloudEvent(ctx context.Context, payload interface{}) {
	if ctx.Value(core.LamassuContextKeySource) == nil {
		ctx = context.WithValue(ctx, core.LamassuContextKeySource, epws.Source)
	}
	epws.Publisher.PublishCloudEvent(ctx, payload)
}
