package eventpub

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/ThreeDotsLabs/watermill/message"
	"github.com/cloudevents/sdk-go/v2/event"
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
	var cloudEvent event.Event
	if _, err := core.TenantContextFromContext(ctx); err == nil {
		tenantEvent, buildErr := helpers.BuildTenantCloudEvent(ctx, payload)
		if buildErr != nil {
			cemp.Logger.Errorf("error while building tenant cloud event: %s", buildErr)
			return
		}
		cloudEvent = tenantEvent
	} else if errors.Is(err, core.ErrTenantContextRequired) {
		cloudEvent = helpers.BuildCloudEvent(ctx, payload)
	} else {
		cemp.Logger.Errorf("error while reading tenant context for cloud event: %s", err)
		return
	}

	eventBytes, marshalErr := json.Marshal(cloudEvent)
	if marshalErr != nil {
		cemp.Logger.Errorf("error while serializing event: %s", marshalErr)
		return
	}

	cemp.Logger.Tracef("publishing event: Type=%s Source=%s ID=%s", cloudEvent.Type(), cloudEvent.Source(), cloudEvent.ID())

	msg := message.NewMessage(cloudEvent.ID(), eventBytes)
	msg.SetContext(ctx) // Pass context to publisher decorator for OTEL trace propagation

	cemp.Publisher.Publish(cloudEvent.Type(), msg)
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
