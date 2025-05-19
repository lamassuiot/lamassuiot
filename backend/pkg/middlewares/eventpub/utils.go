package eventpub

import (
	"context"
	"encoding/json"

	"github.com/ThreeDotsLabs/watermill/message"
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
	cemp.Publisher.Publish(event.Type(), message.NewMessage(event.ID(), eventBytes))
}
