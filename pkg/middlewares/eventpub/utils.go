package eventpub

import (
	"context"
	"encoding/json"

	"github.com/ThreeDotsLabs/watermill/message"
	"github.com/lamassuiot/lamassuiot/v2/pkg/eventbus"
	"github.com/lamassuiot/lamassuiot/v2/pkg/models"
	"github.com/sirupsen/logrus"
)

type CloudEventMiddlewarePublisher struct {
	Publisher message.Publisher
	ServiceID string
	Logger    *logrus.Entry
}

func (cemp *CloudEventMiddlewarePublisher) PublishCloudEvent(ctx context.Context, eventType models.EventType, payload interface{}) {
	src := "lrn://" + cemp.ServiceID
	if ctxSource := ctx.Value(models.ContextSourceKey); ctxSource != nil {
		ctxSourceStr, ok := ctxSource.(string)
		if ok {
			src = ctxSourceStr
		}
	}

	event := eventbus.BuildCloudEvent(string(eventType), src, payload)
	eventBytes, marshalErr := json.Marshal(event)
	if marshalErr != nil {
		cemp.Logger.Errorf("error while serializing event: %s", marshalErr)
		return
	}

	cemp.Logger.Tracef("publishing event: Type=%s Source=%s \n%s", eventType, src, string(eventBytes))
	cemp.Publisher.Publish(string(eventType), message.NewMessage(event.ID(), eventBytes))
}
