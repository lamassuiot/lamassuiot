package messaging

import (
	"context"
	"encoding/json"
	"time"

	"github.com/ThreeDotsLabs/watermill/message"
	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/cloudevents/sdk-go/v2/event"
	"github.com/jakehl/goid"
	"github.com/lamassuiot/lamassuiot/v2/pkg/models"
)

func (engine *MessagingEngine) PublishCloudEvent(ctx context.Context, eventType models.EventType, payload interface{}) {
	src := engine.serviceID
	if ctxSource := ctx.Value(models.ContextSourceKey); ctxSource != nil {
		ctxSourceStr, ok := ctxSource.(string)
		if ok {
			src = ctxSourceStr
		}
	}

	src = "lrn://internal-service"

	event := BuildCloudEvent(string(eventType), src, payload)
	eventBytes, marshalErr := json.Marshal(event)
	if marshalErr != nil {
		engine.logger.Errorf("error while serializing event: %s", marshalErr)
		return
	}

	engine.logger.Tracef("publishing event: Type=%s Source=%s \n%s", eventType, src, string(eventBytes))

	engine.publisher.Publish(string(eventType), message.NewMessage(event.ID(), eventBytes))
}

func BuildCloudEvent(eventType string, eventSource string, payload interface{}) event.Event {
	event := cloudevents.NewEvent()
	event.SetSpecVersion("1.0")
	event.SetSource(eventSource)
	event.SetType(eventType)
	event.SetTime(time.Now())
	event.SetID(goid.NewV4UUID().String())
	event.SetData(cloudevents.ApplicationJSON, payload)
	return event
}

func ParseCloudEvent(msg []byte) (*event.Event, error) {
	var event cloudevents.Event
	err := json.Unmarshal(msg, &event)
	if err != nil {
		return nil, err
	}

	return &event, nil
}
