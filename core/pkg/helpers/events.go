package helpers

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/cloudevents/sdk-go/v2/event"
	"github.com/jakehl/goid"
	"github.com/lamassuiot/lamassuiot/core/v3"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
)

func BuildCloudEvent(ctx context.Context, payload interface{}) event.Event {
	event := cloudevents.NewEvent()

	event.SetSpecVersion("1.0")
	event.SetTime(time.Now())
	event.SetID(goid.NewV4UUID().String())
	event.SetData(cloudevents.ApplicationJSON, payload)

	eventSource, ok := ctx.Value(core.LamassuContextKeySource).(string)
	if ok {
		event.SetSource(fmt.Sprintf("source://%s/%s", core.LamassuContextKeySource, eventSource))
	} else {
		event.SetSource("source://unknown")
	}

	eventType, ok := ctx.Value(core.LamassuContextKeyEventType).(string)
	if ok {
		event.SetType(eventType)
	} else if typedEventType, ok := ctx.Value(core.LamassuContextKeyEventType).(models.EventType); ok {
		event.SetType(string(typedEventType))
	}

	eventSubject, ok := ctx.Value(core.LamassuContextKeyEventSubject).(string)
	if ok {
		event.SetSubject(eventSubject)
	}

	if eventAuthType, ok := ctx.Value(core.LamassuContextKeyAuthType).(string); ok && eventAuthType != "" {
		event.SetExtension("authtype", eventAuthType)
	}

	if eventAuthID, ok := ctx.Value(core.LamassuContextKeyAuthID).(string); ok && eventAuthID != "" {
		event.SetExtension("authtid", eventAuthID)
	}

	if eventAuthCtx, ok := ctx.Value(core.LamassuContextKeyAuthContext).(map[string]interface{}); ok && eventAuthCtx != nil {
		// extensions dont allow nested objects. Must serialize to string
		eventAuthCtxBytes, err := json.Marshal(eventAuthCtx)
		if err != nil {
			eventAuthCtxBytes = []byte("{}")
		}
		event.SetExtension("authclaims", string(eventAuthCtxBytes))
	}

	return event
}

func ParseCloudEvent(msg []byte) (*event.Event, error) {
	var event cloudevents.Event
	fmt.Println(string(msg))
	err := json.Unmarshal(msg, &event)
	if err != nil {
		return nil, err
	}

	return &event, nil
}

func GetEventBody[E any](cloudEvent *event.Event) (*E, error) {
	var elem *E
	if cloudEvent == nil {
		return nil, fmt.Errorf("cloud event is null")
	}

	if cloudEvent.Data() == nil {
		return nil, fmt.Errorf("cloud event data is null")
	}

	eventDataBytes := cloudEvent.Data()
	err := json.Unmarshal(eventDataBytes, &elem)
	return elem, err
}
