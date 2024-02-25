package eventbus

import (
	"encoding/json"
	"time"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/cloudevents/sdk-go/v2/event"
	"github.com/jakehl/goid"
)

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
