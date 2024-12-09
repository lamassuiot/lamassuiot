package helpers

import (
	"encoding/json"
	"testing"
	"time"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/stretchr/testify/assert"
)

func TestBuildCloudEvent(t *testing.T) {
	eventType := "com.example.event"
	eventSource := "/my/source"
	payload := map[string]string{"key": "value"}

	event := BuildCloudEvent(eventType, eventSource, payload)

	assert.Equal(t, "1.0", event.SpecVersion())
	assert.Equal(t, eventSource, event.Source())
	assert.Equal(t, eventType, event.Type())
	assert.WithinDuration(t, time.Now(), event.Time(), time.Second)
	assert.NotEmpty(t, event.ID())
	assert.Equal(t, cloudevents.ApplicationJSON, event.DataContentType())

	var eventData map[string]string
	err := json.Unmarshal(event.Data(), &eventData)
	assert.NoError(t, err)
	assert.Equal(t, payload, eventData)
}

func TestParseCloudEvent(t *testing.T) {
	eventType := "com.example.event"
	eventSource := "/my/source"
	payload := map[string]string{"key": "value"}

	originalEvent := BuildCloudEvent(eventType, eventSource, payload)
	eventBytes, err := json.Marshal(originalEvent)
	assert.NoError(t, err)

	parsedEvent, err := ParseCloudEvent(eventBytes)
	assert.NoError(t, err)
	assert.Equal(t, originalEvent.SpecVersion(), parsedEvent.SpecVersion())
	assert.Equal(t, originalEvent.Type(), parsedEvent.Type())
	assert.Equal(t, originalEvent.Source(), parsedEvent.Source())
	parsedPayload, err := GetEventBody[map[string]string](parsedEvent)
	assert.NoError(t, err)
	assert.Equal(t, payload, *parsedPayload)
}

func TestGetEventBody(t *testing.T) {
	eventType := "com.example.event"
	eventSource := "/my/source"
	payload := map[string]string{"key": "value"}

	event := BuildCloudEvent(eventType, eventSource, payload)

	var eventData map[string]string
	err := json.Unmarshal(event.Data(), &eventData)
	assert.NoError(t, err)
	assert.Equal(t, payload, eventData)

	body, err := GetEventBody[map[string]string](&event)
	assert.NoError(t, err)
	assert.Equal(t, payload, *body)
}

func TestGetEventBodyNullEvent(t *testing.T) {
	_, err := GetEventBody[map[string]string](nil)
	assert.Error(t, err)
	assert.Equal(t, "cloud event is null", err.Error())
}

func TestGetEventBodyNullData(t *testing.T) {
	event := cloudevents.NewEvent()
	_, err := GetEventBody[map[string]string](&event)
	assert.Error(t, err)
	assert.Equal(t, "cloud event data is null", err.Error())
}
