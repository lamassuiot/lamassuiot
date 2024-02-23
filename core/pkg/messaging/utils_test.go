package messaging

import (
	"testing"

	"encoding/json"

	"github.com/stretchr/testify/assert"
)

func TestBuildCloudEvent(t *testing.T) {
	eventType := "testEventType"
	eventSource := "testEventSource"
	payload := struct {
		Message string `json:"message"`
	}{
		Message: "test message",
	}

	event := BuildCloudEvent(eventType, eventSource, payload)

	assert.Equal(t, "1.0", event.SpecVersion())
	assert.Equal(t, eventSource, event.Source())
	assert.Equal(t, eventType, event.Type())
	assert.NotNil(t, event.Time())
	assert.NotNil(t, event.ID())

	var elem *struct {
		Message string `json:"message"`
	}
	eventDataBytes := event.Data()
	json.Unmarshal(eventDataBytes, &elem)

	assert.Equal(t, payload.Message, elem.Message)
}
