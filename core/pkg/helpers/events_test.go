package helpers

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/lamassuiot/lamassuiot/core/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildCloudEvent(t *testing.T) {
	eventType := "com.example.event"
	eventSource := "my/source"
	payload := map[string]string{"key": "value"}

	ctx := context.Background()
	ctx = context.WithValue(ctx, core.LamassuContextKeyEventType, eventType)
	ctx = context.WithValue(ctx, core.LamassuContextKeySource, eventSource)

	event := BuildCloudEvent(ctx, payload)

	assert.Equal(t, "1.0", event.SpecVersion())
	assert.Equal(t, "source://lamassu.io/ctx/source/my/source", event.Source())
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

	ctx := context.Background()
	ctx = context.WithValue(ctx, core.LamassuContextKeyEventType, eventType)
	ctx = context.WithValue(ctx, core.LamassuContextKeySource, eventSource)

	originalEvent := BuildCloudEvent(ctx, payload)
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

	ctx := context.Background()
	ctx = context.WithValue(ctx, core.LamassuContextKeyEventType, eventType)
	ctx = context.WithValue(ctx, core.LamassuContextKeySource, eventSource)

	event := BuildCloudEvent(ctx, payload)

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

func TestTenantCloudEventRoundTripAndValidation(t *testing.T) {
	ctx := core.WithTenantContext(context.Background(), core.TenantContext{
		OrganizationID: "org-a",
		TenantID:       "tenant-a",
		ActorID:        "actor-a",
		ActorType:      "user",
		CorrelationID:  "corr-a",
		Source:         "http-api",
		TenantStatus:   core.TenantActive,
		Validated:      true,
	})
	ctx = context.WithValue(ctx, core.LamassuContextKeyEventType, "certificate.create")

	cloudEvent, err := BuildTenantCloudEvent(ctx, map[string]string{"id": "cert-a"})
	require.NoError(t, err)
	require.NoError(t, ValidateTenantCloudEvent(&cloudEvent))

	tenantContext, err := TenantContextFromCloudEvent(&cloudEvent)
	require.NoError(t, err)
	assert.Equal(t, "tenant-a", tenantContext.TenantID)
	assert.Equal(t, "org-a", tenantContext.OrganizationID)
	assert.Equal(t, "actor-a", tenantContext.ActorID)
	assert.Equal(t, "corr-a", tenantContext.CorrelationID)

	cloudEvent.SetExtension("eventversion", "2")
	err = ValidateTenantCloudEvent(&cloudEvent)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidTenantCloudEvent))
}

func TestBuildTenantCloudEventRejectsUnvalidatedContext(t *testing.T) {
	ctx := context.WithValue(context.Background(), core.LamassuContextKeyEventType, "certificate.create")
	_, err := BuildTenantCloudEvent(ctx, map[string]string{"id": "cert-a"})
	require.Error(t, err)
	assert.True(t, errors.Is(err, core.ErrTenantContextRequired))
}
