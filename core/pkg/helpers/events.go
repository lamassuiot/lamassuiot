package helpers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/cloudevents/sdk-go/v2/event"
	"github.com/google/uuid"
	"github.com/lamassuiot/lamassuiot/core/v3"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"go.opentelemetry.io/otel/trace"
)

const tenantEventVersion = "1"

var ErrInvalidTenantCloudEvent = errors.New("invalid tenant cloud event")

func BuildCloudEvent(ctx context.Context, payload interface{}) event.Event {
	event := cloudevents.NewEvent()

	event.SetSpecVersion("1.0")
	event.SetTime(time.Now())

	// Use OTEL trace ID as event ID
	spanCtx := trace.SpanFromContext(ctx).SpanContext()
	if spanCtx.HasTraceID() {
		event.SetID(fmt.Sprintf("%s-%s", spanCtx.TraceID().String(), spanCtx.SpanID().String()))
		event.SetExtension("traceid", spanCtx.TraceID().String())
		event.SetExtension("spanid", spanCtx.SpanID().String())
	} else {
		event.SetID("unknown")
	}

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
		event.SetExtension("authid", eventAuthID)
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

func BuildTenantCloudEvent(ctx context.Context, payload interface{}) (event.Event, error) {
	tenantContext, err := core.RequireTenantContext(ctx)
	if err != nil {
		return event.Event{}, fmt.Errorf("build tenant cloud event: %w", err)
	}

	eventType := eventContextString(ctx, core.LamassuContextKeyEventType)
	if eventType == "" {
		return event.Event{}, fmt.Errorf("build tenant cloud event: event type is required")
	}
	source := eventContextString(ctx, core.LamassuContextKeySource)
	if source == "" {
		source = tenantContext.Source
	}
	if source == "" {
		return event.Event{}, fmt.Errorf("build tenant cloud event: event source is required")
	}

	cloudEvent := BuildCloudEvent(ctx, payload)
	if cloudEvent.ID() == "" || cloudEvent.ID() == "unknown" {
		cloudEvent.SetID(uuid.NewString())
	}
	cloudEvent.SetType(eventType)
	cloudEvent.SetSource(fmt.Sprintf("source://%s/%s", core.LamassuContextKeySource, source))
	cloudEvent.SetExtension("tenantid", tenantContext.TenantID)
	cloudEvent.SetExtension("organizationid", tenantContext.OrganizationID)
	cloudEvent.SetExtension("actorid", tenantContext.ActorID)
	cloudEvent.SetExtension("actortype", tenantContext.ActorType)
	cloudEvent.SetExtension("correlationid", tenantContext.CorrelationID)
	cloudEvent.SetExtension("eventversion", tenantEventVersion)

	if err := ValidateTenantCloudEvent(&cloudEvent); err != nil {
		return event.Event{}, fmt.Errorf("build tenant cloud event: %w", err)
	}
	return cloudEvent, nil
}

func TenantContextFromCloudEvent(cloudEvent *event.Event) (core.TenantContext, error) {
	if err := ValidateTenantCloudEvent(cloudEvent); err != nil {
		return core.TenantContext{}, err
	}

	tenantContext := core.TenantContext{
		OrganizationID: cloudEventExtension(cloudEvent, "organizationid"),
		TenantID:       cloudEventExtension(cloudEvent, "tenantid"),
		ActorID:        cloudEventExtension(cloudEvent, "actorid"),
		ActorType:      cloudEventExtension(cloudEvent, "actortype"),
		CorrelationID:  cloudEventExtension(cloudEvent, "correlationid"),
		Source:         cloudEvent.Source(),
		TenantStatus:   core.TenantActive,
		Validated:      true,
	}
	if err := tenantContext.Validate(); err != nil {
		return core.TenantContext{}, fmt.Errorf("%w: %v", ErrInvalidTenantCloudEvent, err)
	}
	return tenantContext, nil
}

func ValidateTenantCloudEvent(cloudEvent *event.Event) error {
	if cloudEvent == nil {
		return fmt.Errorf("%w: event is required", ErrInvalidTenantCloudEvent)
	}
	if err := cloudEvent.Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidTenantCloudEvent, err)
	}
	if cloudEvent.SpecVersion() != "1.0" || cloudEvent.ID() == "" || cloudEvent.ID() == "unknown" ||
		cloudEvent.Type() == "" || cloudEvent.Source() == "" || cloudEvent.Time().IsZero() {
		return fmt.Errorf("%w: CloudEvent identity, type, source, time and 1.0 spec version are required", ErrInvalidTenantCloudEvent)
	}
	for _, extension := range []string{
		"tenantid",
		"organizationid",
		"actorid",
		"actortype",
		"correlationid",
		"eventversion",
	} {
		if cloudEventExtension(cloudEvent, extension) == "" {
			return fmt.Errorf("%w: extension %s is required", ErrInvalidTenantCloudEvent, extension)
		}
	}
	if cloudEventExtension(cloudEvent, "eventversion") != tenantEventVersion {
		return fmt.Errorf("%w: unsupported event version %q", ErrInvalidTenantCloudEvent, cloudEventExtension(cloudEvent, "eventversion"))
	}
	return nil
}

func eventContextString(ctx context.Context, key string) string {
	switch value := ctx.Value(key).(type) {
	case string:
		return value
	case models.EventType:
		return string(value)
	default:
		return ""
	}
}

func cloudEventExtension(cloudEvent *event.Event, key string) string {
	rawValue, err := cloudEvent.Context.GetExtension(key)
	if err != nil {
		return ""
	}
	value, ok := rawValue.(string)
	if !ok {
		return ""
	}
	return value
}

func ParseCloudEvent(msg []byte) (*event.Event, error) {
	var event cloudevents.Event
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
