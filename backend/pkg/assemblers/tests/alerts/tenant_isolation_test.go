package alerts

import (
	"context"
	"errors"
	"fmt"
	"testing"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/assemblers/tests"
	core "github.com/lamassuiot/lamassuiot/core/v3"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
)

func TestAlertsTenantIsolation(t *testing.T) {
	serverTest, err := tests.TestServiceBuilder{}.WithDatabase("ca", "alerts", "kms").WithService(tests.ALERTS).Build(t)
	if err != nil {
		t.Fatalf("could not create Alerts test server: %s", err)
	}

	tenantA := alertsTenantContext("00000000-0000-0000-0000-00000000000a")
	tenantB := alertsTenantContext("00000000-0000-0000-0000-00000000000b")
	if _, err := serverTest.Alerts.Service.GetLatestEventsPerEventType(context.Background(), &services.GetLatestEventsPerEventTypeInput{}); !errors.Is(err, core.ErrTenantContextRequired) {
		t.Fatalf("expected missing tenant context to be rejected, got %v", err)
	}
	suspendedTenant := core.WithTenantContext(context.Background(), core.TenantContext{
		OrganizationID: "org-alerts-isolation",
		TenantID:       "00000000-0000-0000-0000-00000000000a",
		ActorID:        "actor-alerts-isolation",
		ActorType:      "test",
		CorrelationID:  "correlation-suspended",
		Source:         "test",
		TenantStatus:   core.TenantSuspended,
		Validated:      true,
	})
	if _, err := serverTest.Alerts.Service.GetLatestEventsPerEventType(suspendedTenant, &services.GetLatestEventsPerEventTypeInput{}); !errors.Is(err, core.ErrTenantContextInvalid) {
		t.Fatalf("expected suspended tenant context to be rejected, got %v", err)
	}
	subscriptions, err := serverTest.Alerts.Service.Subscribe(tenantA, &services.SubscribeInput{
		UserID:    "tenant-a-user",
		EventType: models.EventCreateCAKey,
		Channel: models.Channel{
			Type: models.ChannelTypeWebhook,
			Name: "tenant-a-webhook",
			Config: models.WebhookChannelConfig{
				WebhookURL: "http://localhost:8080",
			},
		},
	})
	if err != nil {
		t.Fatalf("could not create tenant A subscription: %s", err)
	}
	if len(subscriptions) == 0 {
		t.Fatal("expected tenant A subscription")
	}

	foreignSubscriptions, err := serverTest.Alerts.Service.GetUserSubscriptions(tenantB, &services.GetUserSubscriptionsInput{UserID: "tenant-a-user"})
	if err != nil {
		t.Fatalf("could not query tenant B subscriptions: %s", err)
	}
	if len(foreignSubscriptions) != 0 {
		t.Fatalf("expected tenant B to see no tenant A subscriptions, got %d", len(foreignSubscriptions))
	}

	event := cloudevents.NewEvent()
	event.SetID("tenant-a-event")
	event.SetSource("tenant-isolation-test")
	event.SetType(string(models.EventCreateDeviceKey))
	if err := event.SetData(cloudevents.ApplicationJSON, map[string]string{"tenant": "a"}); err != nil {
		t.Fatalf("could not create test event: %s", err)
	}
	if err := serverTest.Alerts.Service.HandleEvent(tenantA, &services.HandleEventInput{Event: event}); err != nil {
		t.Fatalf("could not store tenant A event: %s", err)
	}

	tenantAEvents, err := serverTest.Alerts.Service.GetLatestEventsPerEventType(tenantA, &services.GetLatestEventsPerEventTypeInput{})
	if err != nil {
		t.Fatalf("could not query tenant A events: %s", err)
	}
	if len(tenantAEvents) != 1 {
		t.Fatalf("expected tenant A to see one event, got %d", len(tenantAEvents))
	}

	tenantBEvents, err := serverTest.Alerts.Service.GetLatestEventsPerEventType(tenantB, &services.GetLatestEventsPerEventTypeInput{})
	if err != nil {
		t.Fatalf("could not query tenant B events: %s", err)
	}
	if len(tenantBEvents) != 0 {
		t.Fatalf("expected tenant B to see no tenant A events, got %d", len(tenantBEvents))
	}
}

func alertsTenantContext(tenantID string) context.Context {
	return core.WithTenantContext(context.Background(), core.TenantContext{
		OrganizationID: "org-alerts-isolation",
		TenantID:       tenantID,
		ActorID:        "actor-alerts-isolation",
		ActorType:      "test",
		CorrelationID:  "correlation-" + tenantID,
		Source:         "test",
		TenantStatus:   core.TenantActive,
		Validated:      true,
	})
}

// Regresión de GET /events/latest con 15 o más tipos de evento por tenant: la lectura
// exhaustiva fallaba con «primary key required» porque events tiene PK compuesta.
func TestAlertsLatestEventsWithManyEventTypes(t *testing.T) {
	serverTest, err := tests.TestServiceBuilder{}.WithDatabase("ca", "alerts", "kms").WithService(tests.ALERTS).Build(t)
	if err != nil {
		t.Fatalf("could not create Alerts test server: %s", err)
	}

	tenantA := alertsTenantContext("00000000-0000-0000-0000-00000000000a")
	tenantB := alertsTenantContext("00000000-0000-0000-0000-00000000000b")

	handle := func(ctx context.Context, eventType string) {
		event := cloudevents.NewEvent()
		event.SetID(eventType)
		event.SetSource("many-event-types-test")
		event.SetType(eventType)
		if err := event.SetData(cloudevents.ApplicationJSON, map[string]string{"type": eventType}); err != nil {
			t.Fatalf("could not create test event: %s", err)
		}
		if err := serverTest.Alerts.Service.HandleEvent(ctx, &services.HandleEventInput{Event: event}); err != nil {
			t.Fatalf("could not store event %s: %s", eventType, err)
		}
	}

	const eventTypes = 40
	for i := 0; i < eventTypes; i++ {
		handle(tenantA, fmt.Sprintf("test.many.types.%02d", i))
	}
	handle(tenantB, "test.many.types.00")

	tenantAEvents, err := serverTest.Alerts.Service.GetLatestEventsPerEventType(tenantA, &services.GetLatestEventsPerEventTypeInput{})
	if err != nil {
		t.Fatalf("could not query tenant A events: %s", err)
	}
	if len(tenantAEvents) != eventTypes {
		t.Fatalf("expected tenant A to see %d event types, got %d", eventTypes, len(tenantAEvents))
	}
	for _, ev := range tenantAEvents {
		if ev.TenantID != "00000000-0000-0000-0000-00000000000a" {
			t.Fatalf("tenant A read a row of tenant %s", ev.TenantID)
		}
	}

	tenantBEvents, err := serverTest.Alerts.Service.GetLatestEventsPerEventType(tenantB, &services.GetLatestEventsPerEventTypeInput{})
	if err != nil {
		t.Fatalf("could not query tenant B events: %s", err)
	}
	if len(tenantBEvents) != 1 {
		t.Fatalf("expected tenant B to see one event type, got %d", len(tenantBEvents))
	}
}
