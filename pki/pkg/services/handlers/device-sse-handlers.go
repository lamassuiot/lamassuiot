package handlers

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/cloudevents/sdk-go/v2/event"
	"github.com/lamassuiot/lamassuiot/pki/v3/pkg/controllers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services/eventhandling"
	"github.com/sirupsen/logrus"
)

func NewDeviceEventSSEHandler(l *logrus.Entry, hub *controllers.DeviceEventSSEHub) *eventhandling.CloudEventHandler {
	genericHandler := func(ctx context.Context, e *event.Event) error {
		return handleAnyDeviceEventForSSE(ctx, e, hub, l)
	}

	return &eventhandling.CloudEventHandler{
		Logger: l,
		DispatchMap: map[string]func(context.Context, *event.Event) error{
			string(models.EventCreateDeviceKey):         genericHandler,
			string(models.EventUpdateDeviceStatusKey):   genericHandler,
			string(models.EventUpdateDeviceIDSlotKey):   genericHandler,
			string(models.EventUpdateDeviceMetadataKey): genericHandler,
			string(models.EventDeleteDeviceKey):         genericHandler,
			string(models.EventCreateDeviceEventKey):    genericHandler,
		},
	}
}

func handleAnyDeviceEventForSSE(ctx context.Context, cloudEvent *event.Event, hub *controllers.DeviceEventSSEHub, l *logrus.Entry) error {
	// Extract device ID from the cloud event subject
	// Subjects: "device/{deviceID}" or "device/{deviceID}/event"
	subject := cloudEvent.Subject()
	deviceID := extractDeviceIDFromSubject(subject)
	if deviceID == "" {
		l.Warnf("could not extract device ID from event subject: %s", subject)
		return nil
	}

	// Forward the raw cloud event data as-is. SSE streaming is a best-effort
	// side channel, so we never NACK the cloud event from this handler — that
	// would have the Watermill router retry and eventually DLQ the message,
	// creating operational noise for what is at most a missed UI tick.
	// Passing json.RawMessage also avoids a decode step that could fail on
	// schema drift.
	l.Debugf("pushing %s event to SSE hub for device %s", cloudEvent.Type(), deviceID)
	hub.Publish(deviceID, cloudEvent.Type(), json.RawMessage(cloudEvent.Data()))
	return nil
}

func extractDeviceIDFromSubject(subject string) string {
	// Subject formats:
	//   "device/{deviceID}"        - for device create, update, delete
	//   "device/{deviceID}/event"  - for device event create
	const prefix = "device/"
	if !strings.HasPrefix(subject, prefix) {
		return ""
	}

	rest := subject[len(prefix):]
	// Strip trailing "/event" if present
	rest = strings.TrimSuffix(rest, "/event")

	if rest == "" {
		return ""
	}
	return rest
}
