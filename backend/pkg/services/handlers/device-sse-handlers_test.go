package handlers

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/cloudevents/sdk-go/v2/event"
	"github.com/lamassuiot/lamassuiot/v4/backend/pkg/controllers"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

func TestExtractDeviceIDFromSubject(t *testing.T) {
	tests := []struct {
		name      string
		eventType models.EventType
		subject   string
		want      string
	}{
		{"device subject", models.EventUpdateDeviceStatusKey, "device/abc", "abc"},
		{"device event subject", models.EventCreateDeviceEventKey, "device/abc/event", "abc"},
		{"device id ending in /event on a non-event type", models.EventUpdateDeviceStatusKey, "device/x/event", "x/event"},
		{"device id ending in /event on a device event", models.EventCreateDeviceEventKey, "device/x/event/event", "x/event"},
		{"foreign prefix", models.EventCreateDeviceKey, "other/abc", ""},
		{"empty id", models.EventCreateDeviceKey, "device/", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, extractDeviceIDFromSubject(string(tt.eventType), tt.subject))
		})
	}
}

// A device whose ID ends in "/event" must not have its status events delivered to the stream of the device without
// that suffix: only device-event-create subjects carry the "/event" marker.
func TestSSEHandlerKeepsDeviceSlashEventSeparate(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	l := logrus.NewEntry(logger)

	hub := controllers.NewDeviceEventSSEHub(l, controllers.DeviceEventSSEHubOptions{})
	plain, err := hub.Subscribe("x")
	require.NoError(t, err)
	suffixed, err := hub.Subscribe("x/event")
	require.NoError(t, err)

	e := event.New()
	e.SetType(string(models.EventUpdateDeviceStatusKey))
	e.SetSource("service/devmanager")
	e.SetSubject("device/x/event")
	require.NoError(t, e.SetData(event.ApplicationJSON, map[string]string{"id": "x/event"}))

	handler := NewDeviceEventSSEHandler(l, hub)
	require.NoError(t, handler.DispatchMap[string(models.EventUpdateDeviceStatusKey)](context.Background(), &e))

	select {
	case <-suffixed:
	case <-time.After(time.Second):
		t.Fatal("the x/event stream did not receive the event")
	}
	select {
	case msg := <-plain:
		t.Fatalf("the x stream must not receive the event, got %q", msg)
	default:
	}
}
