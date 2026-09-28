package eventhandling

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"testing"

	"github.com/ThreeDotsLabs/watermill/message"
	"github.com/cloudevents/sdk-go/v2/event"
	"github.com/lamassuiot/lamassuiot/core/v3"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type MockService struct {
	mock.Mock
}

func (s *MockService) Event1(event *event.Event) error {
	args := s.Called(event)
	return args.Error(0)
}

func (s *MockService) Event2(event *event.Event) error {
	args := s.Called(event)
	return args.Error(0)
}

func TestHandleMessage(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)
	entry := logrus.NewEntry(logger)

	svc := MockService{}

	svc.On("Event1", mock.Anything).Return(nil)
	svc.On("Event2", mock.Anything).Return(errors.New("error handling event"))

	dispatchMap := map[string]func(context.Context, *event.Event) error{
		"event_type_1": func(ctx context.Context, event *event.Event) error {
			return svc.Event1(event)
		},
		"event_type_2": func(ctx context.Context, event *event.Event) error {
			return svc.Event2(event)
		},
	}

	handler := CloudEventHandler{
		Logger:      entry,
		DispatchMap: dispatchMap,
	}

	t.Run("ValidEvent", func(t *testing.T) {
		message := &message.Message{
			Payload: []byte(`{"type": "event_type_1", "specversion": "1.0"}`),
		}

		err := handler.HandleMessage(message)
		assert.NoError(t, err)
		svc.AssertCalled(t, "Event1", mock.Anything)
		svc.AssertNotCalled(t, "Event2")
	})

	t.Run("InvalidPayload", func(t *testing.T) {
		message := &message.Message{
			Payload: []byte(`{"type": "event_type_3", "specversion": "1.0"`),
		}

		err := handler.HandleMessage(message)
		assert.Error(t, err)
		svc.AssertNotCalled(t, "Event1")
		svc.AssertNotCalled(t, "Event2")
	})

	t.Run("InvalidEvent", func(t *testing.T) {
		message := &message.Message{
			Payload: []byte(`{"type": "event_type_3", "specversion": "1.0"}`),
		}

		err := handler.HandleMessage(message)
		assert.NoError(t, err)
		svc.AssertNotCalled(t, "Event1")
		svc.AssertNotCalled(t, "Event2")
	})

	t.Run("ErrorHandlingEvent", func(t *testing.T) {
		message := &message.Message{
			Payload: []byte(`{"type": "event_type_2", "specversion": "1.0"}`),
		}

		err := handler.HandleMessage(message)
		assert.Error(t, err)
		svc.AssertNotCalled(t, "Event1")
		svc.AssertCalled(t, "Event2", mock.Anything)
	})
}

func TestHandleAnyEvent(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)
	entry := logrus.NewEntry(logger)

	svc := MockService{}

	svc.On("Event1", mock.Anything).Return(nil)

	dispatchMap := map[string]func(context.Context, *event.Event) error{
		string(models.EventAnyKey): func(ctx context.Context, event *event.Event) error {
			return svc.Event1(event)
		},
	}

	handler := CloudEventHandler{
		Logger:      entry,
		DispatchMap: dispatchMap,
	}

	message := &message.Message{
		Payload: []byte(`{"type": "event_type_1", "specversion": "1.0"}`),
	}

	err := handler.HandleMessage(message)
	assert.NoError(t, err)
	svc.AssertCalled(t, "Event1", mock.Anything)

}

func TestHandleMessagePropagatesConcurrentTenantContexts(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	entry := logrus.NewEntry(logger)
	var mu sync.Mutex
	seen := make(map[string]string)
	handler := CloudEventHandler{
		Logger:                entry,
		RequireTenantEnvelope: true,
		DispatchMap: map[string]func(context.Context, *event.Event) error{
			"tenant.event": func(ctx context.Context, _ *event.Event) error {
				tenantContext, err := core.RequireTenantContext(ctx)
				if err != nil {
					return err
				}
				mu.Lock()
				seen[tenantContext.TenantID] = tenantContext.CorrelationID
				mu.Unlock()
				return nil
			},
		},
	}

	var wait sync.WaitGroup
	for _, item := range []struct{ tenantID, correlationID string }{
		{"tenant-a", "corr-a"},
		{"tenant-b", "corr-b"},
	} {
		wait.Add(1)
		go func(tenantID, correlationID string) {
			defer wait.Done()
			ctx := core.WithTenantContext(context.Background(), core.TenantContext{
				OrganizationID: "org-" + tenantID,
				TenantID:       tenantID,
				ActorID:        "worker",
				ActorType:      "system",
				CorrelationID:  correlationID,
				Source:         "test",
				TenantStatus:   core.TenantActive,
				Validated:      true,
			})
			ctx = context.WithValue(ctx, core.LamassuContextKeyEventType, "tenant.event")
			cloudEvent, err := helpers.BuildTenantCloudEvent(ctx, map[string]string{"value": tenantID})
			if err != nil {
				t.Errorf("could not build tenant event: %s", err)
				return
			}
			payload, err := json.Marshal(cloudEvent)
			if err != nil {
				t.Errorf("could not serialize tenant event: %s", err)
				return
			}
			msg := message.NewMessage(fmt.Sprintf("%s-%s", tenantID, correlationID), payload)
			if err := handler.HandleMessage(msg); err != nil {
				t.Errorf("tenant event was rejected: %s", err)
			}
		}(item.tenantID, item.correlationID)
	}
	wait.Wait()

	assert.Equal(t, map[string]string{"tenant-a": "corr-a", "tenant-b": "corr-b"}, seen)

	legacyEvent := &message.Message{Payload: []byte(`{"type":"tenant.event","specversion":"1.0","id":"legacy","source":"test","time":"2026-09-23T11:00:00Z"}`)}
	assert.ErrorIs(t, handler.HandleMessage(legacyEvent), helpers.ErrInvalidTenantCloudEvent)
}

func TestHandleMessageRejectsInvalidTenantEnvelope(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	handler := CloudEventHandler{
		Logger:                logrus.NewEntry(logger),
		RequireTenantEnvelope: true,
		DispatchMap: map[string]func(context.Context, *event.Event) error{
			"tenant.event": func(context.Context, *event.Event) error { return nil },
		},
	}
	invalidEnvelope := &message.Message{Payload: []byte(`{"specversion":"1.0","id":"event-1","source":"test","type":"tenant.event","time":"2026-09-23T11:00:00Z","tenantid":"tenant-a"}`)}
	assert.ErrorIs(t, handler.HandleMessage(invalidEnvelope), helpers.ErrInvalidTenantCloudEvent)
}
