package handlers

import (
	"errors"
	"testing"

	"github.com/ThreeDotsLabs/watermill/message"
	"github.com/cloudevents/sdk-go/v2/event"
	"github.com/lamassuiot/lamassuiot/v2/pkg/models"
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

func TestHandleEvent(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)
	entry := logrus.NewEntry(logger)

	svc := MockService{}

	svc.On("Event1", mock.Anything).Return(nil)
	svc.On("Event2", mock.Anything).Return(errors.New("error handling event"))

	dispatchMap := map[string]func(*event.Event) error{
		"event_type_1": func(event *event.Event) error {
			return svc.Event1(event)
		},
		"event_type_2": func(event *event.Event) error {
			return svc.Event2(event)
		},
	}

	handler := EventHandler{
		lMessaging: entry,
		dipatchMap: dispatchMap,
	}

	t.Run("ValidEvent", func(t *testing.T) {
		message := &message.Message{
			Payload: []byte(`{"type": "event_type_1", "specversion": "1.0"}`),
		}

		err := handler.HandleEvent(message)
		assert.NoError(t, err)
		svc.AssertCalled(t, "Event1", mock.Anything)
		svc.AssertNotCalled(t, "Event2")
	})

	t.Run("InvalidPayload", func(t *testing.T) {
		message := &message.Message{
			Payload: []byte(`{"type": "event_type_3", "specversion": "1.0"`),
		}

		err := handler.HandleEvent(message)
		assert.Error(t, err)
		svc.AssertNotCalled(t, "Event1")
		svc.AssertNotCalled(t, "Event2")
	})

	t.Run("InvalidEvent", func(t *testing.T) {
		message := &message.Message{
			Payload: []byte(`{"type": "event_type_3", "specversion": "1.0"}`),
		}

		err := handler.HandleEvent(message)
		assert.NoError(t, err)
		svc.AssertNotCalled(t, "Event1")
		svc.AssertNotCalled(t, "Event2")
	})

	t.Run("ErrorHandlingEvent", func(t *testing.T) {
		message := &message.Message{
			Payload: []byte(`{"type": "event_type_2", "specversion": "1.0"}`),
		}

		err := handler.HandleEvent(message)
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

	dispatchMap := map[string]func(*event.Event) error{
		string(models.EventAnyKey): func(event *event.Event) error {
			return svc.Event1(event)
		},
	}

	handler := EventHandler{
		lMessaging: entry,
		dipatchMap: dispatchMap,
	}

	message := &message.Message{
		Payload: []byte(`{"type": "event_type_1", "specversion": "1.0"}`),
	}

	err := handler.HandleEvent(message)
	assert.NoError(t, err)
	svc.AssertCalled(t, "Event1", mock.Anything)

}
