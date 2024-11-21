package eventhandling

import (
	"fmt"

	"github.com/ThreeDotsLabs/watermill/message"
	"github.com/cloudevents/sdk-go/v2/event"
	"github.com/lamassuiot/lamassuiot/v3/core/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v3/core/pkg/models"
	"github.com/sirupsen/logrus"
)

type EventHandler interface {
	HandleMessage(*message.Message) error
}

type CloudEventHandler struct {
	Logger      *logrus.Entry
	DispatchMap map[string]func(*event.Event) error
}

func (h CloudEventHandler) HandleMessage(m *message.Message) error {
	h.Logger.Infof("Received event: %s", m.Payload)
	event, err := helpers.ParseCloudEvent(m.Payload)
	if err != nil {
		err = fmt.Errorf("something went wrong while processing cloud event: %s", err)
		h.Logger.Error(err)
		return err
	}

	handler, ok := h.DispatchMap[event.Type()]
	if !ok {
		h.Logger.Warnf("No handler found for event type: %s", event.Type())

		handler, ok = h.DispatchMap[string(models.EventAnyKey)]
		if !ok {
			h.Logger.Warnf("No default handler found for event type: %s", event.Type())
			return nil
		}
	}

	err = handler(event)

	if err != nil {
		h.Logger.Errorf("Something went wrong while handling event: %s", err)
	}

	return err
}
