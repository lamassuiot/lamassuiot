package handlers

import (
	"fmt"

	"github.com/ThreeDotsLabs/watermill/message"
	"github.com/cloudevents/sdk-go/v2/event"
	"github.com/lamassuiot/lamassuiot/v2/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/v2/pkg/models"
	"github.com/sirupsen/logrus"
)

type IEventHandler interface {
	HandleEvent(event *message.Message) error
}

type EventHandler struct {
	lMessaging  *logrus.Entry
	dispatchMap map[string]func(*event.Event) error
}

func (h EventHandler) HandleEvent(m *message.Message) error {
	h.lMessaging.Infof("Received event: %s", m.Payload)
	event, err := helpers.ParseCloudEvent(m.Payload)
	if err != nil {
		err = fmt.Errorf("something went wrong while processing cloud event: %s", err)
		h.lMessaging.Error(err)
		return err
	}

	handler, ok := h.dispatchMap[event.Type()]
	if !ok {
		h.lMessaging.Warnf("No handler found for event type: %s", event.Type())

		handler, ok = h.dispatchMap[string(models.EventAnyKey)]
		if !ok {
			h.lMessaging.Warnf("No default handler found for event type: %s", event.Type())
			return nil
		}
	}

	err = handler(event)

	if err != nil {
		h.lMessaging.Errorf("Something went wrong while handling event: %s", err)
	}

	return err
}
