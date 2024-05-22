package handlers

import (
	"fmt"

	"github.com/ThreeDotsLabs/watermill/message"
	"github.com/cloudevents/sdk-go/v2/event"
	"github.com/lamassuiot/lamassuiot/v2/pkg/eventbus"
	"github.com/lamassuiot/lamassuiot/v2/pkg/models"
	"github.com/sirupsen/logrus"
)

type IEventHandler interface {
	HandleEvent(event *message.Message) error
}

type EventHandler[T any] struct {
	lMessaging *logrus.Entry
	svc        T
	dipatchMap map[string]func(*event.Event) error
}

func (h EventHandler[T]) HandleEvent(m *message.Message) error {
	h.lMessaging.Infof("Received event: %s", m.Payload)
	event, err := eventbus.ParseCloudEvent(m.Payload)
	if err != nil {
		err = fmt.Errorf("something went wrong while processing cloud event: %s", err)
		h.lMessaging.Error(err)
		return err
	}

	handler, ok := h.dipatchMap[event.Type()]
	if !ok {
		h.lMessaging.Warnf("No handler found for event type: %s", event.Type())

		handler, ok = h.dipatchMap[string(models.EventAnyKey)]
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
