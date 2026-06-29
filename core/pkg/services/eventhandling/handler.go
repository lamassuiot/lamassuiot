package eventhandling

import (
	"context"
	"fmt"

	"github.com/ThreeDotsLabs/watermill/message"
	"github.com/cloudevents/sdk-go/v2/event"
	"github.com/lamassuiot/lamassuiot/core/v3"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/sirupsen/logrus"
)

type EventHandler interface {
	HandleMessage(*message.Message) error
}

type CloudEventHandler struct {
	Logger      *logrus.Entry
	DispatchMap map[string]func(context.Context, *event.Event) error
}

func (h CloudEventHandler) HandleMessage(m *message.Message) error {
	ctx := getContextFromMessage(m)
	lFunc := helpers.ConfigureLogger(ctx, h.Logger)

	lFunc.Infof("Received event: %s", m.Payload)
	event, err := helpers.ParseCloudEvent(m.Payload)
	if err != nil {
		err = fmt.Errorf("something went wrong while processing cloud event: %s", err)
		lFunc.Error(err)
		return err
	}

	handler, ok := h.DispatchMap[event.Type()]
	if !ok {
		lFunc.Warnf("No handler found for event type: %s", event.Type())

		handler, ok = h.DispatchMap[string(models.EventAnyKey)]
		if !ok {
			lFunc.Warnf("No default handler found for event type: %s", event.Type())
			return nil
		}
	}

	err = handler(ctx, event)

	if err != nil {
		lFunc.Errorf("Something went wrong while handling event: %s", err)
	}

	return err
}

func getContextFromMessage(m *message.Message) context.Context {
	ctx := m.Context()

	//Set source in context from metadata
	ebSource := m.Metadata.Get(core.LamassuContextKeySource)
	if ebSource == "" {
		ebSource = "unknown"
	}
	ctx = context.WithValue(ctx, core.LamassuContextKeySource, fmt.Sprintf("eventbus-%s", ebSource))

	//Set request ID in context from metadata
	//TODO: we will need to change this to use the request ID once OTEL tracing is implemented
	ebRequestID := m.Metadata.Get(core.LamassuContextKeyRequestID)
	if ebRequestID == "" {
		ebRequestID = "unknown"
	}
	ctx = context.WithValue(ctx, core.LamassuContextKeyRequestID, ebRequestID)

	//TODO decide how to handle rest of context values
	ctx = context.WithValue(ctx, core.LamassuContextKeyAuthType, "system")

	return ctx
}
