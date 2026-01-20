package eventhandling

import (
	"context"
	"encoding/json"
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
	// Parse event first to extract useful info for logging
	event, err := helpers.ParseCloudEvent(m.Payload)
	if err != nil {
		err = fmt.Errorf("something went wrong while processing cloud event: %s", err)
		h.Logger.Error(err)
		return err
	}

	// Log condensed event info instead of full payload
	h.Logger.Infof("Received event: Type=%s Subject=%s%s", event.Type(), event.Subject(), extractStateTransition(m.Payload))

	handler, ok := h.DispatchMap[event.Type()]
	if !ok {
		h.Logger.Warnf("No handler found for event type: %s", event.Type())

		handler, ok = h.DispatchMap[string(models.EventAnyKey)]
		if !ok {
			h.Logger.Warnf("No default handler found for event type: %s", event.Type())
			return nil
		}
	}

	ctx := getContextFromMessage(m)

	err = handler(ctx, event)

	if err != nil {
		h.Logger.Errorf("Something went wrong while handling event: %s", err)
	}

	return err
}

func getContextFromMessage(m *message.Message) context.Context {
	ctx := context.Background()

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

// extractStateTransition attempts to extract WFX state transition info from the event payload
func extractStateTransition(payload []byte) string {
	var data map[string]interface{}
	if err := json.Unmarshal(payload, &data); err != nil {
		return ""
	}

	// Try to get the "data" field from CloudEvent
	eventData, ok := data["data"].(map[string]interface{})
	if !ok {
		return ""
	}

	// Look for wfx_status which contains state transition info
	wfxStatus, ok := eventData["wfx_status"].(map[string]interface{})
	if !ok {
		return ""
	}

	// Extract current state from workflow definition
	if workflow, ok := wfxStatus["workflow"].(map[string]interface{}); ok {
		if currentState, ok := workflow["state"].(string); ok {
			return fmt.Sprintf(" [WFX State: %s]", currentState)
		}
	}

	return ""
}
