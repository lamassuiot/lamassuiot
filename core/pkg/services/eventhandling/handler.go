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
	Logger                *logrus.Entry
	DispatchMap           map[string]func(context.Context, *event.Event) error
	RequireTenantEnvelope bool
}

func (h CloudEventHandler) HandleMessage(m *message.Message) error {
	if m == nil {
		return fmt.Errorf("cloud event message is required")
	}
	event, err := helpers.ParseCloudEvent(m.Payload)
	if err != nil {
		err = fmt.Errorf("something went wrong while processing cloud event: %s", err)
		if h.Logger != nil {
			h.Logger.Error(err)
		}
		return err
	}

	_, extensionErr := event.Context.GetExtension("tenantid")
	hasTenantEnvelope := extensionErr == nil
	if hasTenantEnvelope {
		tenantContext, err := helpers.TenantContextFromCloudEvent(event)
		if err != nil {
			if h.Logger != nil {
				correlationID, _ := event.Context.GetExtension("correlationid")
				h.Logger.Errorf("rejecting invalid tenant event id=%s type=%s correlation_id=%v: %s", event.ID(), event.Type(), correlationID, err)
			}
			return err
		}
		ctx := getContextFromMessage(m)
		if existingContext, contextErr := core.TenantContextFromContext(ctx); contextErr == nil {
			if err := existingContext.Validate(); err != nil {
				return fmt.Errorf("%w: message tenant context is invalid", helpers.ErrInvalidTenantCloudEvent)
			}
			if existingContext.TenantID != tenantContext.TenantID ||
				existingContext.OrganizationID != tenantContext.OrganizationID ||
				existingContext.ActorID != tenantContext.ActorID ||
				existingContext.CorrelationID != tenantContext.CorrelationID {
				err := fmt.Errorf("%w: message and event tenant contexts disagree", helpers.ErrInvalidTenantCloudEvent)
				if h.Logger != nil {
					h.Logger.Errorf("rejecting conflicting tenant event id=%s type=%s correlation_id=%s", event.ID(), event.Type(), tenantContext.CorrelationID)
				}
				return err
			}
		}
		ctx = core.WithTenantContext(ctx, tenantContext)
		if h.Logger != nil {
			h.Logger.Infof("received tenant event id=%s type=%s tenant_id=%s correlation_id=%s", event.ID(), event.Type(), tenantContext.TenantID, tenantContext.CorrelationID)
		}
		return h.dispatch(ctx, event)
	}
	if h.RequireTenantEnvelope {
		err := fmt.Errorf("%w: tenant envelope is required", helpers.ErrInvalidTenantCloudEvent)
		if h.Logger != nil {
			h.Logger.Errorf("rejecting event without tenant envelope id=%s type=%s", event.ID(), event.Type())
		}
		return err
	}

	if h.Logger != nil {
		h.Logger.Infof("received event id=%s type=%s", event.ID(), event.Type())
	}
	return h.dispatch(getContextFromMessage(m), event)
}

func (h CloudEventHandler) dispatch(ctx context.Context, event *event.Event) error {
	handler, ok := h.DispatchMap[event.Type()]
	if !ok {
		if h.Logger != nil {
			h.Logger.Warnf("No handler found for event type: %s", event.Type())
		}

		handler, ok = h.DispatchMap[string(models.EventAnyKey)]
		if !ok {
			if h.Logger != nil {
				h.Logger.Warnf("No default handler found for event type: %s", event.Type())
			}
			return nil
		}
	}

	err := handler(ctx, event)

	if err != nil && h.Logger != nil {
		h.Logger.Errorf("Something went wrong while handling event: %s", err)
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
