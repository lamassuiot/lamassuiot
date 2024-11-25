package handlers

import (
	"context"

	"github.com/cloudevents/sdk-go/v2/event"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/services"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services/eventhandling"
	"github.com/sirupsen/logrus"
)

func NewAlertsEventHandler(l *logrus.Entry, svc services.AlertsService) *eventhandling.CloudEventHandler {
	return &eventhandling.CloudEventHandler{
		Logger: l,
		DispatchMap: map[string]func(*event.Event) error{
			string(models.EventAnyKey): func(e *event.Event) error {
				return svc.HandleEvent(context.Background(), &services.HandleEventInput{
					Event: *e,
				})
			},
		},
	}
}
