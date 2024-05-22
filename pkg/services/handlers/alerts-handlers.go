package handlers

import (
	"context"

	"github.com/cloudevents/sdk-go/v2/event"
	"github.com/lamassuiot/lamassuiot/v2/pkg/models"
	"github.com/lamassuiot/lamassuiot/v2/pkg/services"
	"github.com/sirupsen/logrus"
)

func NewAlertsEventHandler(l *logrus.Entry, svc services.AlertsService) *EventHandler {
	return &EventHandler{
		lMessaging: l,
		dipatchMap: map[string]func(*event.Event) error{
			string(models.EventAnyKey): func(e *event.Event) error {
				return svc.HandleEvent(context.Background(), &services.HandleEventInput{
					Event: *e,
				})
			},
		},
	}
}
