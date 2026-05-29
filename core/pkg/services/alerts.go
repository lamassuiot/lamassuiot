package services

import (
	"context"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"
)

type AlertsService interface {
	HandleEvent(ctx context.Context, input *HandleEventInput) error
	GetUserSubscriptions(ctx context.Context, input *GetUserSubscriptionsInput) ([]*models.Subscription, error)
	Subscribe(ctx context.Context, input *SubscribeInput) ([]*models.Subscription, error)
	Unsubscribe(ctx context.Context, input *UnsubscribeInput) ([]*models.Subscription, error)

	GetLatestEventsPerEventType(ctx context.Context, input *GetLatestEventsPerEventTypeInput) ([]*models.AlertLatestEvent, error)

	GetEvents(ctx context.Context, input *GetEventsInput) (string, error)
	GetEventByID(ctx context.Context, input *GetEventByIDInput) (*models.StoredEvent, error)

	GetEventRetentionSettings(ctx context.Context) (*models.EventRetentionSettings, error)
	UpdateEventRetentionSettings(ctx context.Context, input *UpdateEventRetentionSettingsInput) (*models.EventRetentionSettings, error)
}

type HandleEventInput struct {
	Event cloudevents.Event
}

type GetLatestEventsPerEventTypeInput struct{}

type GetUserSubscriptionsInput struct {
	UserID string
}

type SubscribeInput struct {
	UserID     string
	EventType  models.EventType
	Conditions []models.SubscriptionCondition
	Channel    models.Channel
}

type UnsubscribeInput struct {
	UserID         string
	SubscriptionID string
}

type GetEventsInput struct {
	QueryParameters *resources.QueryParameters
	ExhaustiveRun   bool
	ApplyFunc       func(models.StoredEvent)
}

type GetEventByIDInput struct {
	ID string `validate:"required"`
}

type UpdateEventRetentionSettingsInput struct {
	AuditEventTTL models.TimeDuration `validate:"required"`
}
