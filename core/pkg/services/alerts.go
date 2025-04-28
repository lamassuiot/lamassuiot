package services

import (
	"context"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
)

type AlertsService interface {
	HandleEvent(ctx context.Context, input *HandleEventInput) error
	GetUserSubscriptions(ctx context.Context, input *GetUserSubscriptionsInput) ([]*models.Subscription, error)
	Subscribe(ctx context.Context, input *SubscribeInput) ([]*models.Subscription, error)
	Unsubscribe(ctx context.Context, input *UnsubscribeInput) ([]*models.Subscription, error)

	GetLatestEventsPerEventType(ctx context.Context, input *GetLatestEventsPerEventTypeInput) ([]*models.AlertLatestEvent, error)
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
