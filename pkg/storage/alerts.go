package storage

import (
	"context"

	"github.com/lamassuiot/lamassuiot/v2/pkg/models"
	"github.com/lamassuiot/lamassuiot/v2/pkg/resources"
)

type SubscriptionsRepository interface {
	GetSubscriptions(ctx context.Context, userID string, exhaustiveRun bool, applyFunc func(models.Subscription), queryParams *resources.QueryParameters, extraOpts map[string]interface{}) (string, error)
	Subscribe(ctx context.Context, sub *models.Subscription) (*models.Subscription, error)
	Unsubscribe(ctx context.Context, subscriptionID string) error
	GetSubscriptionsByEventType(ctx context.Context, eventType string, exhaustiveRun bool, applyFunc func(models.Subscription), queryParams *resources.QueryParameters, extraOpts map[string]interface{}) (string, error)
}

type EventRepository interface {
	GetLatestEventByEventType(ctx context.Context, eventType models.EventType) (bool, *models.AlertLatestEvent, error)
	InsertUpdateEvent(ctx context.Context, ev *models.AlertLatestEvent) (*models.AlertLatestEvent, error)
	GetLatestEvents(ctx context.Context) ([]*models.AlertLatestEvent, error)
}
