package storage

import (
	"context"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"
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

type StoredEventsRepository interface {
	Insert(ctx context.Context, ev *models.StoredEvent) (*models.StoredEvent, error)
	GetByID(ctx context.Context, id string) (bool, *models.StoredEvent, error)
	GetAll(ctx context.Context, exhaustiveRun bool, applyFunc func(models.StoredEvent), queryParams *resources.QueryParameters, extraOpts map[string]interface{}) (string, error)
	DeleteExpired(ctx context.Context) (int64, error)
}

type EventRetentionSettingsRepository interface {
	Get(ctx context.Context) (*models.EventRetentionSettings, error)
	Update(ctx context.Context, settings *models.EventRetentionSettings) (*models.EventRetentionSettings, error)
}
