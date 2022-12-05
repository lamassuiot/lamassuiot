package repository

import (
	"context"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/lamassuiot/lamassuiot/pkg/alerts/common/api"
)

type AlertsRepository interface {
	GetUserSubscriptions(ctx context.Context, userID string) (api.UserSubscription, error)
	Subscribe(ctx context.Context, userID string, channel api.Channel, conditions []string, eventType string, conditionType api.ConditionType) error
	Unsubscribe(ctx context.Context, userID string, subscriptionID string) error
	GetSubscriptionsByEventType(ctx context.Context, eventType string) ([]api.Subscription, error)

	CreateChannel(ctx context.Context, id string, channeltype string, name string, config string) error
	DeleteChannel(ctx context.Context, id string) error

	InsertAndUpdateEventLog(ctx context.Context, eventType string, event cloudevents.Event) error
	SelectEventLogs(ctx context.Context) ([]cloudevents.Event, error)
}
