package repository

import (
	"context"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/lamassuiot/lamassuiot/pkg/mail/common/api"
)

type MailConfiguration interface {
	AddSubscription(ctx context.Context, email string, events []string) error
	SelectSubscribersByEventType(ctx context.Context, eventType string) ([]api.Subscription, error)
	//SelectUserConfigurationByUserID(ctx context.Context, userID string) (api.UserConfiguration, error)
	SubscribeToEvents(ctx context.Context, email string, eventType string) (api.Subscription, error)
	UnSubscribeToEvents(ctx context.Context, email string, eventType string) (api.Subscription, error)

	InsertAndUpdateEventLog(ctx context.Context, eventType string, event cloudevents.Event) error
	SelectEventLogs(ctx context.Context) ([]cloudevents.Event, error)
}
