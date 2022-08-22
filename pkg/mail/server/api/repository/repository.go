package repository

import (
	"context"

	"github.com/lamassuiot/lamassuiot/pkg/mail/common/api"
)

type MailConfiguration interface {
	UpdateUserConfiguration(ctx context.Context, userID string, email string, events []string) error
	InsertUserConfiguration(ctx context.Context, userID string, email string, events []string) error
	SelectSubscribersByEventType(ctx context.Context, eventType string) ([]api.UserConfiguration, error)
	SelectUserConfigurationByUserID(ctx context.Context, userID string) (api.UserConfiguration, error)
	SubscribeToEvents(ctx context.Context, userID string, eventType []string) (api.UserConfiguration, error)
	UnSubscribeToEvents(ctx context.Context, userID string, eventType []string) (api.UserConfiguration, error)
}
