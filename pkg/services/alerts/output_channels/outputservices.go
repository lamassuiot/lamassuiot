package outputchannels

import (
	"context"

	cloudevents "github.com/cloudevents/sdk-go/v2"
)

type NotificationSenderService interface {
	SendNotification(ctx context.Context, event cloudevents.Event) error
}
