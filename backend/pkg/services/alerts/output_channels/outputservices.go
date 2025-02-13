package outputchannels

import (
	"context"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
)

type NotificationSenderService interface {
	SendNotification(ctx context.Context, event cloudevents.Event) error
}

var outputServicesBuilders = make(map[models.ChannelType]func(c models.Channel, smtpServer config.SMTPServer) (NotificationSenderService, error))

func RegisterOutputServiceBuilder(name models.ChannelType, builder func(c models.Channel, smtpServer config.SMTPServer) (NotificationSenderService, error)) {
	outputServicesBuilders[name] = builder
}

func GetOutputServiceBuilder(name models.ChannelType) func(c models.Channel, smtpServer config.SMTPServer) (NotificationSenderService, error) {
	return outputServicesBuilders[name]
}

func init() {
	RegisterWebhookOutputServiceBuilder()
	RegisterMSTeamsOutputServiceBuilder()
	RegisterSMTPOutputServiceBuilder()
}
