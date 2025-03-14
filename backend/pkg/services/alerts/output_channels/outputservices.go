package outputchannels

import (
	"context"
	"fmt"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/sirupsen/logrus"
)

type NotificationSenderService interface {
	SendNotification(logger *logrus.Entry, ctx context.Context, event cloudevents.Event) error
}

var outputServicesBuilders = make(map[models.ChannelType]func(c models.Channel, smtpServer config.SMTPServer) (NotificationSenderService, error))

func RegisterOutputServiceBuilder(name models.ChannelType, builder func(c models.Channel, smtpServer config.SMTPServer) (NotificationSenderService, error)) {
	outputServicesBuilders[name] = builder
}

func GetOutputServiceBuilder(name models.ChannelType) func(c models.Channel, smtpServer config.SMTPServer) (NotificationSenderService, error) {
	return outputServicesBuilders[name]
}

func GetOutputService(c models.Channel, smtpServer config.SMTPServer) (NotificationSenderService, error) {
	builder := GetOutputServiceBuilder(c.Type)
	if builder == nil {
		return nil, fmt.Errorf("output service %s not found", c.Type)
	}
	return builder(c, smtpServer)
}

func SendNotification(logger *logrus.Entry, ctx context.Context, c models.Channel, smtpServer config.SMTPServer, event cloudevents.Event) error {
	svc, err := GetOutputService(c, smtpServer)
	if err != nil {
		return err
	}
	return svc.SendNotification(logger, ctx, event)
}

func init() {
	RegisterWebhookOutputServiceBuilder()
	RegisterMSTeamsOutputServiceBuilder()
	RegisterSMTPOutputServiceBuilder()
}
