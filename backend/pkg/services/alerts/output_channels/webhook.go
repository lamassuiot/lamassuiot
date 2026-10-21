package outputchannels

import (
	"context"
	"encoding/json"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	lconfig "github.com/lamassuiot/lamassuiot/v4/backend/pkg/config"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/sirupsen/logrus"
)

type WebhookOutputService struct {
	name   string
	config models.WebhookChannelConfig
}

func NewWebhookOutputService(name string, config models.WebhookChannelConfig) NotificationSenderService {
	return &WebhookOutputService{
		name:   name,
		config: config,
	}
}

func (s *WebhookOutputService) SendNotification(logger *logrus.Entry, ctx context.Context, event cloudevents.Event) error {
	if s.config.WebhookURL == "" {
		return nil
	}

	msBytes, err := json.Marshal(event)
	if err != nil {
		return err
	}

	return sendHTTPNotification(ctx, logger, s.name, s.config.WebhookURL, s.config.WebhookMethod, s.config.HTTPClient, msBytes)
}

func RegisterWebhookOutputServiceBuilder() {
	RegisterOutputServiceBuilder(models.ChannelTypeWebhook, func(c models.Channel, smtpServer lconfig.SMTPServer) (NotificationSenderService, error) {
		config, err := decodeChannelConfig[models.WebhookChannelConfig](c)
		if err != nil {
			return nil, err
		}
		return NewWebhookOutputService(c.Name, config), nil
	})
}
