package outputchannels

import (
	"context"
	"encoding/json"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	lconfig "github.com/lamassuiot/lamassuiot/backend/v3/pkg/config"
	webhookclient "github.com/lamassuiot/lamassuiot/backend/v3/pkg/helpers/webhook-client"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
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
	msBytes, err := json.Marshal(event)
	if err != nil {
		return err
	}

	if s.config.WebhookURL != "" {

		_, err = webhookclient.InvokeWebhook(ctx, logger, models.WebhookCall{
			Name:   s.name,
			Url:    s.config.WebhookURL,
			Method: s.config.WebhookMethod,
			Config: models.WebhookCallHttpClient{
				ValidateServerCert: false,
				LogLevel:           "INFO",
				AuthMode:           config.NoAuth,
			},
		},
			msBytes)
		if err != nil {
			return err
		}
	}

	return nil
}

func RegisterWebhookOutputServiceBuilder() {
	RegisterOutputServiceBuilder(models.ChannelTypeWebhook, func(c models.Channel, smtpServer lconfig.SMTPServer) (NotificationSenderService, error) {
		chanConfigBytes, err := json.Marshal(c.Config)
		if err != nil {
			return nil, err
		}
		config := models.WebhookChannelConfig{}
		if err := json.Unmarshal(chanConfigBytes, &config); err != nil {
			return nil, err
		}
		return NewWebhookOutputService(c.Name, config), nil
	})
}
