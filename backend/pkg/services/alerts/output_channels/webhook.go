package outputchannels

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/config"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
)

type WebhookOutputService struct {
	config models.WebhookChannelConfig
}

func NewWebhookOutputService(config models.WebhookChannelConfig) NotificationSenderService {
	return &WebhookOutputService{
		config: config,
	}
}

func (s *WebhookOutputService) SendNotification(ctx context.Context, event cloudevents.Event) error {
	msBytes, err := json.Marshal(event)
	if err != nil {
		return err
	}

	if s.config.WebhookURL != "" {
		req, err := http.NewRequest(s.config.WebhookMethod, s.config.WebhookURL, bytes.NewBuffer(msBytes))
		if err != nil {
			return err
		}

		_, err = http.DefaultClient.Do(req)
		if err != nil {
			return err
		}

	}

	return nil
}

func RegisterWebhookOutputServiceBuilder() {
	RegisterOutputServiceBuilder(models.ChannelTypeWebhook, func(c models.Channel, smtpServer config.SMTPServer) (NotificationSenderService, error) {
		chanConfigBytes, err := json.Marshal(c.Config)
		if err != nil {
			return nil, err
		}
		config := models.WebhookChannelConfig{}
		if err := json.Unmarshal(chanConfigBytes, &config); err != nil {
			return nil, err
		}
		return NewWebhookOutputService(config), nil
	})
}
