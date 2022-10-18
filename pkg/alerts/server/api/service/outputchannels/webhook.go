package outputchannels

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"

	"github.com/lamassuiot/lamassuiot/pkg/alerts/common/api"
)

type WebhookOutputService struct {
}

type WebhookChannelConfig struct {
	WebhookURL string `json:"webhook_url"`
	Method     string `json:"method"`
}

func (s *WebhookOutputService) ParseEventAndSend(ctx context.Context, eventType string, eventDescription string, eventData map[string]string, channels []api.Channel) error {

	var webhooks = make(map[string]string)
	for _, channel := range channels {
		if channel.Type == api.ChannelTypeWebhook {
			configBytes, err := json.Marshal(channel.Config)
			if err != nil {
				continue
			}

			var config WebhookChannelConfig
			err = json.Unmarshal(configBytes, &config)
			if err != nil {
				continue
			}

			if config.WebhookURL != "" {
				webhooks[config.WebhookURL] = config.Method
			}
		}
	}

	msBytes, err := json.Marshal(eventData)
	if err != nil {
		return err
	}

	for webhookURL, method := range webhooks {
		req, err := http.NewRequest(method, webhookURL, bytes.NewBuffer(msBytes))
		if err != nil {
			return err
		}

		_, err = http.DefaultClient.Do(req)
		if err != nil {
			continue
		}

	}

	return nil
}
