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
	WebhookURL    string `json:"webhook_url"`
	WebhookMethod string `json:"webhook_method"`
}

func (s *WebhookOutputService) ParseEventAndSend(ctx context.Context, eventType string, eventDescription string, eventData map[string]string, channel api.Channel) error {
	msBytes, err := json.Marshal(eventData)
	if err != nil {
		return err
	}

	if channel.Type == api.ChannelTypeWebhook {
		configBytes, err := json.Marshal(channel.Config)
		if err != nil {
			return err
		}

		var config WebhookChannelConfig
		err = json.Unmarshal(configBytes, &config)
		if err != nil {
			return err
		}

		if config.WebhookURL != "" {
			req, err := http.NewRequest(config.WebhookMethod, config.WebhookURL, bytes.NewBuffer(msBytes))
			if err != nil {
				return err
			}

			_, err = http.DefaultClient.Do(req)
			if err != nil {
				return err
			}

		}
	}

	return nil
}
