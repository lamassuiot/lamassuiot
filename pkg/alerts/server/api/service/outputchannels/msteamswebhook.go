package outputchannels

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"

	"github.com/lamassuiot/lamassuiot/pkg/alerts/common/api"
)

type MSTeamsWebhookSectionFact struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type MSTeamsWebhookSection struct {
	ActivityTitle string `json:"activityTitle"`
	ActivityText  string `json:"activityText"`
	ActivityImage string `json:"activityImage"`
	Facts         []MSTeamsWebhookSectionFact
	Markdown      bool `json:"markdown"`
}
type MSTeamsWebhookMsg struct {
	Type       string `json:"@type"`
	Context    string `json:"@context"`
	Summary    string `json:"summary"`
	ThemeColor string `json:"themeColor"`
	Sections   []MSTeamsWebhookSection
}

type MSTeamsChannelConfig struct {
	WebhookURL string `json:"webhook_url"`
}

type MSTeamsOutputService struct{}

func (s *MSTeamsOutputService) ParseEventAndSend(ctx context.Context, eventType string, eventDescription string, eventData map[string]string, channels []api.Channel) error {
	webhooks := make([]string, 0)
	for _, channel := range channels {
		if channel.Type == api.ChannelTypeMSTeams {
			configBytes, err := json.Marshal(channel.Config)
			if err != nil {
				continue
			}

			var config MSTeamsChannelConfig
			err = json.Unmarshal(configBytes, &config)
			if err != nil {
				continue
			}

			if config.WebhookURL != "" {
				webhooks = append(webhooks, config.WebhookURL)
			}
		}
	}

	msFacts := []MSTeamsWebhookSectionFact{}
	for k, v := range eventData {
		msFacts = append(msFacts, MSTeamsWebhookSectionFact{
			Name:  k,
			Value: v,
		})
	}
	teamsWebhookMsg := MSTeamsWebhookMsg{
		Type:       "MessageCard",
		Context:    "http://schema.org/extensions",
		Summary:    eventType,
		ThemeColor: "0945F8",
		Sections: []MSTeamsWebhookSection{
			{
				ActivityTitle: eventType,
				ActivityText:  eventDescription,
				ActivityImage: "https://avatars.githubusercontent.com/u/27340420?s=200&v=4",
				Facts:         msFacts,
				Markdown:      true,
			},
		},
	}

	msBytes, err := json.Marshal(teamsWebhookMsg)
	if err != nil {
		return err
	}

	for _, webhookURL := range webhooks {
		req, err := http.NewRequest("POST", webhookURL, bytes.NewBuffer(msBytes))
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
