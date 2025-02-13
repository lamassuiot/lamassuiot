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

type MSTeamsWebhookOutputService struct {
	config models.MSTeamsChannelConfig
}

func NewMSTeamsOutputService(config models.MSTeamsChannelConfig) NotificationSenderService {
	return &MSTeamsWebhookOutputService{
		config: config,
	}
}

func (s *MSTeamsWebhookOutputService) SendNotification(ctx context.Context, event cloudevents.Event) error {
	var eventDataMap map[string]any
	json.Unmarshal(event.Data(), &eventDataMap)

	msFacts := []MSTeamsWebhookSectionFact{}
	for k, v := range eventDataMap {
		valueB, err := json.Marshal(v)
		if err != nil {
			valueB = []byte{}
		}
		msFacts = append(msFacts, MSTeamsWebhookSectionFact{
			Name:  k,
			Value: string(valueB),
		})
	}

	teamsWebhookMsg := MSTeamsWebhookMsg{
		Type:       "MessageCard",
		Context:    "http://schema.org/extensions",
		Summary:    event.Type(),
		ThemeColor: "0945F8",
		Sections: []MSTeamsWebhookSection{
			{
				ActivityTitle: event.Type(),
				ActivityText:  "eventDescription",
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

	req, err := http.NewRequest("POST", s.config.WebhookURL, bytes.NewBuffer(msBytes))
	if err != nil {
		return err
	}

	_, err = http.DefaultClient.Do(req)

	return err
}

func RegisterMSTeamsOutputServiceBuilder() {
	RegisterOutputServiceBuilder(models.ChannelTypeMSTeams, func(c models.Channel, smtpServer config.SMTPServer) (NotificationSenderService, error) {
		chanConfigBytes, err := json.Marshal(c.Config)
		if err != nil {
			return nil, err
		}
		var webhookCfg models.MSTeamsChannelConfig
		err = json.Unmarshal(chanConfigBytes, &webhookCfg)
		if err != nil {
			return nil, err
		}
		return NewMSTeamsOutputService(webhookCfg), nil
	})
}
