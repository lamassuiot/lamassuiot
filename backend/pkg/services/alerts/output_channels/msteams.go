package outputchannels

import (
	"context"
	"encoding/json"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	lconfig "github.com/lamassuiot/lamassuiot/v4/backend/pkg/config"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/sirupsen/logrus"
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
	name   string
	config models.MSTeamsChannelConfig
}

func NewMSTeamsOutputService(name string, config models.MSTeamsChannelConfig) NotificationSenderService {
	return &MSTeamsWebhookOutputService{
		name:   name,
		config: config,
	}
}

func (s *MSTeamsWebhookOutputService) SendNotification(logger *logrus.Entry, ctx context.Context, event cloudevents.Event) error {
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

	return sendHTTPNotification(ctx, logger, s.name, s.config.WebhookURL, "POST", s.config.HTTPClient, msBytes)
}

func RegisterMSTeamsOutputServiceBuilder() {
	RegisterOutputServiceBuilder(models.ChannelTypeMSTeams, func(c models.Channel, smtpServer lconfig.SMTPServer) (NotificationSenderService, error) {
		webhookCfg, err := decodeChannelConfig[models.MSTeamsChannelConfig](c)
		if err != nil {
			return nil, err
		}
		return NewMSTeamsOutputService(c.Name, webhookCfg), nil
	})
}
