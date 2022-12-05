package service

import (
	"context"
	"encoding/json"
	"io/ioutil"

	"github.com/lamassuiot/lamassuiot/pkg/alerts/common/api"
	"github.com/lamassuiot/lamassuiot/pkg/alerts/server/api/repository"
	"github.com/lamassuiot/lamassuiot/pkg/alerts/server/api/service/outputchannels"
	"github.com/ohler55/ojg/oj"
	"github.com/xeipuuv/gojsonschema"

	//"github.com/xeipuuv/gojsonschema"
	"github.com/oliveagle/jsonpath"

	cloudevents "github.com/cloudevents/sdk-go/v2"
)

type EventFieldsTemplate struct {
	CloudEventFieldName string `json:"event_field_name"`
	EmailFieldName      string `json:"email_field_name"`
}

type EventTemplate struct {
	EventType string                `json:"event_type"`
	Fields    []EventFieldsTemplate `json:"fields"`
}

type Service interface {
	Health(ctx context.Context) bool
	HandleEvent(ctx context.Context, input *api.HandleEventInput) (*api.HandleEventOutput, error)
	SubscribedEvent(ctx context.Context, input *api.SubscribeEventInput) (*api.SubscribeEventOutput, error)
	UnsubscribedEvent(ctx context.Context, input *api.UnsubscribedEventInput) (*api.UnsubscribedEventOutput, error)
	GetEventLogs(ctx context.Context, input *api.GetEventsInput) ([]cloudevents.Event, error)
	GetSubscriptions(ctx context.Context, input *api.GetSubscriptionsInput) (*api.GetSubscriptionsOutput, error)
}

type alertsService struct {
	alertsRepository    repository.AlertsRepository
	eventsConfiguration map[string]EventTemplate
	smtpServer          outputchannels.SMTPOutputService
}

func NewAlertsService(alertsRepository repository.AlertsRepository, templateDataFilePath string, smtpServer outputchannels.SMTPOutputService) (Service, error) {
	file, err := ioutil.ReadFile(templateDataFilePath)
	if err != nil {
		return nil, err
	}
	eventsConfigArray := []EventTemplate{}
	_ = json.Unmarshal(file, &eventsConfigArray)

	eventsConfig := map[string]EventTemplate{}
	for _, v := range eventsConfigArray {
		eventsConfig[v.EventType] = v
	}

	return &alertsService{
		alertsRepository:    alertsRepository,
		eventsConfiguration: eventsConfig,
		smtpServer:          smtpServer,
	}, nil
}

func (s *alertsService) Health(ctx context.Context) bool {
	return true
}

func (s *alertsService) HandleEvent(ctx context.Context, input *api.HandleEventInput) (*api.HandleEventOutput, error) {
	var eventData map[string]string
	json.Unmarshal(input.Event.Data(), &eventData)

	data := map[string]string{}
	if _, ok := s.eventsConfiguration[input.Event.Type()]; !ok {
		for k, v := range eventData {
			data[k] = v
		}
	} else {
		fieldsToUse := s.eventsConfiguration[input.Event.Type()].Fields
		for _, v := range fieldsToUse {
			if _, ok := eventData[v.CloudEventFieldName]; ok {
				data[v.EmailFieldName] = eventData[v.CloudEventFieldName]
			}
		}
	}

	data["Timestamp"] = input.Event.Time().Format("2006-01-02 3:4:5 pm")

	err := s.alertsRepository.InsertAndUpdateEventLog(ctx, input.Event.Type(), input.Event)
	if err != nil {
		return nil, err
	}

	subs, err := s.alertsRepository.GetSubscriptionsByEventType(ctx, input.Event.Type())
	if err != nil {
		return nil, err
	}

	jsonData, err := input.Event.MarshalJSON()
	if err != nil {
		return nil, err
	}

	fullfiledSubs := []api.Subscription{}

	documentLoader := gojsonschema.NewStringLoader(string(jsonData))
	_, err = oj.ParseString(string(jsonData))
	if err != nil {
		return nil, err
	}

	for _, sub := range subs {
		//Test if event matches conditions and send
		if len(sub.Conditions) == 0 {
			fullfiledSubs = append(fullfiledSubs, sub)
			continue
		}

		for _, condition := range sub.Conditions {
			//Check if JSONPath or JsonSchema
			switch sub.ConditionType {
			case api.JSONSchema:
				schemaLoader := gojsonschema.NewStringLoader(condition)
				result, err := gojsonschema.Validate(schemaLoader, documentLoader)

				if err != nil {
					return nil, err
				}

				if result.Valid() {
					fullfiledSubs = append(fullfiledSubs, sub)
				}

			case api.JSONPath:

				/*json_condition, err := jp.ParseString(condition)
				if err != nil {
					return nil, err
				}*/

				res, err := jsonpath.JsonPathLookup(eventData, condition)
				if err != nil {
					return nil, err
				}

				if res != nil {
					fullfiledSubs = append(fullfiledSubs, sub)
				}
			}
		}
	}

	for _, sub := range fullfiledSubs {
		switch sub.Channel.Type {
		case api.ChannelTypeEmail:
			s.smtpServer.ParseEventAndSend(ctx, input.Event.Type(), "", data, sub.Channel)
		case api.ChannelTypeWebhook:
			webhookSvc := outputchannels.WebhookOutputService{}
			webhookSvc.ParseEventAndSend(ctx, input.Event.Type(), "", data, sub.Channel)
		case api.ChannelTypeMSTeams:
			msTeamsSvc := outputchannels.MSTeamsOutputService{}
			msTeamsSvc.ParseEventAndSend(ctx, input.Event.Type(), "", data, sub.Channel)
		}
	}

	return &api.HandleEventOutput{}, nil
}

func (s *alertsService) SubscribedEvent(ctx context.Context, input *api.SubscribeEventInput) (*api.SubscribeEventOutput, error) {

	channel := api.Channel{
		Type:   input.Channel.Type,
		Name:   input.Channel.Name,
		Config: input.Channel.Config,
	}
	err := s.alertsRepository.Subscribe(ctx, input.UserID, channel, input.Conditions, input.EventType, input.ConditionType)
	if err != nil {
		return &api.SubscribeEventOutput{}, err
	}

	userSub, err := s.alertsRepository.GetUserSubscriptions(ctx, input.UserID)

	return &api.SubscribeEventOutput{
		UserSubscription: userSub,
	}, err
}

func (s *alertsService) UnsubscribedEvent(ctx context.Context, input *api.UnsubscribedEventInput) (*api.UnsubscribedEventOutput, error) {
	_, err := s.alertsRepository.GetUserSubscriptions(ctx, input.UserID)
	if err != nil {
		return &api.UnsubscribedEventOutput{}, err
	}

	err = s.alertsRepository.Unsubscribe(ctx, input.UserID, input.SubscriptionID)
	if err != nil {

		return &api.UnsubscribedEventOutput{}, err
	}

	userSub, err := s.alertsRepository.GetUserSubscriptions(ctx, input.UserID)

	return &api.UnsubscribedEventOutput{
		UserSubscription: userSub,
	}, err
}

func (s *alertsService) GetEventLogs(ctx context.Context, input *api.GetEventsInput) ([]cloudevents.Event, error) {
	logEvents, err := s.alertsRepository.SelectEventLogs(ctx)
	if err != nil {
		return []cloudevents.Event{}, err
	}

	return logEvents, nil
}

func (s *alertsService) GetSubscriptions(ctx context.Context, input *api.GetSubscriptionsInput) (*api.GetSubscriptionsOutput, error) {
	subscription, _ := s.alertsRepository.GetUserSubscriptions(ctx, input.UserID)

	return &api.GetSubscriptionsOutput{
		UserSubscription: subscription,
	}, nil
}
