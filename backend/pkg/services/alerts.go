package services

import (
	"context"
	"encoding/json"
	"time"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/google/uuid"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/config"
	outputChannels "github.com/lamassuiot/lamassuiot/backend/v3/pkg/services/alerts/output_channels"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"
	"github.com/sirupsen/logrus"
)

type AlertsService interface {
	HandleEvent(ctx context.Context, input *HandleEventInput) error
	GetUserSubscriptions(ctx context.Context, input *GetUserSubscriptionsInput) ([]*models.Subscription, error)
	Subscribe(ctx context.Context, input *SubscribeInput) ([]*models.Subscription, error)
	Unsubscribe(ctx context.Context, input *UnsubscribeInput) ([]*models.Subscription, error)

	GetLatestEventsPerEventType(ctx context.Context, input *GetLatestEventsPerEventTypeInput) ([]*models.AlertLatestEvent, error)
}

type AlertsServiceBackend struct {
	subsStorage      storage.SubscriptionsRepository
	eventStorage     storage.EventRepository
	smtpServerConfig config.SMTPServer
	logger           *logrus.Entry
}

type AlertsServiceBuilder struct {
	SubsStorage      storage.SubscriptionsRepository
	EventStorage     storage.EventRepository
	SmtpServerConfig config.SMTPServer
	Logger           *logrus.Entry
}

func NewAlertsService(builder AlertsServiceBuilder) AlertsService {
	return &AlertsServiceBackend{
		subsStorage:      builder.SubsStorage,
		eventStorage:     builder.EventStorage,
		smtpServerConfig: builder.SmtpServerConfig,
		logger:           builder.Logger,
	}
}

type HandleEventInput struct {
	Event cloudevents.Event
}

func (svc *AlertsServiceBackend) HandleEvent(ctx context.Context, input *HandleEventInput) error {
	lFunc := helpers.ConfigureLogger(ctx, svc.logger)

	lFunc.Infof("handling Event ID '%s'. Event Type '%s'", input.Event.ID(), input.Event.Type())
	exists, storedEv, err := svc.eventStorage.GetLatestEventByEventType(ctx, models.EventType(input.Event.Type()))
	if err != nil {
		lFunc.Errorf("could not obtain last event stored for type %s", input.Event.Type())
		return err
	}

	if !exists {
		storedEv = &models.AlertLatestEvent{}
	}

	storedEv.TotalSeen++
	storedEv.EventType = models.EventType(input.Event.Type())
	storedEv.Event = input.Event
	storedEv.LastSeen = time.Now()

	_, err = svc.eventStorage.InsertUpdateEvent(ctx, storedEv)
	if err != nil {
		lFunc.Errorf("could not insert/update latest event: %s", err)
		return err
	}

	_, err = svc.subsStorage.GetSubscriptionsByEventType(ctx, input.Event.Type(), true, func(sub models.Subscription) {
		// Send alert
		lFunc.Debugf("sending notification to user %s via %s", sub.UserID, sub.Channel.Type)
		var outSvc outputChannels.NotificationSenderService
		chanConfigBytes, err := json.Marshal(sub.Channel.Config)
		if err != nil {
			lFunc.Errorf("cannot get channel config to bytes")
		}
		switch sub.Channel.Type {
		case models.ChannelTypeWebhook:
			var webhookCfg models.WebhookChannelConfig
			err = json.Unmarshal(chanConfigBytes, &webhookCfg)
			if err != nil {
				lFunc.Errorf("cannot get channel config to WebhookChannelConfig")
			}
			outSvc = outputChannels.NewWebhookOutputService(webhookCfg)
		case models.ChannelTypeMSTeams:
			var webhookCfg models.MSTeamsChannelConfig
			err = json.Unmarshal(chanConfigBytes, &webhookCfg)
			if err != nil {
				lFunc.Errorf("cannot get channel config to MSTeamsChannelConfig")
			}
			outSvc = outputChannels.NewMSTeamsOutputService(webhookCfg)

		case models.ChannelTypeEmail:
			var emailConf models.EmailConfig
			err = json.Unmarshal(chanConfigBytes, &emailConf)
			if err != nil {
				lFunc.Errorf("cannot get channel config to EmailConfig")
			}
			outSvc = outputChannels.NewSMTPOutputService(emailConf, svc.smtpServerConfig)

		default:
			lFunc.Errorf("unsupported channel type. No implementation for %s", sub.Channel.Type)
		}

		err = outSvc.SendNotification(ctx, input.Event)
		if err != nil {
			lFunc.Errorf("error while sending notification to user %s via %s. Event ID '%s'. Event Type '%s'. Got error: %s", sub.UserID, sub.Channel.Type, input.Event.ID(), input.Event.Type(), err)
		}
	}, nil, nil)

	if err != nil {
		lFunc.Errorf("could not get user subscriptions for event type %s: %s", input.Event.Type(), err)
		return err
	}
	lFunc.Debugf("completed handling Event ID '%s'. Event Type '%s'", input.Event.ID(), input.Event.Type())
	return nil
}

type GetLatestEventsPerEventTypeInput struct{}

func (svc *AlertsServiceBackend) GetLatestEventsPerEventType(ctx context.Context, input *GetLatestEventsPerEventTypeInput) ([]*models.AlertLatestEvent, error) {
	lFunc := helpers.ConfigureLogger(ctx, svc.logger)

	events, err := svc.eventStorage.GetLatestEvents(ctx)
	if err != nil {
		lFunc.Errorf("got unexpected error while reading events: %s", err)
		return nil, err
	}

	return events, nil
}

type GetUserSubscriptionsInput struct {
	UserID string
}

func (svc *AlertsServiceBackend) GetUserSubscriptions(ctx context.Context, input *GetUserSubscriptionsInput) ([]*models.Subscription, error) {
	lFunc := helpers.ConfigureLogger(ctx, svc.logger)

	userSubs := []*models.Subscription{}
	_, err := svc.subsStorage.GetSubscriptions(ctx, input.UserID, true, func(sub models.Subscription) {
		derefSub := sub
		userSubs = append(userSubs, &derefSub)
	}, &resources.QueryParameters{}, map[string]interface{}{})

	if err != nil {
		lFunc.Errorf("got unexpected error while reading subscriptions from DB: %s", err)
		return nil, err
	}

	lFunc.Infof("user %s has %d active subscriptions", input.UserID, len(userSubs))

	return userSubs, nil
}

type SubscribeInput struct {
	UserID     string
	EventType  models.EventType
	Conditions []models.SubscriptionCondition
	Channel    models.Channel
}

func (svc *AlertsServiceBackend) Subscribe(ctx context.Context, input *SubscribeInput) ([]*models.Subscription, error) {
	lFunc := helpers.ConfigureLogger(ctx, svc.logger)

	lFunc.Infof("subscribing user %s to event type %s with %d conditions over %s", input.UserID, input.EventType, len(input.Conditions), input.Channel.Type)
	sub := &models.Subscription{
		ID:               uuid.NewString(),
		UserID:           input.UserID,
		EventType:        input.EventType,
		SubscriptionDate: time.Now(),
		Conditions:       input.Conditions,
		Channel:          input.Channel,
	}

	_, err := svc.subsStorage.Subscribe(ctx, sub)
	if err != nil {
		lFunc.Errorf("could not insert new subscription. Got unexpected error: %s", err)
		return nil, err
	}

	return svc.GetUserSubscriptions(ctx, &GetUserSubscriptionsInput{UserID: input.UserID})
}

type UnsubscribeInput struct {
	UserID         string
	SubscriptionID string
}

func (svc *AlertsServiceBackend) Unsubscribe(ctx context.Context, input *UnsubscribeInput) ([]*models.Subscription, error) {
	lFunc := helpers.ConfigureLogger(ctx, svc.logger)

	var loopError error
	userSubs := []*models.Subscription{}
	_, err := svc.subsStorage.GetSubscriptions(ctx, input.UserID, true, func(sub models.Subscription) {
		if sub.ID == input.SubscriptionID {
			lFunc.Infof("unsubscribing user %s from subscription with ID %s over event of type %s", input.UserID, sub.ID, sub.EventType)
			err := svc.subsStorage.Unsubscribe(ctx, input.SubscriptionID)
			if err != nil {
				lFunc.Errorf("got unexpected error while updating DB: %s", err)
				loopError = err
			}
		} else {
			derefSub := sub
			userSubs = append(userSubs, &derefSub)
		}
	}, &resources.QueryParameters{}, map[string]interface{}{})

	if err != nil {
		lFunc.Errorf("got unexpected error while reading subscriptions from DB: %s", err)
		return nil, err
	}

	if loopError != nil {
		return nil, loopError
	}

	lFunc.Infof("user %s has %d active subscriptions", input.UserID, len(userSubs))
	return userSubs, nil
}
