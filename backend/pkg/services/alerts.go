package services

import (
	"context"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lamassuiot/lamassuiot/backend/v3/pkg/config"
	eventfilters "github.com/lamassuiot/lamassuiot/backend/v3/pkg/services/alerts/event_filters"
	outputchannels "github.com/lamassuiot/lamassuiot/backend/v3/pkg/services/alerts/output_channels"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/helpers"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/services"
	"github.com/sirupsen/logrus"
)

type AlertsServiceBackend struct {
	subsStorage            storage.SubscriptionsRepository
	eventStorage           storage.EventRepository
	storedEventsStorage    storage.StoredEventsRepository
	retentionSettingsStore storage.EventRetentionSettingsRepository
	smtpServerConfig       config.SMTPServer
	logger                 *logrus.Entry
}

type AlertsServiceBuilder struct {
	SubsStorage            storage.SubscriptionsRepository
	EventStorage           storage.EventRepository
	StoredEventsStorage    storage.StoredEventsRepository
	RetentionSettingsStore storage.EventRetentionSettingsRepository
	SmtpServerConfig       config.SMTPServer
	Logger                 *logrus.Entry
}

func NewAlertsService(builder AlertsServiceBuilder) services.AlertsService {
	return &AlertsServiceBackend{
		subsStorage:            builder.SubsStorage,
		eventStorage:           builder.EventStorage,
		storedEventsStorage:    builder.StoredEventsStorage,
		retentionSettingsStore: builder.RetentionSettingsStore,
		smtpServerConfig:       builder.SmtpServerConfig,
		logger:                 builder.Logger,
	}
}

func (svc *AlertsServiceBackend) storeLastEventInstance(ctx context.Context, input *services.HandleEventInput) error {
	exists, storedEv, err := svc.eventStorage.GetLatestEventByEventType(ctx, models.EventType(input.Event.Type()))
	if err != nil {
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
	return err
}

func (svc *AlertsServiceBackend) storeEventInstance(ctx context.Context, input *services.HandleEventInput) error {
	if !strings.HasPrefix(input.Event.Type(), "audit.") {
		return nil
	}

	retentionSettings, err := svc.retentionSettingsStore.Get(ctx)
	if err != nil {
		return err
	}

	now := time.Now()
	ev := &models.StoredEvent{
		ID:         uuid.NewString(),
		EventType:  input.Event.Type(),
		Event:      input.Event,
		ReceivedAt: now,
		ExpiresAt:  now.Add(retentionSettings.AuditEventTTL),
	}

	_, err = svc.storedEventsStorage.Insert(ctx, ev)
	return err
}

func (svc *AlertsServiceBackend) HandleEvent(ctx context.Context, input *services.HandleEventInput) error {
	lFunc := helpers.ConfigureLogger(ctx, svc.logger)

	lFunc.Infof("handling Event ID '%s'. Event Type '%s'", input.Event.ID(), input.Event.Type())
	err := svc.storeLastEventInstance(ctx, input)
	if err != nil {
		lFunc.Errorf("could not insert/update latest event: %s", err)
	}

	if err := svc.storeEventInstance(ctx, input); err != nil {
		lFunc.Errorf("could not store event instance: %s", err)
	}

	sendAlert := func(sub models.Subscription) {
		// Send alert
		lFunc.Debugf("sending notification to user %s via %s", sub.UserID, sub.Channel.Type)

		// Evaluate conditions
		conditionsMet, err := eventfilters.EvalConditions(sub.Conditions, input.Event)
		if err != nil {
			lFunc.Errorf("error while evaluating condition for user %s: %s", sub.UserID, err)
		}

		if conditionsMet {
			// Send notification
			err = outputchannels.SendNotification(lFunc, ctx, sub.Channel, svc.smtpServerConfig, input.Event)
			if err != nil {
				lFunc.Errorf("error while sending notification to user %s via %s. Event ID '%s'. Event Type '%s'. Got error: %s", sub.UserID, sub.Channel.Type, input.Event.ID(), input.Event.Type(), err)
			}

		} else {
			lFunc.Debugf("conditions not met for user %s, skipping notification", sub.UserID)
		}
	}

	_, err = svc.subsStorage.GetSubscriptionsByEventType(ctx, input.Event.Type(), true, sendAlert, nil, nil)
	if err != nil {
		lFunc.Errorf("could not get user subscriptions for event type %s: %s", input.Event.Type(), err)
		return err
	}
	lFunc.Debugf("completed handling Event ID '%s'. Event Type '%s'", input.Event.ID(), input.Event.Type())
	return nil
}

func (svc *AlertsServiceBackend) GetLatestEventsPerEventType(ctx context.Context, input *services.GetLatestEventsPerEventTypeInput) ([]*models.AlertLatestEvent, error) {
	lFunc := helpers.ConfigureLogger(ctx, svc.logger)

	events, err := svc.eventStorage.GetLatestEvents(ctx)
	if err != nil {
		lFunc.Errorf("got unexpected error while reading events: %s", err)
		return nil, err
	}

	return events, nil
}

func (svc *AlertsServiceBackend) GetEvents(ctx context.Context, input *services.GetEventsInput) (string, error) {
	lFunc := helpers.ConfigureLogger(ctx, svc.logger)

	nextBookmark, err := svc.storedEventsStorage.GetAll(ctx, input.ExhaustiveRun, input.ApplyFunc, input.QueryParameters, nil)
	if err != nil {
		lFunc.Errorf("got unexpected error while reading stored events: %s", err)
		return "", err
	}

	return nextBookmark, nil
}

func (svc *AlertsServiceBackend) GetEventByID(ctx context.Context, input *services.GetEventByIDInput) (*models.StoredEvent, error) {
	lFunc := helpers.ConfigureLogger(ctx, svc.logger)

	exists, ev, err := svc.storedEventsStorage.GetByID(ctx, input.ID)
	if err != nil {
		lFunc.Errorf("got unexpected error while reading stored event %s: %s", input.ID, err)
		return nil, err
	}

	if !exists {
		return nil, nil
	}

	return ev, nil
}

func (svc *AlertsServiceBackend) GetEventRetentionSettings(ctx context.Context) (*models.EventRetentionSettings, error) {
	lFunc := helpers.ConfigureLogger(ctx, svc.logger)

	settings, err := svc.retentionSettingsStore.Get(ctx)
	if err != nil {
		lFunc.Errorf("got unexpected error while reading retention settings: %s", err)
		return nil, err
	}

	return settings, nil
}

func (svc *AlertsServiceBackend) UpdateEventRetentionSettings(ctx context.Context, input *services.UpdateEventRetentionSettingsInput) (*models.EventRetentionSettings, error) {
	lFunc := helpers.ConfigureLogger(ctx, svc.logger)

	auditTTL, err := time.ParseDuration(input.AuditEventTTL)
	if err != nil {
		return nil, err
	}

	settings, err := svc.retentionSettingsStore.Update(ctx, &models.EventRetentionSettings{
		AuditEventTTL: auditTTL,
	})
	if err != nil {
		lFunc.Errorf("got unexpected error while updating retention settings: %s", err)
		return nil, err
	}

	return settings, nil
}

func (svc *AlertsServiceBackend) GetUserSubscriptions(ctx context.Context, input *services.GetUserSubscriptionsInput) ([]*models.Subscription, error) {
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

func (svc *AlertsServiceBackend) Subscribe(ctx context.Context, input *services.SubscribeInput) ([]*models.Subscription, error) {
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

	return svc.GetUserSubscriptions(ctx, &services.GetUserSubscriptionsInput{UserID: input.UserID})
}

func (svc *AlertsServiceBackend) Unsubscribe(ctx context.Context, input *services.UnsubscribeInput) ([]*models.Subscription, error) {
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
