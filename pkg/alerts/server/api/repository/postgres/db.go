package postgres

import (
	"context"
	"encoding/json"
	"time"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/go-kit/kit/log"
	"github.com/go-kit/log/level"
	"github.com/jakehl/goid"
	"github.com/lamassuiot/lamassuiot/pkg/alerts/common/api"
	alerterrors "github.com/lamassuiot/lamassuiot/pkg/alerts/server/api/errors"
	"github.com/lamassuiot/lamassuiot/pkg/alerts/server/api/repository"
	"github.com/lib/pq"
	"gorm.io/gorm"
)

type SubscriptionDAO struct {
	ID               string `gorm:"primaryKey"`
	UserID           string
	Event            string
	Channel          ChannelDAO     `gorm:"foreignKey:SubscriptionID"`
	Conditions       pq.StringArray `gorm:"type:text[]"`
	SubscriptionDate time.Time
	ConditionType    api.ConditionType
	ExpectedValue    string
}

type ChannelDAO struct {
	ID             string `gorm:"primaryKey"`
	SubscriptionID string `gorm:"primaryKey"`
	Name           string
	Type           string
	Config         string
}

type LogEventDAO struct {
	EventType string `gorm:"primaryKey"`
	Event     string
	Date      time.Time
}

func (SubscriptionDAO) TableName() string {
	return "subscriptions"
}

func (ChannelDAO) TableName() string {
	return "channels"
}

func (LogEventDAO) TableName() string {
	return "events"
}

func (c *ChannelDAO) toChannel() api.Channel {
	var config map[string]interface{}
	json.Unmarshal([]byte(c.Config), &config)
	return api.Channel{
		Name:   c.Name,
		Type:   api.ChannelType(c.Type),
		Config: config,
	}
}

func (c *LogEventDAO) toLogEvent() (api.LogEvent, error) {
	var event cloudevents.Event
	err := json.Unmarshal([]byte(c.Event), &event)
	if err != nil {
		return api.LogEvent{}, err
	}

	logEvent := api.LogEvent{
		EventType: c.EventType,
		Event:     event,
		Date:      c.Date,
	}

	return logEvent, nil
}

func NewPostgresDB(db *gorm.DB, logger log.Logger) repository.AlertsRepository {
	db.AutoMigrate(&ChannelDAO{})
	db.AutoMigrate(&SubscriptionDAO{})
	db.AutoMigrate(&LogEventDAO{})

	return &PostgresDBContext{db, logger}
}

type PostgresDBContext struct {
	*gorm.DB
	logger log.Logger
}

func (db PostgresDBContext) GetUserSubscriptions(ctx context.Context, userID string) (api.UserSubscription, error) {
	var susbscriptions []SubscriptionDAO

	if err := db.WithContext(ctx).Model(&SubscriptionDAO{}).Where("user_id = ?", userID).First(&susbscriptions).Error; err != nil {
		notFoundErr := &alerterrors.ResourceNotFoundError{
			ResourceType: "User",
			ResourceId:   userID,
		}
		return api.UserSubscription{}, notFoundErr
	}

	db.WithContext(ctx).Model(&SubscriptionDAO{}).Where("user_id= ? ", userID).Preload("Channel").Find(&susbscriptions)

	userSubs := api.UserSubscription{
		Subscriptions: []api.Subscription{},
	}

	for _, v := range susbscriptions {
		userSubs.Subscriptions = append(userSubs.Subscriptions, api.Subscription{
			ID:               v.ID,
			EventType:        v.Event,
			SubscriptionDate: v.SubscriptionDate,
			UserID:           v.UserID,
			Channel:          v.Channel.toChannel(),
			Conditions:       v.Conditions,
			ConditionType:    v.ConditionType,
			ExpectedValue:    v.ExpectedValue,
		})
	}

	return userSubs, nil
}

func (db PostgresDBContext) Subscribe(ctx context.Context, userID string, channel api.Channel, conditions []string, eventType string, conditionType api.ConditionType, expectedValue string) error {
	configBytes, err := json.Marshal(channel.Config)
	if err != nil {
		return err
	}

	if err := db.WithContext(ctx).Create(&SubscriptionDAO{
		ID:     goid.NewV4UUID().String(),
		UserID: userID,
		Channel: ChannelDAO{
			ID:     goid.NewV4UUID().String(),
			Name:   channel.Name,
			Type:   string(channel.Type),
			Config: string(configBytes),
		},
		Event:            eventType,
		SubscriptionDate: time.Now(),
		Conditions:       conditions,
		ConditionType:    conditionType,
		ExpectedValue:    expectedValue,
	}).Error; err != nil {
		level.Debug(db.logger).Log("msg", "Could not create subscription", "err", err)
		return err
	}

	return nil
}

func (db PostgresDBContext) Unsubscribe(ctx context.Context, userID string, subscriptionID string) error {
	var sub SubscriptionDAO
	if err := db.WithContext(ctx).Model(&SubscriptionDAO{}).Where("user_id= ? ", userID).Where("id= ? ", subscriptionID).Preload("Channel").Find(&sub).Error; err != nil {
		level.Debug(db.logger).Log("msg", "Could not obtain User from database")
		notFoundErr := &alerterrors.ResourceNotFoundError{
			ResourceType: "UserID",
			ResourceId:   userID,
		}
		return notFoundErr
	}

	err := db.DeleteChannel(ctx, sub.Channel.ID)
	if err != nil {
		return err
	}

	if err := db.WithContext(ctx).Delete(&sub).Error; err != nil {
		return err
	}

	return nil
}

func (db PostgresDBContext) GetSubscriptionsByEventType(ctx context.Context, eventType string) ([]api.Subscription, error) {
	subsDAO := []SubscriptionDAO{}
	if err := db.WithContext(ctx).Where("event = ?", eventType).Preload("Channel").Find(&subsDAO).Error; err != nil {
		level.Debug(db.logger).Log("msg", "Could not get subscription", "err", err)
		return make([]api.Subscription, 0), err
	}

	subs := []api.Subscription{}
	for _, v := range subsDAO {
		subs = append(subs, api.Subscription{
			ID:               v.ID,
			EventType:        v.Event,
			SubscriptionDate: v.SubscriptionDate,
			UserID:           v.UserID,
			Channel:          v.Channel.toChannel(),
			Conditions:       v.Conditions,
			ConditionType:    v.ConditionType,
		})
	}

	return subs, nil
}

func (db PostgresDBContext) CreateChannel(ctx context.Context, id string, channeltype string, name string, config string) error {
	if err := db.WithContext(ctx).Create(&ChannelDAO{
		ID:     id,
		Name:   name,
		Config: config,
	}).Error; err != nil {
		level.Debug(db.logger).Log("msg", "Could not create channel", "err", err)
		duplicateErr := &alerterrors.DuplicateResourceError{
			ResourceType: "Channel",
			ResourceId:   id,
		}
		return duplicateErr
	}

	return nil
}

func (db PostgresDBContext) DeleteChannel(ctx context.Context, id string) error {
	if err := db.WithContext(ctx).Where("id = ?", id).Delete(&ChannelDAO{}).Error; err != nil {
		level.Debug(db.logger).Log("msg", "Could not delte channel", "err", err)
		notFoundErr := &alerterrors.ResourceNotFoundError{
			ResourceType: "Channel",
			ResourceId:   id,
		}
		return notFoundErr
	}

	return nil
}

func (db PostgresDBContext) InsertAndUpdateEventLog(ctx context.Context, eventType string, event cloudevents.Event) error {
	var exists bool
	exists = true
	var eventDAO LogEventDAO
	if err := db.WithContext(ctx).Model(&LogEventDAO{}).Where("event_type = ?", eventType).First(&eventDAO).Error; err != nil {
		level.Debug(db.logger).Log("msg", "Could not obtain event from database")
		exists = false
	}

	serializedCloudEvent, err := event.MarshalJSON()
	if err != nil {
		return err
	}

	stringifiedCloudEvent := string(serializedCloudEvent)

	if !exists {
		tx := db.WithContext(ctx).Model(&LogEventDAO{}).Create(&LogEventDAO{
			EventType: eventType,
			Event:     stringifiedCloudEvent,
			Date:      time.Now(),
		})

		if tx.Error != nil {
			duplicationErr := &alerterrors.DuplicateResourceError{
				ResourceType: "LogEvent",
				ResourceId:   eventType,
			}
			return duplicationErr
		}
	} else {
		eventDAO.Event = stringifiedCloudEvent
		eventDAO.Date = time.Now()
		if err := db.Save(&eventDAO).Error; err != nil {
			return err
		}
	}

	return nil
}

func (db PostgresDBContext) SelectEventLogs(ctx context.Context) ([]cloudevents.Event, error) {
	var logEventsDAO []LogEventDAO
	tx := db.WithContext(ctx).Model(&LogEventDAO{})
	if err := tx.Find(&logEventsDAO).Error; err != nil {
		level.Debug(db.logger).Log("err", err, "msg", "Could not obtain logs from database")
		return []cloudevents.Event{}, err
	}

	var logEvents = []cloudevents.Event{}
	for _, v := range logEventsDAO {
		event := cloudevents.Event{}
		err := json.Unmarshal([]byte(v.Event), &event)
		if err != nil {
			level.Debug(db.logger).Log("err", err)
			continue
		}
		logEvents = append(logEvents, event)
	}

	return logEvents, nil
}
