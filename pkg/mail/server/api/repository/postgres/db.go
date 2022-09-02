package postgres

import (
	"context"
	"encoding/json"
	"time"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/go-kit/kit/log"
	"github.com/go-kit/log/level"
	"github.com/lamassuiot/lamassuiot/pkg/mail/common/api"
	mailerrors "github.com/lamassuiot/lamassuiot/pkg/mail/server/api/errors"
	"github.com/lamassuiot/lamassuiot/pkg/mail/server/api/repository"
	"github.com/lib/pq"
	"gorm.io/gorm"
)

type SubscriptionDAO struct {
	Email            string         `gorm:"primaryKey"`
	SubscribedEvents pq.StringArray `gorm:"type:text[]"`
}

type LogEventDAO struct {
	EventType string `gorm:"primaryKey"`
	Event     string
	Date      time.Time
}

func (SubscriptionDAO) TableName() string {
	return "subscriptions"
}

func (LogEventDAO) TableName() string {
	return "events"
}

func (c *SubscriptionDAO) toUserConfiguration() (api.Subscription, error) {

	userConfiguration := api.Subscription{
		Email:            c.Email,
		SubscribedEvents: c.SubscribedEvents,
	}

	return userConfiguration, nil
}

func (c *LogEventDAO) toLogEvent() (api.LogEvent, error) {

	var event cloudevents.Event
	err := json.Unmarshal([]byte(c.Event), &event)

	logEvent := api.LogEvent{
		EventType: c.EventType,
		Event:     event,
		Date:      c.Date,
	}

	return logEvent, err
}

func NewPostgresDB(db *gorm.DB, logger log.Logger) repository.MailConfiguration {
	db.AutoMigrate(&SubscriptionDAO{})
	db.AutoMigrate(&LogEventDAO{})

	return &PostgresDBContext{db, logger}
}

type PostgresDBContext struct {
	*gorm.DB
	logger log.Logger
}

func (db *PostgresDBContext) AddSubscription(ctx context.Context, email string, events []string) error {
	var userConfig SubscriptionDAO

	if err := db.Model(&SubscriptionDAO{}).Where("email = ?", email).First(&userConfig).Error; err != nil {
		level.Debug(db.logger).Log("msg", "Could not obtain user from database")
		notFoundErr := &mailerrors.ResourceNotFoundError{
			ResourceType: "Certificate",
			ResourceId:   email,
		}
		return notFoundErr
	}

	userConfig.Email = email
	userConfig.SubscribedEvents = events

	db.Save(&userConfig)

	return nil
}

func (db PostgresDBContext) SelectSubscribersByEventType(ctx context.Context, eventType string) ([]api.Subscription, error) {

	var usersConfig []SubscriptionDAO
	tx := db.Model(&SubscriptionDAO{}).Where(" ? = ANY(subscribed_events) ", eventType)
	if err := tx.Find(&usersConfig).Error; err != nil {
		level.Debug(db.logger).Log("err", err, "msg", "Could not obtain subscribers from database")
		return []api.Subscription{}, err
	}

	var subscribersEmail []api.Subscription
	for _, v := range usersConfig {
		userConfig, err := v.toUserConfiguration()
		if err != nil {
			level.Debug(db.logger).Log("err", err)
			continue
		}
		subscribersEmail = append(subscribersEmail, userConfig)
	}

	return subscribersEmail, nil
}

func (db PostgresDBContext) SubscribeToEvents(ctx context.Context, email string, eventType string) (api.Subscription, error) {
	var exists bool
	exists = true

	var userConfig SubscriptionDAO
	if err := db.Model(&SubscriptionDAO{}).Where("email = ?", email).First(&userConfig).Error; err != nil {
		exists = false
	}
	if !exists {
		tx := db.Model(&SubscriptionDAO{}).Create(&SubscriptionDAO{
			Email:            email,
			SubscribedEvents: []string{eventType},
		})

		if tx.Error != nil {
			duplicationErr := &mailerrors.DuplicateResourceError{
				ResourceType: "LogEvent",
				ResourceId:   eventType,
			}
			return api.Subscription{}, duplicationErr
		}
	} else {
		userConfig.SubscribedEvents = append(userConfig.SubscribedEvents, eventType)
		if err := db.Save(&userConfig).Error; err != nil {
			return api.Subscription{Email: email,
				SubscribedEvents: userConfig.SubscribedEvents}, err
		}
	}

	return api.Subscription{
		Email:            userConfig.Email,
		SubscribedEvents: userConfig.SubscribedEvents,
	}, nil
}

func (db PostgresDBContext) UnSubscribeToEvents(ctx context.Context, email string, eventType string) (api.Subscription, error) {
	var userConfig SubscriptionDAO

	if err := db.Model(&SubscriptionDAO{}).Where("email = ?", email).First(&userConfig).Error; err != nil {

		level.Debug(db.logger).Log("err", err, "msg", "Could not obtain subscribers from database")
		return api.Subscription{}, err

	}

	userConfig.SubscribedEvents = remove(userConfig.SubscribedEvents, eventType)
	if err := db.Save(&userConfig).Error; err != nil {
		return api.Subscription{}, err

	}

	return userConfig.toUserConfiguration()
}

func (db PostgresDBContext) InsertAndUpdateEventLog(ctx context.Context, eventType string, event cloudevents.Event) error {
	var exists bool
	exists = true
	var eventDAO LogEventDAO
	if err := db.Model(&LogEventDAO{}).Where("event_type = ?", eventType).First(&eventDAO).Error; err != nil {
		level.Debug(db.logger).Log("msg", "Could not obtain CAs from database")
		exists = false
	}

	serializedCloudEvent, err := event.MarshalJSON()
	if err != nil {
		return err
	}

	stringifiedCloudEvent := string(serializedCloudEvent)

	if !exists {
		tx := db.Model(&LogEventDAO{}).Create(&LogEventDAO{
			EventType: eventType,
			Event:     stringifiedCloudEvent,
			Date:      time.Now(),
		})

		if tx.Error != nil {
			duplicationErr := &mailerrors.DuplicateResourceError{
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
	tx := db.Model(&LogEventDAO{})
	if err := tx.Find(&logEventsDAO).Error; err != nil {
		level.Debug(db.logger).Log("err", err, "msg", "Could not obtain subscribers from database")
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

func remove(s []string, r string) []string {
	for i, v := range s {
		if v == r {
			return append(s[:i], s[i+1:]...)
		}
	}
	return s
}
