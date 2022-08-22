package postgres

import (
	"context"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/log/level"
	"github.com/lamassuiot/lamassuiot/pkg/mail/common/api"
	mailerrors "github.com/lamassuiot/lamassuiot/pkg/mail/server/api/errors"
	"github.com/lamassuiot/lamassuiot/pkg/mail/server/api/repository"
	"github.com/lib/pq"

	"gorm.io/gorm"
)

type UserConfigurationDAO struct {
	UserID           string `gorm:"primaryKey"`
	Email            string
	SubscribedEvents pq.StringArray `gorm:"type:text[]"`
}

func (UserConfigurationDAO) TableName() string {
	return "users_config"
}

func (c *UserConfigurationDAO) toUserConfiguration() (api.UserConfiguration, error) {

	userConfiguration := api.UserConfiguration{
		UserID:           c.UserID,
		Email:            c.Email,
		SubscribedEvents: c.SubscribedEvents,
	}

	return userConfiguration, nil
}
func NewPostgresDB(db *gorm.DB, logger log.Logger) repository.MailConfiguration {
	db.AutoMigrate(&UserConfigurationDAO{})

	return &PostgresDBContext{db, logger}
}

type PostgresDBContext struct {
	*gorm.DB
	logger log.Logger
}

func (db *PostgresDBContext) UpdateUserConfiguration(ctx context.Context, userID string, email string, events []string) error {
	var userConfig UserConfigurationDAO

	if err := db.Model(&UserConfigurationDAO{}).Where("user_id = ?", userID).First(&userConfig).Error; err != nil {
		level.Debug(db.logger).Log("msg", "Could not obtain user from database")
		notFoundErr := &mailerrors.ResourceNotFoundError{
			ResourceType: "Certificate",
			ResourceId:   userID,
		}
		return notFoundErr
	}

	userConfig.Email = email
	userConfig.SubscribedEvents = events

	db.Save(&userConfig)

	return nil
}

func (db PostgresDBContext) InsertUserConfiguration(ctx context.Context, userID string, email string, events []string) error {
	tx := db.Model(&UserConfigurationDAO{}).Create(&UserConfigurationDAO{
		UserID:           userID,
		Email:            email,
		SubscribedEvents: events,
	})

	if tx.Error != nil {
		duplicationErr := &mailerrors.DuplicateResourceError{
			ResourceType: "UserConfiguration",
			ResourceId:   userID,
		}
		return duplicationErr
	}

	return nil
}

func (db PostgresDBContext) SelectSubscribersByEventType(ctx context.Context, eventType string) ([]api.UserConfiguration, error) {

	var usersConfig []UserConfigurationDAO
	tx := db.Model(&UserConfigurationDAO{}).Where(" ? = ANY(subscribed_events) ", eventType)
	if err := tx.Find(&usersConfig).Error; err != nil {
		level.Debug(db.logger).Log("err", err, "msg", "Could not obtain subscribers from database")
		return []api.UserConfiguration{}, err
	}

	var subscribersEmail []api.UserConfiguration
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

func (db PostgresDBContext) SelectUserConfigurationByUserID(ctx context.Context, userID string) (api.UserConfiguration, error) {
	var userConfig UserConfigurationDAO
	if err := db.Model(&UserConfigurationDAO{}).Where("user_id = ?", userID).First(&userConfig).Error; err != nil {
		level.Debug(db.logger).Log("err", err, "msg", "Could not obtain user configuration from database")
		notFoundErr := &mailerrors.ResourceNotFoundError{
			ResourceType: "User Configuration",
			ResourceId:   userConfig.UserID,
		}
		return api.UserConfiguration{}, notFoundErr
	}

	return userConfig.toUserConfiguration()
}

func (db PostgresDBContext) SubscribeToEvents(ctx context.Context, userID string, eventType []string) (api.UserConfiguration, error) {
	var userConfig UserConfigurationDAO
	if err := db.Model(&UserConfigurationDAO{}).Where("user_id = ?", userID).First(&userConfig).Error; err != nil {
		return api.UserConfiguration{}, err
	}

	for _, v := range eventType {
		userConfig.SubscribedEvents = append(userConfig.SubscribedEvents, v)
	}

	if err := db.Save(&userConfig).Error; err != nil {
		return api.UserConfiguration{}, err
	}
	return userConfig.toUserConfiguration()
}

func (db PostgresDBContext) UnSubscribeToEvents(ctx context.Context, userID string, eventType []string) (api.UserConfiguration, error) {
	var userConfig UserConfigurationDAO
	if err := db.Model(&UserConfigurationDAO{}).Where("user_id = ?", userID).First(&userConfig).Error; err != nil {
		return api.UserConfiguration{}, err
	}

	for _, v := range eventType {
		if len(userConfig.SubscribedEvents) > 0 {
			userConfig.SubscribedEvents = remove(userConfig.SubscribedEvents, v)
		}
	}

	if err := db.Save(&userConfig).Error; err != nil {
		return api.UserConfiguration{}, err
	}
	return userConfig.toUserConfiguration()
}

func remove(s []string, r string) []string {
	for i, v := range s {
		if v == r {
			return append(s[:i], s[i+1:]...)
		}
	}
	return s
}
