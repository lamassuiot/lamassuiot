package postgres

import (
	"context"

	"github.com/lamassuiot/lamassuiot/v2/pkg/models"
	"github.com/lamassuiot/lamassuiot/v2/pkg/resources"
	"github.com/lamassuiot/lamassuiot/v2/pkg/storage"
	"gorm.io/gorm"
)

type PostgresSubscriptionsStore struct {
	db      *gorm.DB
	querier *postgresDBQuerier[models.Subscription]
}

func NewSubscriptionsPostgresRepository(db *gorm.DB) (storage.SubscriptionsRepository, error) {
	querier, err := CheckAndCreateTable(db, "subscriptions", "id", models.Subscription{})
	if err != nil {
		return nil, err
	}

	return &PostgresSubscriptionsStore{
		db:      db,
		querier: (*postgresDBQuerier[models.Subscription])(querier),
	}, nil
}

func (db *PostgresSubscriptionsStore) GetSubscriptions(ctx context.Context, userID string, exhaustiveRun bool, applyFunc func(models.Subscription), queryParams *resources.QueryParameters, extraOpts map[string]interface{}) (string, error) {
	opts := []gormWhereParams{
		{query: "user_id = ?", extraArgs: []any{userID}},
	}
	return db.querier.SelectAll(ctx, queryParams, opts, exhaustiveRun, applyFunc)
}

func (db *PostgresSubscriptionsStore) Subscribe(ctx context.Context, sub *models.Subscription) (*models.Subscription, error) {
	return db.querier.Insert(ctx, sub, sub.ID)
}

func (db *PostgresSubscriptionsStore) Unsubscribe(ctx context.Context, subscriptionID string) error {
	return db.querier.Delete(ctx, subscriptionID)
}

func (db *PostgresSubscriptionsStore) GetSubscriptionsByEventType(ctx context.Context, eventType string, exhaustiveRun bool, applyFunc func(models.Subscription), queryParams *resources.QueryParameters, extraOpts map[string]interface{}) (string, error) {
	opts := []gormWhereParams{
		{query: "event_type = ?", extraArgs: []any{eventType}},
	}
	return db.querier.SelectAll(ctx, queryParams, opts, exhaustiveRun, applyFunc)
}
