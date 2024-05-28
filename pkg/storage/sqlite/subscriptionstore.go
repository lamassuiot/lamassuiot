//go:build experimental
// +build experimental

package sqlite

import (
	"context"

	"github.com/lamassuiot/lamassuiot/v2/pkg/models"
	"github.com/lamassuiot/lamassuiot/v2/pkg/resources"
	"github.com/lamassuiot/lamassuiot/v2/pkg/storage"
	"gorm.io/gorm"
)

type SQLiteSubscriptionsStore struct {
	db      *gorm.DB
	querier *sqliteDBQuerier[models.Subscription]
}

func NewSubscriptionsSQLiteRepository(db *gorm.DB) (storage.SubscriptionsRepository, error) {
	querier, err := CheckAndCreateTable(db, "subscriptions", "id", models.Subscription{})
	if err != nil {
		return nil, err
	}

	return &SQLiteSubscriptionsStore{
		db:      db,
		querier: (*sqliteDBQuerier[models.Subscription])(querier),
	}, nil
}

func (db *SQLiteSubscriptionsStore) GetSubscriptions(ctx context.Context, userID string, exhaustiveRun bool, applyFunc func(models.Subscription), queryParams *resources.QueryParameters, extraOpts map[string]interface{}) (string, error) {
	opts := []gormWhereParams{
		{query: "user_id = ?", extraArgs: []any{userID}},
	}
	return db.querier.SelectAll(ctx, queryParams, opts, exhaustiveRun, applyFunc)
}

func (db *SQLiteSubscriptionsStore) Subscribe(ctx context.Context, sub *models.Subscription) (*models.Subscription, error) {
	return db.querier.Insert(ctx, sub, sub.ID)
}

func (db *SQLiteSubscriptionsStore) Unsubscribe(ctx context.Context, subscriptionID string) error {
	return db.querier.Delete(ctx, subscriptionID)
}

func (db *SQLiteSubscriptionsStore) GetSubscriptionsByEventType(ctx context.Context, eventType string, exhaustiveRun bool, applyFunc func(models.Subscription), queryParams *resources.QueryParameters, extraOpts map[string]interface{}) (string, error) {
	opts := []gormWhereParams{
		{query: "event_type = ?", extraArgs: []any{eventType}},
	}
	return db.querier.SelectAll(ctx, queryParams, opts, exhaustiveRun, applyFunc)
}
