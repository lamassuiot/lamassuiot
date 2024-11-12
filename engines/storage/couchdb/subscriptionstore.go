//go:build experimental
// +build experimental

package couchdb

import (
	"context"

	kivik "github.com/go-kivik/kivik/v4"
	_ "github.com/go-kivik/kivik/v4/couchdb" // The CouchDB driver
	"github.com/lamassuiot/lamassuiot/v3/core/pkg/models"
	"github.com/lamassuiot/lamassuiot/v3/core/pkg/resources"
)

const subscriptionsDBName = "subscriptions"

type CouchSubscriptionsStore struct {
	client  *kivik.Client
	querier *couchDBQuerier[models.Subscription]
}

func NewSubscriptionsCouchRepository(client *kivik.Client) (*CouchSubscriptionsStore, error) {
	err := CheckAndCreateDB(client, subscriptionsDBName)
	if err != nil {
		return nil, err
	}

	db := client.DB(subscriptionsDBName)
	querier := newCouchDBQuerier[models.Subscription](db)

	return &CouchSubscriptionsStore{
		client:  client,
		querier: &querier,
	}, nil
}

func (db *CouchSubscriptionsStore) GetSubscriptions(ctx context.Context, userID string, exhaustiveRun bool, applyFunc func(models.Subscription), queryParams *resources.QueryParameters, extraOpts map[string]interface{}) (string, error) {
	opts := map[string]interface{}{
		"selector": map[string]interface{}{"user_id": userID},
	}
	return db.querier.SelectAll(queryParams, &opts, exhaustiveRun, applyFunc)
}

func (db *CouchSubscriptionsStore) Subscribe(ctx context.Context, sub *models.Subscription) (*models.Subscription, error) {
	return db.querier.Insert(*sub, sub.ID)
}

func (db *CouchSubscriptionsStore) Unsubscribe(ctx context.Context, subscriptionID string) error {
	return db.querier.Delete(subscriptionID)
}

func (db *CouchSubscriptionsStore) GetSubscriptionsByEventType(ctx context.Context, eventType string, exhaustiveRun bool, applyFunc func(models.Subscription), queryParams *resources.QueryParameters, extraOpts map[string]interface{}) (string, error) {
	opts := map[string]interface{}{
		"selector": map[string]interface{}{"event_type": eventType},
	}
	return db.querier.SelectAll(queryParams, &opts, exhaustiveRun, applyFunc)
}
