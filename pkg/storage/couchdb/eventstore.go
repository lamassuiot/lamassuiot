//go:build experimental
// +build experimental

package couchdb

import (
	"context"

	_ "github.com/go-kivik/couchdb"
	"github.com/go-kivik/kivik/v4"
	"github.com/lamassuiot/lamassuiot/v2/pkg/models"
	"github.com/lamassuiot/lamassuiot/v2/pkg/resources"
)

const eventsDBName = "events"

type CouchEventsStore struct {
	client  *kivik.Client
	querier *couchDBQuerier[models.AlertLatestEvent]
}

func NewEventsCouchRepository(client *kivik.Client) (*CouchEventsStore, error) {
	err := CheckAndCreateDB(client, eventsDBName)
	if err != nil {
		return nil, err
	}

	db := client.DB(eventsDBName)
	querier := newCouchDBQuerier[models.AlertLatestEvent](db)

	return &CouchEventsStore{
		client:  client,
		querier: &querier,
	}, nil
}

func (db *CouchEventsStore) InsertUpdateEvent(ctx context.Context, ev *models.AlertLatestEvent) (*models.AlertLatestEvent, error) {
	exists, _, err := db.querier.SelectExists(string(ev.EventType))
	if err != nil {
		return nil, err
	}

	if exists {
		return db.querier.Update(*ev, string(ev.EventType))
	} else {
		return db.querier.Insert(*ev, string(ev.EventType))
	}
}

func (db *CouchEventsStore) GetLatestEventByEventType(ctx context.Context, eventType models.EventType) (bool, *models.AlertLatestEvent, error) {
	return db.querier.SelectExists(string(eventType))
}

func (db *CouchEventsStore) GetLatestEvents(ctx context.Context) ([]*models.AlertLatestEvent, error) {
	evs := []*models.AlertLatestEvent{}
	queryParams := &resources.QueryParameters{}
	extraOpts := map[string]interface{}{}

	_, err := db.querier.SelectAll(queryParams, &extraOpts, true, func(elem models.AlertLatestEvent) {
		evs = append(evs, &elem)
	})

	if err != nil {
		return nil, err
	}

	return evs, nil
}
