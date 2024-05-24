package sqlite

import (
	"context"

	"github.com/lamassuiot/lamassuiot/v2/pkg/models"
	"github.com/lamassuiot/lamassuiot/v2/pkg/resources"
	"github.com/lamassuiot/lamassuiot/v2/pkg/storage"
	"gorm.io/gorm"
)

type SQLiteEventsStore struct {
	db      *gorm.DB
	querier *sqliteDBQuerier[models.AlertLatestEvent]
}

func NewEventsSQLiteRepository(db *gorm.DB) (storage.EventRepository, error) {
	querier, err := CheckAndCreateTable(db, "events", "event_type", models.AlertLatestEvent{})
	if err != nil {
		return nil, err
	}

	return &SQLiteEventsStore{
		db:      db,
		querier: (*sqliteDBQuerier[models.AlertLatestEvent])(querier),
	}, nil
}

func (db *SQLiteEventsStore) InsertUpdateEvent(ctx context.Context, ev *models.AlertLatestEvent) (*models.AlertLatestEvent, error) {
	event, err := db.querier.Update(ctx, ev, string(ev.EventType))
	if err == nil {
		return event, nil
	}
	if err == gorm.ErrRecordNotFound {
		return db.querier.Insert(ctx, ev, string(ev.EventType))
	}
	return nil, err
}

func (db *SQLiteEventsStore) GetLatestEventByEventType(ctx context.Context, eventType models.EventType) (bool, *models.AlertLatestEvent, error) {
	return db.querier.SelectExists(ctx, string(eventType), nil)
}

func (db *SQLiteEventsStore) GetLatestEvents(ctx context.Context) ([]*models.AlertLatestEvent, error) {
	evs := []*models.AlertLatestEvent{}
	_, err := db.querier.SelectAll(ctx, &resources.QueryParameters{}, []gormWhereParams{}, true, func(elem models.AlertLatestEvent) {
		derefElem := elem
		evs = append(evs, &derefElem)
	})

	if err != nil {
		return nil, err
	}

	return evs, nil
}
