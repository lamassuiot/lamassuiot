package postgres

import (
	"context"

	"github.com/lamassuiot/lamassuiot/v2/pkg/models"
	"github.com/lamassuiot/lamassuiot/v2/pkg/resources"
	"github.com/lamassuiot/lamassuiot/v2/pkg/storage"
	"gorm.io/gorm"
)

type PostgresEventsStore struct {
	db      *gorm.DB
	querier *postgresDBQuerier[models.AlertLatestEvent]
}

func NewEventsPostgresRepository(db *gorm.DB) (storage.EventRepository, error) {
	querier, err := CheckAndCreateTable(db, "events", "event_type", models.AlertLatestEvent{})
	if err != nil {
		return nil, err
	}

	return &PostgresEventsStore{
		db:      db,
		querier: (*postgresDBQuerier[models.AlertLatestEvent])(querier),
	}, nil
}

func (db *PostgresEventsStore) InsertUpdateEvent(ctx context.Context, ev *models.AlertLatestEvent) (*models.AlertLatestEvent, error) {
	event, err := db.querier.Update(ev, string(ev.EventType))
	if err == nil {
		return event, nil
	}
	if err == gorm.ErrRecordNotFound {
		return db.querier.Insert(ev, string(ev.EventType))
	}
	return nil, err
}

func (db *PostgresEventsStore) GetLatestEventByEventType(ctx context.Context, eventType models.EventType) (bool, *models.AlertLatestEvent, error) {
	return db.querier.SelectExists(string(eventType), nil)
}

func (db *PostgresEventsStore) GetLatestEvents(ctx context.Context) ([]*models.AlertLatestEvent, error) {
	evs := []*models.AlertLatestEvent{}
	_, err := db.querier.SelectAll(&resources.QueryParameters{}, []gormWhereParams{}, true, func(elem models.AlertLatestEvent) {
		derefElem := elem
		evs = append(evs, &derefElem)
	})

	if err != nil {
		return nil, err
	}

	return evs, nil
}
