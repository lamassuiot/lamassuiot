package postgres

import (
	"context"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

type PostgresEventsStore struct {
	db      *gorm.DB
	querier *PostgresDBQuerier[models.AlertLatestEvent]
}

func NewEventsPostgresRepository(logger *logrus.Entry, db *gorm.DB) (storage.EventRepository, error) {
	querier, err := TableQuery(logger, db, "events", "event_type", models.AlertLatestEvent{})
	if err != nil {
		return nil, err
	}

	return &PostgresEventsStore{
		db:      db,
		querier: (*PostgresDBQuerier[models.AlertLatestEvent])(querier),
	}, nil
}

func (db *PostgresEventsStore) InsertUpdateEvent(ctx context.Context, ev *models.AlertLatestEvent) (*models.AlertLatestEvent, error) {
	event, err := db.querier.Update(ctx, ev, string(ev.EventType))
	if err == nil {
		return event, nil
	}
	if err == gorm.ErrRecordNotFound {
		return db.querier.Insert(ctx, ev, string(ev.EventType))
	}
	return nil, err
}

func (db *PostgresEventsStore) GetLatestEventByEventType(ctx context.Context, eventType models.EventType) (bool, *models.AlertLatestEvent, error) {
	return db.querier.SelectExists(ctx, string(eventType), nil)
}

func (db *PostgresEventsStore) GetLatestEvents(ctx context.Context) ([]*models.AlertLatestEvent, error) {
	evs := []*models.AlertLatestEvent{}
	_, err := db.querier.SelectAll(ctx, &resources.QueryParameters{}, []gormExtraOps{}, true, func(elem models.AlertLatestEvent) {
		derefElem := elem
		evs = append(evs, &derefElem)
	})

	if err != nil {
		return nil, err
	}

	return evs, nil
}
