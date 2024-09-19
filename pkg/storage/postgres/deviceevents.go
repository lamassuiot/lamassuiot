package postgres

import (
	"context"

	"github.com/google/uuid"
	"github.com/lamassuiot/lamassuiot/v2/pkg/models"
	"github.com/lamassuiot/lamassuiot/v2/pkg/resources"
	"github.com/lamassuiot/lamassuiot/v2/pkg/storage"
	"gorm.io/gorm"
)

type PostgresDeviceEventsStore struct {
	db      *gorm.DB
	querier *postgresDBQuerier[models.DeviceEvent]
}

func NewDeviceEventsRepository(db *gorm.DB) (storage.DeviceEventsRepo, error) {
	querier, err := CheckAndCreateTable(db, "device_events", "id", models.DeviceEvent{})
	if err != nil {
		return nil, err
	}

	return &PostgresDeviceEventsStore{
		db:      db,
		querier: querier,
	}, nil
}

func (db *PostgresDeviceEventsStore) InsertEvent(ctx context.Context, event *models.DeviceEvent) (*models.DeviceEvent, error) {
	if event.ID == "" {
		event.ID = uuid.NewString()
	}
	return db.querier.Insert(ctx, event, event.ID)
}

func (db *PostgresDeviceEventsStore) SelectEvents(ctx context.Context, deviceID string, applyFunc func(models.DeviceEvent), queryParams *resources.QueryParameters, extraOpts map[string]interface{}) (string, error) {
	opts := []gormWhereParams{
		{query: "device_id = ?", extraArgs: []any{deviceID}},
	}
	return db.querier.SelectAll(ctx, queryParams, opts, false, applyFunc)
}
