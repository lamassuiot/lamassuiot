package postgres

import (
	"context"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/resources"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type PostgresEventsStore struct {
	db      *gorm.DB
	querier *postgresDBQuerier[models.AlertLatestEvent]
}

func NewEventsPostgresRepository(logger *logrus.Entry, db *gorm.DB) (storage.EventRepository, error) {
	querier, err := TableQuery(logger, db, "events", "event_type", models.AlertLatestEvent{})
	if err != nil {
		return nil, err
	}

	return &PostgresEventsStore{
		db:      db,
		querier: (*postgresDBQuerier[models.AlertLatestEvent])(querier),
	}, nil
}

// InsertUpdateEvent registra una aparición de ev.EventType para el tenant en un único upsert
// atómico: la primera crea la fila con total_seen = 1 y las siguientes incrementan el contador
// en la base de datos. Así, eventos concurrentes del mismo tipo (bus en memoria o varias
// réplicas de Alerts) no chocan en la clave (tenant_id, event_type) ni pierden incrementos.
// ev.TotalSeen se ignora a la entrada y se devuelve con el valor almacenado.
func (db *PostgresEventsStore) InsertUpdateEvent(ctx context.Context, ev *models.AlertLatestEvent) (*models.AlertLatestEvent, error) {
	tenantID, scoped, err := db.querier.tenantScope(ctx)
	if err != nil {
		return nil, err
	}
	if scoped {
		// El tenant del contexto siempre manda.
		setTenantID(ev, tenantID)
	}
	ev.TotalSeen = 1

	// SQLite no tiene GREATEST: su MAX escalar es equivalente.
	greatest := "GREATEST"
	if isSQLite(db.db) {
		greatest = "MAX"
	}

	err = db.querier.withTenantScopedTx(ctx, scoped, func(tx *gorm.DB) error {
		return tx.Table(db.querier.tableName).Clauses(
			clause.OnConflict{
				Columns: []clause.Column{{Name: tenantIDColumnName}, {Name: "event_type"}},
				DoUpdates: clause.Set{
					{Column: clause.Column{Name: "event"}, Value: gorm.Expr("excluded.event")},
					{Column: clause.Column{Name: "last_seen"}, Value: gorm.Expr(greatest + "(events.last_seen, excluded.last_seen)")},
					{Column: clause.Column{Name: "total_seen"}, Value: gorm.Expr("COALESCE(events.total_seen, 0) + 1")},
				},
			},
			clause.Returning{},
		).Create(ev).Error
	})
	if err != nil {
		return nil, err
	}

	return ev, nil
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
