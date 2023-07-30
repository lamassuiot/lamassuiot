package postgres

import (
	"context"

	"github.com/lamassuiot/lamassuiot/pkg/v3/models"
	"github.com/lamassuiot/lamassuiot/pkg/v3/resources"
	"github.com/lamassuiot/lamassuiot/pkg/v3/storage"
	"gorm.io/gorm"
)

const caDBName = "ca_certificates"

type PostgresCAStore struct {
	db      *gorm.DB
	querier *postgresDBQuerier[models.CACertificate]
}

func NewCAPostgresRepository(db *gorm.DB) (storage.CACertificatesRepo, error) {
	querier, err := CheckAndCreateTable(db, caDBName, "id", models.CACertificate{})
	if err != nil {
		return nil, err
	}

	return &PostgresCAStore{
		db:      db,
		querier: querier,
	}, nil
}

func (db *PostgresCAStore) Count(ctx context.Context) (int, error) {
	return db.querier.Count()
}

func (db *PostgresCAStore) SelectByType(ctx context.Context, CAType models.CAType, exhaustiveRun bool, applyFunc func(*models.CACertificate), queryParams *resources.QueryParameters, extraOpts map[string]interface{}) (string, error) {
	opts := []gormWhereParams{
		{query: "ca_meta_type = ?", extraArgs: []any{CAType}},
	}
	return db.querier.SelectAll(queryParams, opts, exhaustiveRun, applyFunc)
}

func (db *PostgresCAStore) SelectAll(ctx context.Context, exhaustiveRun bool, applyFunc func(*models.CACertificate), queryParams *resources.QueryParameters, extraOpts map[string]interface{}) (string, error) {
	return db.querier.SelectAll(queryParams, []gormWhereParams{}, exhaustiveRun, applyFunc)
}

func (db *PostgresCAStore) SelectExists(ctx context.Context, id string) (bool, *models.CACertificate, error) {
	return db.querier.SelectExists(id)
}

func (db *PostgresCAStore) Insert(ctx context.Context, caCertificate *models.CACertificate) (*models.CACertificate, error) {
	return db.querier.Insert(*caCertificate, caCertificate.IssuerCAMetadata.CAID)
}

func (db *PostgresCAStore) Update(ctx context.Context, caCertificate *models.CACertificate) (*models.CACertificate, error) {
	return db.querier.Update(*caCertificate, caCertificate.IssuerCAMetadata.CAID)
}
