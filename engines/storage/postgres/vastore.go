package postgres

import (
	"context"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

type PostgresVAStore struct {
	db      *gorm.DB
	querier *postgresDBQuerier[models.VARole]
}

func NewVARepository(logger *logrus.Entry, db *gorm.DB) (storage.VARepo, error) {
	querier, err := TableQuery(logger, db, "va_role", "ca_ski", models.VARole{})
	if err != nil {
		return nil, err
	}

	return &PostgresVAStore{
		db:      db,
		querier: querier,
	}, nil
}

func (db *PostgresVAStore) Get(ctx context.Context, caSki string) (bool, *models.VARole, error) {
	return db.querier.SelectExists(ctx, caSki, nil)
}

func (db *PostgresVAStore) GetAll(ctx context.Context, req storage.StorageListRequest[models.VARole]) (string, error) {
	return db.querier.SelectAll(ctx, req.QueryParams, []gormExtraOps{}, req.ExhaustiveRun, req.ApplyFunc)
}

func (db *PostgresVAStore) Update(ctx context.Context, role *models.VARole) (*models.VARole, error) {
	return db.querier.Update(ctx, role, role.CASubjectKeyID)
}

func (db *PostgresVAStore) Insert(ctx context.Context, role *models.VARole) (*models.VARole, error) {
	return db.querier.Insert(ctx, role, role.CASubjectKeyID)
}
