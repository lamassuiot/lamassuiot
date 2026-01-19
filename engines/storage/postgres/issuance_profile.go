package postgres

import (
	"context"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

type PostgresIssuanceStorage struct {
	db      *gorm.DB
	querier *postgresDBQuerier[models.IssuanceProfile]
}

func NewIssuanceProfileRepository(logger *logrus.Entry, db *gorm.DB) (storage.IssuanceProfileRepo, error) {
	querier, err := TableQuery(logger, db, "issuance_profiles", []string{"id"}, models.IssuanceProfile{})
	if err != nil {
		return nil, err
	}

	return &PostgresIssuanceStorage{
		db:      db,
		querier: querier,
	}, nil
}

func (db *PostgresIssuanceStorage) Count(ctx context.Context) (int, error) {
	return db.querier.Count(ctx, []gormExtraOps{})
}

func (db *PostgresIssuanceStorage) SelectAll(ctx context.Context, req storage.StorageListRequest[models.IssuanceProfile]) (string, error) {
	return db.querier.SelectAll(ctx, req.QueryParams, []gormExtraOps{}, req.ExhaustiveRun, req.ApplyFunc)
}

func (db *PostgresIssuanceStorage) SelectByID(ctx context.Context, id string) (bool, *models.IssuanceProfile, error) {
	exists, profile, err := db.querier.SelectExists(ctx, map[string]string{"id": id})
	if err != nil {
		return false, nil, err
	}

	if !exists {
		return false, nil, nil
	}

	return true, profile, nil
}

func (db *PostgresIssuanceStorage) Insert(ctx context.Context, issuanceProfile *models.IssuanceProfile) (*models.IssuanceProfile, error) {
	profile, err := db.querier.Insert(ctx, issuanceProfile)
	if err != nil {
		return nil, err
	}

	return profile, nil
}

func (db *PostgresIssuanceStorage) Update(ctx context.Context, issuanceProfile *models.IssuanceProfile) (*models.IssuanceProfile, error) {
	profile, err := db.querier.Update(ctx, issuanceProfile, map[string]string{"id": issuanceProfile.ID})
	if err != nil {
		return nil, err
	}

	return profile, nil
}

func (db *PostgresIssuanceStorage) Delete(ctx context.Context, id string) error {
	err := db.querier.Delete(ctx, map[string]string{"id": id})
	if err != nil {
		return err
	}

	return nil
}
