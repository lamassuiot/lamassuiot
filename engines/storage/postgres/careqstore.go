package postgres

import (
	"context"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

const caRequestDBName = "ca_certificate_requests"

type PostgresCACertificateRequestStore struct {
	db      *gorm.DB
	querier *postgresDBQuerier[models.CACertificateRequest]
}

func NewCACertRequestPostgresRepository(log *logrus.Entry, db *gorm.DB) (storage.CACertificateRequestRepo, error) {
	querier, err := TableQuery(log, db, caRequestDBName, "id", models.CACertificateRequest{})
	if err != nil {
		return nil, err
	}

	return &PostgresCACertificateRequestStore{
		db:      db,
		querier: querier,
	}, nil
}

func (db *PostgresCACertificateRequestStore) Insert(ctx context.Context, caCertificateRequest *models.CACertificateRequest) (*models.CACertificateRequest, error) {
	return db.querier.Insert(ctx, caCertificateRequest, caCertificateRequest.ID)
}

func (db *PostgresCACertificateRequestStore) SelectExistsByID(ctx context.Context, id string) (bool, *models.CACertificateRequest, error) {
	return db.querier.SelectExists(ctx, id, nil)
}

func (db *PostgresCACertificateRequestStore) Update(ctx context.Context, caCertificate *models.CACertificateRequest) (*models.CACertificateRequest, error) {
	return db.querier.Update(ctx, caCertificate, caCertificate.ID)
}

func (db *PostgresCACertificateRequestStore) Delete(ctx context.Context, reqID string) error {
	return db.querier.Delete(ctx, reqID)
}

func (db *PostgresCACertificateRequestStore) SelectAll(ctx context.Context, req storage.StorageListRequest[models.CACertificateRequest]) (string, error) {
	return db.querier.SelectAll(ctx, req.QueryParams, []gormExtraOps{}, req.ExhaustiveRun, req.ApplyFunc)
}
