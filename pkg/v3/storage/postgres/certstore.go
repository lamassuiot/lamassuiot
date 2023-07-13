package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/lamassuiot/lamassuiot/pkg/v3/models"
	"github.com/lamassuiot/lamassuiot/pkg/v3/resources"
	"github.com/lamassuiot/lamassuiot/pkg/v3/storage"
	"gorm.io/gorm"
)

const certDBName = "certificates"

type PostgresCertificateStorage struct {
	db      *gorm.DB
	querier *postgresDBQuerier[models.Certificate]
}

func NewPostgresCertificateRepository(db *gorm.DB) (storage.CertificatesRepo, error) {
	querier, err := CheckAndCreateTable(db, certDBName, "serial_number", models.Certificate{})
	if err != nil {
		return nil, err
	}

	return &PostgresCertificateStorage{
		db:      db,
		querier: querier,
	}, nil
}

func (db *PostgresCertificateStorage) Count(ctx context.Context) (int, error) {
	return db.querier.Count()
}

func (db *PostgresCertificateStorage) SelectByType(ctx context.Context, CAType models.CAType, exhaustiveRun bool, applyFunc func(*models.Certificate), queryParams *resources.QueryParameters, extraOpts map[string]interface{}) (string, error) {
	opts := []gormWhereParams{
		{query: "ca_meta_type = ?", extraArgs: []any{CAType}},
	}
	return db.querier.SelectAll(queryParams, opts, exhaustiveRun, applyFunc)
}

func (db *PostgresCertificateStorage) Exists(ctx context.Context, sn string) (bool, error) {
	return db.querier.Exists(sn)
}

func (db *PostgresCertificateStorage) SelectAll(ctx context.Context, exhaustiveRun bool, applyFunc func(*models.Certificate), queryParams *resources.QueryParameters, extraOpts map[string]interface{}) (string, error) {
	return db.querier.SelectAll(queryParams, []gormWhereParams{}, exhaustiveRun, applyFunc)
}

func (db *PostgresCertificateStorage) Select(ctx context.Context, id string) (*models.Certificate, error) {
	return db.querier.SelectByID(id)
}

func (db *PostgresCertificateStorage) Insert(ctx context.Context, certificate *models.Certificate) (*models.Certificate, error) {
	return db.querier.Insert(*certificate, certificate.SerialNumber)
}

func (db *PostgresCertificateStorage) Update(ctx context.Context, certificate *models.Certificate) (*models.Certificate, error) {
	return db.querier.Update(*certificate, certificate.SerialNumber)
}

func (db *PostgresCertificateStorage) SelectByCA(ctx context.Context, caID string, exhaustiveRun bool, applyFunc func(*models.Certificate), queryParams *resources.QueryParameters, extraOpts map[string]interface{}) (string, error) {
	opts := []gormWhereParams{
		{query: "issuer_metadata_meta_id = ?", extraArgs: []any{caID}},
	}
	return db.querier.SelectAll(queryParams, opts, exhaustiveRun, applyFunc)
}

func (db *PostgresCertificateStorage) SelectByExpirationDate(ctx context.Context, beforeExpirationDate time.Time, afterExpirationDate time.Time, exhaustiveRun bool, applyFunc func(*models.Certificate), queryParams *resources.QueryParameters, extraOpts map[string]interface{}) (string, error) {
	opts := []gormWhereParams{
		{query: "valid_to > ?", extraArgs: []any{afterExpirationDate}},
		{query: "valid_to < ?", extraArgs: []any{beforeExpirationDate}},
		{query: "status != ?", extraArgs: []any{models.StatusExpired}},
		{query: "status != ?", extraArgs: []any{models.StatusRevoked}},
	}

	return db.querier.SelectAll(queryParams, opts, exhaustiveRun, applyFunc)
}

func (db *PostgresCertificateStorage) CountByCA(ctx context.Context, caID string) (int, error) {
	return -1, fmt.Errorf("TODO")
}
