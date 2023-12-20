package postgres

import (
	"context"
	"time"

	"github.com/lamassuiot/lamassuiot/v2/pkg/models"
	"github.com/lamassuiot/lamassuiot/v2/pkg/storage"
	"gorm.io/gorm"
)

const certDBName = "certificates"

type PostgresCertificateStorage struct {
	db      *gorm.DB
	querier *postgresDBQuerier[models.Certificate]
}

func NewCertificateRepository(db *gorm.DB) (storage.CertificatesRepo, error) {
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
	return db.querier.Count([]gormWhereParams{})
}

func (db *PostgresCertificateStorage) CountByCAIDAndStatus(ctx context.Context, caID string, status models.CertificateStatus) (int, error) {
	opts := []gormWhereParams{
		{query: "issuer_meta_id = ?", extraArgs: []any{caID}},
		{query: "status = ?", extraArgs: []any{status}},
	}
	return db.querier.Count(opts)
}

func (db *PostgresCertificateStorage) SelectByType(ctx context.Context, CAType models.CertificateType, req storage.StorageListRequest[models.Certificate]) (string, error) {
	opts := []gormWhereParams{
		{query: "ca_meta_type = ?", extraArgs: []any{CAType}},
	}
	return db.querier.SelectAll(req.QueryParams, opts, req.ExhaustiveRun, req.ApplyFunc)
}

func (db *PostgresCertificateStorage) SelectAll(ctx context.Context, req storage.StorageListRequest[models.Certificate]) (string, error) {
	return db.querier.SelectAll(req.QueryParams, []gormWhereParams{}, req.ExhaustiveRun, req.ApplyFunc)
}

func (db *PostgresCertificateStorage) SelectExistsBySerialNumber(ctx context.Context, id string) (bool, *models.Certificate, error) {
	return db.querier.SelectExists(id, nil)
}

func (db *PostgresCertificateStorage) Insert(ctx context.Context, certificate *models.Certificate) (*models.Certificate, error) {
	return db.querier.Insert(*certificate, certificate.SerialNumber)
}

func (db *PostgresCertificateStorage) Update(ctx context.Context, certificate *models.Certificate) (*models.Certificate, error) {
	return db.querier.Update(*certificate, certificate.SerialNumber)
}

func (db *PostgresCertificateStorage) SelectByCA(ctx context.Context, caID string, req storage.StorageListRequest[models.Certificate]) (string, error) {
	opts := []gormWhereParams{
		{query: "issuer_meta_id = ?", extraArgs: []any{caID}},
	}
	return db.querier.SelectAll(req.QueryParams, opts, req.ExhaustiveRun, req.ApplyFunc)
}

func (db *PostgresCertificateStorage) SelectByExpirationDate(ctx context.Context, beforeExpirationDate time.Time, afterExpirationDate time.Time, req storage.StorageListRequest[models.Certificate]) (string, error) {
	opts := []gormWhereParams{
		{query: "valid_to > ?", extraArgs: []any{afterExpirationDate}},
		{query: "valid_to < ?", extraArgs: []any{beforeExpirationDate}},
		{query: "status != ?", extraArgs: []any{models.StatusExpired}},
		{query: "status != ?", extraArgs: []any{models.StatusRevoked}},
	}

	return db.querier.SelectAll(req.QueryParams, opts, req.ExhaustiveRun, req.ApplyFunc)
}

func (db *PostgresCertificateStorage) SelectByCAIDAndStatus(ctx context.Context, CAID string, status models.CertificateStatus, req storage.StorageListRequest[models.Certificate]) (string, error) {
	opts := []gormWhereParams{
		{query: "status = ?", extraArgs: []any{status}},
		{query: "issuer_meta_id = ?", extraArgs: []any{CAID}},
	}

	return db.querier.SelectAll(req.QueryParams, opts, req.ExhaustiveRun, req.ApplyFunc)
}

func (db *PostgresCertificateStorage) SelectByStatus(ctx context.Context, status models.CertificateStatus, req storage.StorageListRequest[models.Certificate]) (string, error) {
	opts := []gormWhereParams{
		{query: "status = ?", extraArgs: []any{status}},
	}

	return db.querier.SelectAll(req.QueryParams, opts, req.ExhaustiveRun, req.ApplyFunc)
}

func (db *PostgresCertificateStorage) CountByCA(ctx context.Context, CAID string) (int, error) {
	return db.querier.Count([]gormWhereParams{
		{query: "issuer_meta_id = ?", extraArgs: []any{CAID}},
	})
}
