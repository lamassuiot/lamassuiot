//go:build experimental
// +build experimental

package sqlite

import (
	"context"
	"time"

	"github.com/lamassuiot/lamassuiot/core/v3/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/core/v3/pkg/models"
	"gorm.io/gorm"
)

const certDBName = "certificates"

type SQLiteCertificateStorage struct {
	db      *gorm.DB
	querier *sqliteDBQuerier[models.Certificate]
}

func NewCertificateRepository(db *gorm.DB) (storage.CertificatesRepo, error) {
	querier, err := TableQuery(db, certDBName, "serial_number", models.Certificate{})
	if err != nil {
		return nil, err
	}

	return &SQLiteCertificateStorage{
		db:      db,
		querier: querier,
	}, nil
}

func (db *SQLiteCertificateStorage) Count(ctx context.Context) (int, error) {
	return db.querier.Count(ctx, []gormWhereParams{})
}

func (db *SQLiteCertificateStorage) CountByCAIDAndStatus(ctx context.Context, caID string, status models.CertificateStatus) (int, error) {
	opts := []gormWhereParams{
		{query: "issuer_meta_id = ?", extraArgs: []any{caID}},
		{query: "status = ?", extraArgs: []any{status}},
	}
	return db.querier.Count(ctx, opts)
}

func (db *SQLiteCertificateStorage) SelectByType(ctx context.Context, CAType models.CertificateType, req storage.StorageListRequest[models.Certificate]) (string, error) {
	opts := []gormWhereParams{
		{query: "ca_meta_type = ?", extraArgs: []any{CAType}},
	}
	return db.querier.SelectAll(ctx, req.QueryParams, opts, req.ExhaustiveRun, req.ApplyFunc)
}

func (db *SQLiteCertificateStorage) SelectAll(ctx context.Context, req storage.StorageListRequest[models.Certificate]) (string, error) {
	return db.querier.SelectAll(ctx, req.QueryParams, []gormWhereParams{}, req.ExhaustiveRun, req.ApplyFunc)
}

func (db *SQLiteCertificateStorage) SelectExistsBySerialNumber(ctx context.Context, id string) (bool, *models.Certificate, error) {
	return db.querier.SelectExists(ctx, id, nil)
}

func (db *SQLiteCertificateStorage) Insert(ctx context.Context, certificate *models.Certificate) (*models.Certificate, error) {
	return db.querier.Insert(ctx, certificate, certificate.SerialNumber)
}

func (db *SQLiteCertificateStorage) Update(ctx context.Context, certificate *models.Certificate) (*models.Certificate, error) {
	return db.querier.Update(ctx, certificate, certificate.SerialNumber)
}

func (db *SQLiteCertificateStorage) SelectByCA(ctx context.Context, caID string, req storage.StorageListRequest[models.Certificate]) (string, error) {
	opts := []gormWhereParams{
		{query: "issuer_meta_id = ?", extraArgs: []any{caID}},
	}
	return db.querier.SelectAll(ctx, req.QueryParams, opts, req.ExhaustiveRun, req.ApplyFunc)
}

func (db *SQLiteCertificateStorage) SelectByExpirationDate(ctx context.Context, beforeExpirationDate time.Time, afterExpirationDate time.Time, req storage.StorageListRequest[models.Certificate]) (string, error) {
	opts := []gormWhereParams{
		{query: "valid_to > ?", extraArgs: []any{afterExpirationDate}},
		{query: "valid_to < ?", extraArgs: []any{beforeExpirationDate}},
		{query: "status != ?", extraArgs: []any{models.StatusExpired}},
		{query: "status != ?", extraArgs: []any{models.StatusRevoked}},
	}

	return db.querier.SelectAll(ctx, req.QueryParams, opts, req.ExhaustiveRun, req.ApplyFunc)
}

func (db *SQLiteCertificateStorage) SelectByCAIDAndStatus(ctx context.Context, CAID string, status models.CertificateStatus, req storage.StorageListRequest[models.Certificate]) (string, error) {
	opts := []gormWhereParams{
		{query: "status = ?", extraArgs: []any{status}},
		{query: "issuer_meta_id = ?", extraArgs: []any{CAID}},
	}

	return db.querier.SelectAll(ctx, req.QueryParams, opts, req.ExhaustiveRun, req.ApplyFunc)
}

func (db *SQLiteCertificateStorage) SelectByStatus(ctx context.Context, status models.CertificateStatus, req storage.StorageListRequest[models.Certificate]) (string, error) {
	opts := []gormWhereParams{
		{query: "status = ?", extraArgs: []any{status}},
	}

	return db.querier.SelectAll(ctx, req.QueryParams, opts, req.ExhaustiveRun, req.ApplyFunc)
}

func (db *SQLiteCertificateStorage) CountByCA(ctx context.Context, CAID string) (int, error) {
	return db.querier.Count(ctx, []gormWhereParams{
		{query: "issuer_meta_id = ?", extraArgs: []any{CAID}},
	})
}
