//go:build experimental
// +build experimental

package sqlite

import (
	"context"

	"github.com/lamassuiot/lamassuiot/v3/core/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/v3/core/pkg/models"
	"gorm.io/gorm"
)

const caDBName = "ca_certificates"

type SQLiteCAStore struct {
	db      *gorm.DB
	querier *sqliteDBQuerier[models.CACertificate]
}

func NewCARepository(db *gorm.DB) (storage.CACertificatesRepo, error) {
	querier, err := CheckAndCreateTable(db, caDBName, "id", models.CACertificate{})
	if err != nil {
		return nil, err
	}

	return &SQLiteCAStore{
		db:      db,
		querier: querier,
	}, nil
}

func (db *SQLiteCAStore) Count(ctx context.Context) (int, error) {
	return db.querier.Count(ctx, []gormWhereParams{})
}

func (db *SQLiteCAStore) CountByEngine(ctx context.Context, engineID string) (int, error) {
	return db.querier.Count(ctx, []gormWhereParams{
		{query: "engine_id = ?", extraArgs: []any{engineID}},
	})
}

func (db *SQLiteCAStore) CountByStatus(ctx context.Context, status models.CertificateStatus) (int, error) {
	return db.querier.Count(ctx, []gormWhereParams{
		{query: "status = ?", extraArgs: []any{status}},
	})
}

func (db *SQLiteCAStore) SelectByType(ctx context.Context, CAType models.CertificateType, req storage.StorageListRequest[models.CACertificate]) (string, error) {
	opts := []gormWhereParams{
		{query: "ca_meta_type = ?", extraArgs: []any{CAType}},
	}
	return db.querier.SelectAll(ctx, req.QueryParams, opts, req.ExhaustiveRun, req.ApplyFunc)
}

func (db *SQLiteCAStore) SelectAll(ctx context.Context, req storage.StorageListRequest[models.CACertificate]) (string, error) {
	return db.querier.SelectAll(ctx, req.QueryParams, []gormWhereParams{}, req.ExhaustiveRun, req.ApplyFunc)
}

func (db *SQLiteCAStore) SelectByCommonName(ctx context.Context, commonName string, req storage.StorageListRequest[models.CACertificate]) (string, error) {
	return db.querier.SelectAll(ctx, req.QueryParams, []gormWhereParams{
		{query: "subject_common_name = ? ", extraArgs: []any{commonName}},
	}, req.ExhaustiveRun, req.ApplyFunc)
}

func (db *SQLiteCAStore) SelectExistsBySerialNumber(ctx context.Context, serialNumber string) (bool, *models.CACertificate, error) {
	queryCol := "serial_number"
	return db.querier.SelectExists(ctx, serialNumber, &queryCol)
}

func (db *SQLiteCAStore) SelectByParentCA(ctx context.Context, parentCAID string, req storage.StorageListRequest[models.CACertificate]) (string, error) {
	return db.querier.SelectAll(ctx, req.QueryParams, []gormWhereParams{
		{query: "issuer_meta_id = ? ", extraArgs: []any{parentCAID}},
	}, req.ExhaustiveRun, req.ApplyFunc)
}

func (db *SQLiteCAStore) SelectExistsByID(ctx context.Context, id string) (bool, *models.CACertificate, error) {
	return db.querier.SelectExists(ctx, id, nil)
}

func (db *SQLiteCAStore) Insert(ctx context.Context, caCertificate *models.CACertificate) (*models.CACertificate, error) {
	return db.querier.Insert(ctx, caCertificate, caCertificate.ID)
}

func (db *SQLiteCAStore) Update(ctx context.Context, caCertificate *models.CACertificate) (*models.CACertificate, error) {
	return db.querier.Update(ctx, caCertificate, caCertificate.ID)
}

func (db *SQLiteCAStore) Delete(ctx context.Context, id string) error {
	return db.querier.Delete(ctx, id)
}
