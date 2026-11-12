package postgres

import (
	"context"
	"math/big"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/errs"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

const crlSettingsSignerFK = "crl_settings_signer_cert_fk"

type PostgresCRLSettingsStore struct {
	db      *gorm.DB
	querier *DBQuerier[models.CRLSettings]
}

func NewCRLSettingsRepository(logger *logrus.Entry, db *gorm.DB) (storage.CRLSettingsRepo, error) {
	querier, err := TableQuery(logger, db, "crl_settings", "ca_id", models.CRLSettings{})
	if err != nil {
		return nil, err
	}

	return &PostgresCRLSettingsStore{
		db:      db,
		querier: querier,
	}, nil
}

func (db *PostgresCRLSettingsStore) Get(ctx context.Context, caID string) (bool, *models.CRLSettings, error) {
	return db.querier.SelectExists(ctx, caID, nil)
}

func (db *PostgresCRLSettingsStore) GetByLegacySKI(ctx context.Context, ski string) (bool, *models.CRLSettings, error) {
	col := "legacy_ski"
	return db.querier.SelectExists(ctx, ski, &col)
}

func (db *PostgresCRLSettingsStore) GetAll(ctx context.Context, req storage.StorageListRequest[models.CRLSettings]) (string, error) {
	return db.querier.SelectAll(ctx, req.QueryParams, []GormExtraOps{}, req.ExhaustiveRun, req.ApplyFunc)
}

func (db *PostgresCRLSettingsStore) Insert(ctx context.Context, settings *models.CRLSettings) (*models.CRLSettings, error) {
	inserted, err := db.querier.Insert(ctx, settings, settings.CAID)
	if isForeignKeyViolation(err, crlSettingsSignerFK) {
		return nil, errs.ErrCertificateNotFound
	}
	return inserted, err
}

func (db *PostgresCRLSettingsStore) UpdateOptions(ctx context.Context, caID string, options models.CRLSettingsOptions) (*models.CRLSettings, error) {
	tx := db.db.WithContext(ctx).Table("crl_settings").Where("ca_id = ?", caID).
		Select("refresh_interval", "validity", "signer_serial_number", "regenerate_on_revoke").
		Updates(&models.CRLSettings{Options: options})
	if isForeignKeyViolation(tx.Error, crlSettingsSignerFK) {
		return nil, errs.ErrCertificateNotFound
	}
	if tx.Error != nil {
		return nil, tx.Error
	}
	if tx.RowsAffected == 0 {
		return nil, errs.ErrCRLSettingsNotFound
	}

	_, updated, err := db.Get(ctx, caID)
	return updated, err
}

func (db *PostgresCRLSettingsStore) UpdateLatestCRL(ctx context.Context, caID string, expectedVersion *big.Int, latest models.LatestCRLMeta) error {
	tx := db.db.WithContext(ctx).Table("crl_settings").
		Where("ca_id = ? AND latest_crl_version = ?", caID, expectedVersion.String()).
		Updates(map[string]any{
			"latest_crl_version":     latest.Version.String(),
			"latest_crl_valid_from":  latest.ValidFrom,
			"latest_crl_valid_until": latest.ValidUntil,
		})
	if tx.Error != nil {
		return tx.Error
	}
	if tx.RowsAffected == 0 {
		return errs.ErrCRLSettingsConflict
	}
	return nil
}

func (db *PostgresCRLSettingsStore) SetSigner(ctx context.Context, caID, expectedSerial, newSerial string) (bool, error) {
	tx := db.db.WithContext(ctx).Table("crl_settings").
		Where("ca_id = ? AND signer_serial_number = ?", caID, expectedSerial).
		Update("signer_serial_number", newSerial)
	if isForeignKeyViolation(tx.Error, crlSettingsSignerFK) {
		return false, errs.ErrCertificateNotFound
	}
	if tx.Error != nil {
		return false, tx.Error
	}
	return tx.RowsAffected > 0, nil
}
