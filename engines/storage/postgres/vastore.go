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

const (
	crlSettingsSignerFK       = "crl_settings_signer_cert_fk"
	crlSettingsSignerKeyFK    = "crl_settings_signer_key_fk"
	crlSettingsSignerByStatus = "crl_settings_signer_by_status"
)

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
	if err = signerError(err); err != nil {
		return nil, err
	}
	return inserted, nil
}

// signerError translates the violations of the signer constraints: a signer that is not an existing certificate or
// whose key is not in the KMS, or a signer whose columns do not fit the status of the settings (an ACTIVE signer needs
// its key).
func signerError(err error) error {
	switch {
	case isForeignKeyViolation(err, crlSettingsSignerFK):
		return errs.ErrCertificateNotFound
	case isForeignKeyViolation(err, crlSettingsSignerKeyFK):
		return errs.ErrKeyNotFound
	case isCheckViolation(err, crlSettingsSignerByStatus):
		return errs.ErrValidateBadRequest
	}
	return err
}

func nullable(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// noRowsError explains why a conditional write changed nothing: the settings do not exist, they are in a status the
// write does not accept, or (when they are in the expected status) another writer got there first.
func (db *PostgresCRLSettingsStore) noRowsError(ctx context.Context, caID string, wrongStatus func(models.CRLSettingsStatus) bool, statusErr error) error {
	exists, current, err := db.Get(ctx, caID)
	if err != nil {
		return err
	}
	if !exists {
		return errs.ErrCRLSettingsNotFound
	}
	if wrongStatus(current.Status) {
		return statusErr
	}
	return errs.ErrCRLSettingsConflict
}

func notActive(status models.CRLSettingsStatus) bool { return status != models.CRLSettingsActive }

func (db *PostgresCRLSettingsStore) UpdateOptions(ctx context.Context, caID string, options models.CRLSettingsOptions, signer models.CRLSignerKey) (*models.CRLSettings, error) {
	var rowsAffected int64
	err := db.tenantTable(ctx, func(q *gorm.DB, _ string, _ bool) error {
		result := q.Where("ca_id = ? AND status = ?", caID, models.CRLSettingsActive).
			Select("refresh_interval", "validity", "signer_serial_number", "regenerate_on_revoke", "signer_engine_id", "signer_key_id").
			Updates(&models.CRLSettings{Options: options, SignerEngineID: nullable(signer.EngineID), SignerKeyID: nullable(signer.KeyID)})
		rowsAffected = result.RowsAffected
		return result.Error
	})
	if err = signerError(err); err != nil {
		return nil, err
	}
	if rowsAffected == 0 {
		return nil, db.noRowsError(ctx, caID, notActive, errs.ErrCRLSettingsNotActive)
	}

	_, updated, err := db.Get(ctx, caID)
	return updated, err
}

func (db *PostgresCRLSettingsStore) UpdateLatestCRL(ctx context.Context, caID string, expectedVersion *big.Int, latest models.LatestCRLMeta) error {
	var rowsAffected int64
	err := db.tenantTable(ctx, func(q *gorm.DB, _ string, _ bool) error {
		result := q.Where("ca_id = ? AND status = ? AND latest_crl_version = ?", caID, models.CRLSettingsActive, expectedVersion.String()).
			Updates(map[string]any{
				"latest_crl_version":     latest.Version.String(),
				"latest_crl_valid_from":  latest.ValidFrom,
				"latest_crl_valid_until": latest.ValidUntil,
			})
		rowsAffected = result.RowsAffected
		return result.Error
	})
	if err != nil {
		return err
	}
	if rowsAffected == 0 {
		return db.noRowsError(ctx, caID, notActive, errs.ErrCRLSettingsNotActive)
	}
	return nil
}

func (db *PostgresCRLSettingsStore) MarkFinal(ctx context.Context, caID string, latestVersion *big.Int) error {
	var rowsAffected int64
	err := db.tenantTable(ctx, func(q *gorm.DB, _ string, _ bool) error {
		q = q.Where("ca_id = ? AND status = ?", caID, models.CRLSettingsActive)
		if latestVersion != nil {
			q = q.Where("latest_crl_version = ?", latestVersion.String())
		}
		result := q.Updates(map[string]any{"status": models.CRLSettingsFinal, "signer_engine_id": nil, "signer_key_id": nil})
		rowsAffected = result.RowsAffected
		return result.Error
	})
	if err != nil {
		return err
	}
	if rowsAffected == 0 {
		// Already FINAL or ARCHIVED: transitions only move forward, so a retried one has nothing left to do.
		return db.noRowsError(ctx, caID, notActive, nil)
	}
	return nil
}

func (db *PostgresCRLSettingsStore) MarkArchived(ctx context.Context, caID string) error {
	var rowsAffected int64
	err := db.tenantTable(ctx, func(q *gorm.DB, _ string, _ bool) error {
		result := q.Where("ca_id = ? AND status IN ?", caID, []models.CRLSettingsStatus{models.CRLSettingsActive, models.CRLSettingsFinal}).
			Updates(map[string]any{"status": models.CRLSettingsArchived, "signer_serial_number": nil, "signer_engine_id": nil, "signer_key_id": nil})
		rowsAffected = result.RowsAffected
		return result.Error
	})
	if err != nil {
		return err
	}
	if rowsAffected == 0 {
		exists, _, err := db.Get(ctx, caID)
		if err != nil {
			return err
		}
		if !exists {
			return errs.ErrCRLSettingsNotFound
		}
	}
	return nil
}

func (db *PostgresCRLSettingsStore) Delete(ctx context.Context, caID string) error {
	var rowsAffected int64
	err := db.tenantTable(ctx, func(q *gorm.DB, _ string, _ bool) error {
		result := q.Where("ca_id = ? AND status = ?", caID, models.CRLSettingsArchived).
			Delete(&models.CRLSettings{})
		rowsAffected = result.RowsAffected
		return result.Error
	})
	if err != nil {
		return err
	}
	if rowsAffected == 0 {
		return db.noRowsError(ctx, caID, func(models.CRLSettingsStatus) bool { return true }, errs.ErrCRLSettingsNotArchived)
	}
	return nil
}

func (db *PostgresCRLSettingsStore) tenantTable(ctx context.Context, fn func(q *gorm.DB, tenantID string, scoped bool) error) error {
	tenantID, scoped, err := db.querier.tenantScope(ctx)
	if err != nil {
		return err
	}

	return db.querier.withTenantScopedTx(ctx, tenantID, scoped, func(tx *gorm.DB) error {
		q := tx.Table("crl_settings")
		if scoped {
			q = q.Where(db.querier.tenantIDColumn()+" = ?", tenantID)
		}
		return fn(q, tenantID, scoped)
	})
}
