package oracle

import (
	"context"
	"math/big"
	"regexp"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/engines/storage"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/errs"
	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
	"gorm.io/gorm"
)

const crlSettingsTable = "crl_settings"

type crlSettingsStore struct{ db *gorm.DB }

var _ storage.CRLSettingsRepo = (*crlSettingsStore)(nil)

var (
	crlSettingsPK             = regexp.MustCompile(`(?i)\([^)]*\blamassu_crl_settings_pk\)`)
	crlSettingsLegacySKI      = regexp.MustCompile(`(?i)\([^)]*\blamassu_crl_legacy_ski_uq\)`)
	crlSettingsSignerByStatus = regexp.MustCompile(`(?i)\([^)]*\blamassu_crl_signer_by_status\)`)
	crlSettingsSignerCertFK   = regexp.MustCompile(`(?i)\([^)]*\blamassu_crl_signer_cert_fk\)`)
	crlSettingsSignerKeyFK    = regexp.MustCompile(`(?i)\([^)]*\blamassu_crl_signer_key_fk\)`)
)

// crlSettingsFields are the columns the API filters and sorts CRL settings by
// (resources.CRLSettingsFilterableFields).
var crlSettingsFields = map[string]struct{}{"ca_id": {}, "status": {}, "legacy_ski": {}}

func (s *crlSettingsStore) table(ctx context.Context) *gorm.DB {
	return s.db.WithContext(ctx).Table(crlSettingsTable)
}

func (s *crlSettingsStore) selectOne(ctx context.Context, column, value string) (bool, *models.CRLSettings, error) {
	var settings models.CRLSettings
	tx := s.table(ctx).Where(column+" = ?", value).Limit(1).Find(&settings)
	if tx.Error != nil {
		return false, nil, tx.Error
	}
	if tx.RowsAffected == 0 {
		return false, nil, nil
	}
	return true, &settings, nil
}

func (s *crlSettingsStore) Get(ctx context.Context, caID string) (bool, *models.CRLSettings, error) {
	return s.selectOne(ctx, "ca_id", caID)
}

func (s *crlSettingsStore) GetByLegacySKI(ctx context.Context, ski string) (bool, *models.CRLSettings, error) {
	return s.selectOne(ctx, "legacy_ski", ski)
}

func (s *crlSettingsStore) GetAll(ctx context.Context, req storage.StorageListRequest[models.CRLSettings]) (string, error) {
	return listRows(s.table(ctx), req, crlSettingsFields, crlSettingsFields, nil, nil, []string{"ca_id"},
		func(settings models.CRLSettings) []any { return []any{settings.CAID} })
}

// crlSettingsWriteError translates the constraint violations of a write as the PostgreSQL repository does: a signer
// that is not an existing certificate or whose key is not in the KMS, signer columns that do not fit the status of
// the settings (an ACTIVE signer needs its key), or a CA id or legacy SKI already taken.
func crlSettingsWriteError(err error) error {
	switch {
	case constraintError(err, "ORA-02291", crlSettingsSignerCertFK):
		return errs.ErrCertificateNotFound
	case constraintError(err, "ORA-02291", crlSettingsSignerKeyFK):
		return errs.ErrKeyNotFound
	case constraintError(err, "ORA-02290", crlSettingsSignerByStatus):
		return errs.ErrValidateBadRequest
	case constraintError(err, "ORA-00001", crlSettingsPK), constraintError(err, "ORA-00001", crlSettingsLegacySKI):
		return gorm.ErrDuplicatedKey
	}
	return err
}

func (s *crlSettingsStore) Insert(ctx context.Context, settings *models.CRLSettings) (*models.CRLSettings, error) {
	if err := s.table(ctx).Create(settings).Error; err != nil {
		return nil, crlSettingsWriteError(err)
	}
	return settings, nil
}

// noRowsError explains why a conditional write changed nothing: the settings do not exist, they are in a status the
// write does not accept, or (when they are in the expected status) another writer got there first.
func (s *crlSettingsStore) noRowsError(ctx context.Context, caID string, wrongStatus func(models.CRLSettingsStatus) bool, statusErr error) error {
	exists, current, err := s.Get(ctx, caID)
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

func nullable(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func (s *crlSettingsStore) UpdateOptions(ctx context.Context, caID string, options models.CRLSettingsOptions, signer models.CRLSignerKey) (*models.CRLSettings, error) {
	tx := s.table(ctx).Where("ca_id = ? AND status = ?", caID, models.CRLSettingsActive).
		Select("refresh_interval", "validity", "signer_serial_number", "regenerate_on_revoke", "signer_engine_id", "signer_key_id").
		Updates(&models.CRLSettings{Options: options, SignerEngineID: nullable(signer.EngineID), SignerKeyID: nullable(signer.KeyID)})
	if err := crlSettingsWriteError(tx.Error); err != nil {
		return nil, err
	}
	if tx.RowsAffected == 0 {
		return nil, s.noRowsError(ctx, caID, notActive, errs.ErrCRLSettingsNotActive)
	}

	_, updated, err := s.Get(ctx, caID)
	return updated, err
}

// UpdateLatestCRL compares the version as text: it is stored as the canonical decimal of big.Int.String.
func (s *crlSettingsStore) UpdateLatestCRL(ctx context.Context, caID string, expectedVersion *big.Int, latest models.LatestCRLMeta) error {
	tx := s.table(ctx).
		Where("ca_id = ? AND status = ? AND latest_crl_version = ?", caID, models.CRLSettingsActive, expectedVersion.String()).
		Updates(map[string]any{
			"latest_crl_version":     latest.Version.String(),
			"latest_crl_valid_from":  latest.ValidFrom,
			"latest_crl_valid_until": latest.ValidUntil,
		})
	if tx.Error != nil {
		return tx.Error
	}
	if tx.RowsAffected == 0 {
		return s.noRowsError(ctx, caID, notActive, errs.ErrCRLSettingsNotActive)
	}
	return nil
}

func (s *crlSettingsStore) MarkFinal(ctx context.Context, caID string, latestVersion *big.Int) error {
	q := s.table(ctx).Where("ca_id = ? AND status = ?", caID, models.CRLSettingsActive)
	if latestVersion != nil {
		q = q.Where("latest_crl_version = ?", latestVersion.String())
	}
	tx := q.Updates(map[string]any{"status": models.CRLSettingsFinal, "signer_engine_id": nil, "signer_key_id": nil})
	if tx.Error != nil {
		return tx.Error
	}
	if tx.RowsAffected == 0 {
		// Already FINAL or ARCHIVED: transitions only move forward, so a retried one has nothing left to do.
		return s.noRowsError(ctx, caID, notActive, nil)
	}
	return nil
}

func (s *crlSettingsStore) MarkArchived(ctx context.Context, caID string) error {
	tx := s.table(ctx).
		Where("ca_id = ? AND status IN ?", caID, []models.CRLSettingsStatus{models.CRLSettingsActive, models.CRLSettingsFinal}).
		Updates(map[string]any{"status": models.CRLSettingsArchived, "signer_serial_number": nil, "signer_engine_id": nil, "signer_key_id": nil})
	if tx.Error != nil {
		return tx.Error
	}
	if tx.RowsAffected == 0 {
		exists, _, err := s.Get(ctx, caID)
		if err != nil {
			return err
		}
		if !exists {
			return errs.ErrCRLSettingsNotFound
		}
	}
	return nil
}

func (s *crlSettingsStore) Delete(ctx context.Context, caID string) error {
	tx := s.table(ctx).Where("ca_id = ? AND status = ?", caID, models.CRLSettingsArchived).Delete(&models.CRLSettings{})
	if tx.Error != nil {
		return tx.Error
	}
	if tx.RowsAffected == 0 {
		return s.noRowsError(ctx, caID, func(models.CRLSettingsStatus) bool { return true }, errs.ErrCRLSettingsNotArchived)
	}
	return nil
}
