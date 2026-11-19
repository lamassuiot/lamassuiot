package storage

import (
	"context"
	"math/big"

	"github.com/lamassuiot/lamassuiot/v4/core/pkg/models"
)

// CRLSettingsRepo only offers scoped writes: a whole-row save would overwrite columns that other writers own
// (status, signer, latest CRL) with a stale copy.
type CRLSettingsRepo interface {
	Insert(ctx context.Context, settings *models.CRLSettings) (*models.CRLSettings, error)
	Get(ctx context.Context, caID string) (bool, *models.CRLSettings, error)
	GetByLegacySKI(ctx context.Context, ski string) (bool, *models.CRLSettings, error)
	GetAll(ctx context.Context, req StorageListRequest[models.CRLSettings]) (string, error)
	// UpdateOptions writes the editable options, and the key of the signer, of ACTIVE settings only
	// (errs.ErrCRLSettingsNotActive otherwise).
	UpdateOptions(ctx context.Context, caID string, options models.CRLSettingsOptions, signer models.CRLSignerKey) (*models.CRLSettings, error)
	// UpdateLatestCRL writes the latest CRL of ACTIVE settings only (errs.ErrCRLSettingsNotActive otherwise), and fails
	// with errs.ErrCRLSettingsConflict if its version is no longer expectedVersion.
	UpdateLatestCRL(ctx context.Context, caID string, expectedVersion *big.Int, latest models.LatestCRLMeta) error
	// MarkFinal moves ACTIVE settings to FINAL and stops retaining the key of their signer. With a latestVersion, only
	// while their latest CRL is still that version (errs.ErrCRLSettingsConflict otherwise): the final CRL must stay the
	// last one. Settings already FINAL or ARCHIVED are left as they are.
	MarkFinal(ctx context.Context, caID string, latestVersion *big.Int) error
	// MarkArchived moves ACTIVE or FINAL settings to ARCHIVED and stops retaining their signer certificate. Archived
	// settings are left as they are.
	MarkArchived(ctx context.Context, caID string) error
	// Delete purges ARCHIVED settings only (errs.ErrCRLSettingsNotArchived otherwise).
	Delete(ctx context.Context, caID string) error
}
